"""Pure unit tests for S3 subsystems — no LiveServer, no LMDB, fast."""
import hashlib
import hmac
import json
import time
from unittest import TestCase

from django.http import HttpResponse
from django.test import SimpleTestCase

# ---------------------------------------------------------------------------
# Presigned tokens (P2-native)
# ---------------------------------------------------------------------------
from p2.s3.presign import generate_presigned_url, validate_presigned_token, _unb64
from p2.s3.errors import AWSExpiredToken, AWSPresignedInvalid
from p2.s3.constants import PRESIGNED_MAX_EXPIRY


class PresignedTokenTests(SimpleTestCase):

    def _tok(self, url):
        return url.split('X-P2-Signature=')[1].split('&')[0]

    def test_roundtrip(self):
        url = generate_presigned_url('http://h/b/k', 'b', 'k', 'GET')
        self.assertTrue(validate_presigned_token(self._tok(url), 'b', 'k', 'GET'))

    def test_wrong_bucket(self):
        url = generate_presigned_url('http://h/b/k', 'b', 'k', 'GET')
        with self.assertRaises(AWSPresignedInvalid):
            validate_presigned_token(self._tok(url), 'X', 'k', 'GET')

    def test_wrong_key(self):
        url = generate_presigned_url('http://h/b/k', 'b', 'k', 'GET')
        with self.assertRaises(AWSPresignedInvalid):
            validate_presigned_token(self._tok(url), 'b', 'X', 'GET')

    def test_wrong_method(self):
        url = generate_presigned_url('http://h/b/k', 'b', 'k', 'GET')
        with self.assertRaises(AWSPresignedInvalid):
            validate_presigned_token(self._tok(url), 'b', 'k', 'PUT')

    def test_expired(self):
        url = generate_presigned_url('http://h/b/k', 'b', 'k', 'GET', expires_in=1)
        time.sleep(2)
        with self.assertRaises(AWSExpiredToken):
            validate_presigned_token(self._tok(url), 'b', 'k', 'GET')

    def test_tampered_sig(self):
        url = generate_presigned_url('http://h/b/k', 'b', 'k', 'GET')
        tok = self._tok(url)
        bad = tok[:-1] + ('a' if tok[-1] != 'a' else 'b')
        with self.assertRaises(AWSPresignedInvalid):
            validate_presigned_token(bad, 'b', 'k', 'GET')

    def test_malformed(self):
        with self.assertRaises(AWSPresignedInvalid):
            validate_presigned_token('nodot', 'b', 'k', 'GET')

    def test_max_expiry_clamped(self):
        url = generate_presigned_url('http://h/b/k', 'b', 'k', 'GET',
                                     expires_in=PRESIGNED_MAX_EXPIRY + 9999)
        payload = json.loads(_unb64(self._tok(url).rsplit('.', 1)[0]))
        self.assertLessEqual(payload['exp'], int(time.time()) + PRESIGNED_MAX_EXPIRY + 1)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
from p2.s3.cors import (
    _match_origin, find_matching_rule, apply_cors_headers,
    parse_cors_xml, build_cors_xml,
)


class CORSOriginMatchTests(TestCase):

    def test_exact(self):
        self.assertTrue(_match_origin('https://a.com', 'https://a.com'))

    def test_wildcard(self):
        self.assertTrue(_match_origin('*', 'https://any.com'))

    def test_subdomain(self):
        self.assertTrue(_match_origin('https://*.a.com', 'https://x.a.com'))

    def test_no_match(self):
        self.assertFalse(_match_origin('https://a.com', 'https://b.com'))


class CORSRuleMatchTests(TestCase):

    RULES = [
        {'AllowedOrigins': ['https://app.io'], 'AllowedMethods': ['GET', 'PUT']},
        {'AllowedOrigins': ['*'], 'AllowedMethods': ['GET']},
    ]

    def test_specific_match(self):
        self.assertIsNotNone(find_matching_rule(self.RULES, 'https://app.io', 'PUT'))

    def test_wildcard_fallback(self):
        self.assertIsNotNone(find_matching_rule(self.RULES, 'https://x.com', 'GET'))

    def test_no_method(self):
        self.assertIsNone(find_matching_rule(self.RULES, 'https://x.com', 'DELETE'))


class CORSHeaderTests(TestCase):

    def test_headers_applied(self):
        rule = {
            'AllowedOrigins': ['https://a.com'], 'AllowedMethods': ['GET'],
            'AllowedHeaders': ['Auth'], 'ExposeHeaders': ['ETag'], 'MaxAgeSeconds': 600,
        }
        resp = apply_cors_headers(HttpResponse(), rule, 'https://a.com')
        self.assertEqual(resp['Access-Control-Allow-Origin'], 'https://a.com')
        self.assertEqual(resp['Access-Control-Max-Age'], '600')
        self.assertEqual(resp['Vary'], 'Origin')


class CORSXMLTests(TestCase):

    def test_parse_roundtrip(self):
        xml = b'<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><MaxAgeSeconds>60</MaxAgeSeconds></CORSRule></CORSConfiguration>'
        rules = parse_cors_xml(xml)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['AllowedMethods'], ['GET'])
        self.assertEqual(rules[0]['MaxAgeSeconds'], 60)
        # rebuild and re-parse
        from xml.etree import ElementTree
        rules2 = parse_cors_xml(ElementTree.tostring(build_cors_xml(rules)))
        self.assertEqual(rules2[0]['AllowedOrigins'], ['*'])

    def test_multiple_rules(self):
        xml = b'<CORSConfiguration><CORSRule><AllowedOrigin>a</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule><CORSRule><AllowedOrigin>b</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>'
        self.assertEqual(len(parse_cors_xml(xml)), 2)


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------
from p2.s3.policy import parse_policy, check_access, AccessCheckResult


class PolicyParseTests(TestCase):

    def test_valid(self):
        stmts = parse_policy(json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}],
        }))
        self.assertEqual(len(stmts), 1)

    def test_bad_version(self):
        with self.assertRaises(ValueError):
            parse_policy(json.dumps({'Version': '1999', 'Statement': []}))

    def test_bad_json(self):
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            parse_policy('not-json')

    def test_bad_effect(self):
        with self.assertRaises(ValueError):
            parse_policy(json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Maybe', 'Action': '*', 'Resource': '*'}],
            }))


class PolicyCheckTests(TestCase):

    def _stmts(self, effect, action, resource):
        return parse_policy(json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': effect, 'Action': action, 'Resource': resource}],
        }))

    def test_allow(self):
        self.assertEqual(check_access(self._stmts('Allow', 's3:GetObject', '*'),
                                      's3:GetObject', 'arn:aws:s3:::b/k'),
                         AccessCheckResult.ALLOW)

    def test_deny_overrides(self):
        stmts = parse_policy(json.dumps({
            'Version': '2012-10-17',
            'Statement': [
                {'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'},
                {'Effect': 'Deny', 'Action': 's3:DeleteObject', 'Resource': '*'},
            ],
        }))
        self.assertEqual(check_access(stmts, 's3:DeleteObject', 'x'), AccessCheckResult.DENY)

    def test_no_match(self):
        self.assertEqual(check_access(self._stmts('Allow', 's3:PutObject', '*'),
                                      's3:GetObject', 'x'),
                         AccessCheckResult.NO_MATCH)

    def test_wildcard_action(self):
        self.assertEqual(check_access(self._stmts('Allow', 's3:*', '*'),
                                      's3:GetObject', 'x'),
                         AccessCheckResult.ALLOW)


# ---------------------------------------------------------------------------
# AWS SigV4 internals
# ---------------------------------------------------------------------------
from p2.s3.auth.aws_v4 import (
    AWSv4AuthenticationRequest, _derive_signing_key, _hmac_sign,
)


class SigV4ParseTests(TestCase):

    def test_from_querystring(self):
        from django.http import QueryDict
        qs = QueryDict(mutable=True)
        qs['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
        qs['X-Amz-Credential'] = 'AK/20260415/us-east-1/s3/aws4_request'
        qs['X-Amz-Date'] = '20260415T120000Z'
        qs['X-Amz-SignedHeaders'] = 'host'
        qs['X-Amz-Signature'] = 'abcd1234'
        req = AWSv4AuthenticationRequest.from_querystring(qs)
        self.assertIsNotNone(req)
        self.assertEqual(req.algorithm, 'AWS4-HMAC-SHA256')
        self.assertEqual(req.access_key, 'AK')
        self.assertEqual(req.region, 'us-east-1')
        self.assertEqual(req.signature, 'abcd1234')

    def test_from_querystring_missing_param(self):
        from django.http import QueryDict
        qs = QueryDict(mutable=True)
        qs['X-Amz-Date'] = '20260415T120000Z'
        self.assertIsNone(AWSv4AuthenticationRequest.from_querystring(qs))

    def test_from_header(self):
        headers = {
            'HTTP_AUTHORIZATION': 'AWS4-HMAC-SHA256 Credential=AK/20260415/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abcd',
            'HTTP_X_AMZ_DATE': '20260415T120000Z',
        }
        req = AWSv4AuthenticationRequest.from_header(headers)
        self.assertIsNotNone(req)
        self.assertEqual(req.access_key, 'AK')
        self.assertEqual(req.signature, 'abcd')

    def test_from_header_missing(self):
        self.assertIsNone(AWSv4AuthenticationRequest.from_header({}))


class SigV4KeyDerivationTests(TestCase):

    def test_derive_signing_key_deterministic(self):
        k1 = _derive_signing_key('secret', '20260415', 'us-east-1', 's3')
        k2 = _derive_signing_key('secret', '20260415', 'us-east-1', 's3')
        self.assertEqual(k1, k2)

    def test_different_date_different_key(self):
        k1 = _derive_signing_key('secret', '20260415', 'us-east-1', 's3')
        k2 = _derive_signing_key('secret', '20260416', 'us-east-1', 's3')
        self.assertNotEqual(k1, k2)

    def test_hmac_sign(self):
        result = _hmac_sign(b'key', 'msg')
        expected = hmac.new(b'key', b'msg', hashlib.sha256).digest()
        self.assertEqual(result, expected)


# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------
from p2.s3.errors import (
    AWSSignatureMismatch, AWSAccessDenied, AWSNoSuchKey, AWSNoSuchBucket,
    AWSBadDigest, AWSPresignedInvalid, AWSExpiredToken,
)


class ErrorCodeTests(TestCase):

    def test_status_codes(self):
        self.assertEqual(AWSSignatureMismatch.status, 403)
        self.assertEqual(AWSAccessDenied.status, 401)
        self.assertEqual(AWSNoSuchKey.status, 404)
        self.assertEqual(AWSNoSuchBucket.status, 404)
        self.assertEqual(AWSBadDigest.status, 400)
        self.assertEqual(AWSPresignedInvalid.status, 403)
        self.assertEqual(AWSExpiredToken.status, 403)

    def test_error_codes(self):
        self.assertEqual(AWSSignatureMismatch.code, 'SignatureDoesNotMatch')
        self.assertEqual(AWSAccessDenied.code, 'AccessDenied')
        self.assertEqual(AWSNoSuchKey.code, 'NoSuchKey')


# ---------------------------------------------------------------------------
# Object metadata: legacy UI-upload schema + mime inference
# ---------------------------------------------------------------------------
class ObjectMetadataHelperTests(SimpleTestCase):
    def test_legacy_schema_is_read(self):
        from p2.s3.views.objects import _meta_size, _meta_etag, _meta_mime
        meta = {
            'blob.p2.io/mime': 'image/png',
            'blob.p2.io/size/bytes': '1234',
            'blob.p2.io/hash/md5': 'abc',
            'internal_path': '/internal-storage/volumes/x/aa/bb/cc',
        }
        self.assertEqual(_meta_size(meta), 1234)
        self.assertEqual(_meta_etag(meta), 'abc')
        self.assertEqual(_meta_mime(meta, 'a.png'), 'image/png')

    def test_generic_mime_is_inferred_from_key(self):
        from p2.s3.views.objects import _meta_mime
        self.assertEqual(_meta_mime({'mime': 'application/octet-stream'}, 'a/b.jpg'), 'image/jpeg')
        self.assertEqual(_meta_mime({}, 'notes.txt'), 'text/plain; charset=utf-8')
        self.assertEqual(_meta_mime({}, 'blob.unknownext'), 'application/octet-stream')

    def test_explicit_mime_is_kept(self):
        from p2.s3.views.objects import _meta_mime
        self.assertEqual(_meta_mime({'mime': 'video/mp4'}, 'x.bin'), 'video/mp4')

    def test_legacy_path_only_for_non_block_objects(self):
        from p2.s3.views.objects import _legacy_fs_path
        self.assertIsNone(_legacy_fs_path({'blocks': [{'x': 1}], 'internal_path': '/internal-storage/a'}))
        self.assertIsNotNone(_legacy_fs_path({'internal_path': '/internal-storage/a'}))

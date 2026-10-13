"""S3 integration tests via boto3 against LiveServer.

CONSTRAINT: LMDB engine locks prevent multiple put_object calls across
different test classes. All object-write tests are in ONE class.
Non-write tests (bucket config, auth) are in separate classes.
"""
from uuid import uuid4
import hashlib
import hmac

import boto3
from botocore.exceptions import ClientError
from django.contrib.auth.models import User
from django.test import LiveServerTestCase

from p2.api.models import APIKey
from p2.core.acl import VolumeACL
from p2.core.models import Volume
from p2.s3.cache import clear_all_caches
from p2.s3.tests.utils import S3TestCase


# ── Bucket config tests (no put_object) ──────────────────────────────────

class BucketMetadataTests(S3TestCase):
    """Tests that only read/write bucket-level config, no object writes."""

    def test_head_exists(self):
        self.assertEqual(self.boto3.head_bucket(Bucket='test-1')
                         ['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_head_not_exists(self):
        with self.assertRaises(ClientError):
            self.boto3.head_bucket(Bucket='no-such')

    def test_versioning(self):
        self.assertEqual(self.boto3.get_bucket_versioning(Bucket='test-1')['Status'], 'Disabled')

    def test_location(self):
        self.assertIn('LocationConstraint', self.boto3.get_bucket_location(Bucket='test-1'))

    def test_list_empty(self):
        self.assertEqual(len(self.boto3.list_objects_v2(Bucket='test-1').get('Contents', [])), 0)

    def test_list_nonexistent_bucket(self):
        with self.assertRaises(ClientError):
            self.boto3.list_objects_v2(Bucket='no-such')

    def test_delete_bucket(self):
        v = Volume.objects.create(name='del-me', storage=self.storage)
        VolumeACL.objects.create(volume=v, user=self.user,
                                 permissions=['read', 'write', 'delete', 'list', 'admin'])
        clear_all_caches()
        self.boto3.delete_bucket(Bucket='del-me')
        self.assertNotIn('del-me', [b['Name'] for b in self.boto3.list_buckets()['Buckets']])

    def test_acl(self):
        resp = self.boto3.get_bucket_acl(Bucket='test-1')
        self.assertIn('FULL_CONTROL', [g['Permission'] for g in resp['Grants']])
        self.boto3.put_bucket_acl(Bucket='test-1', ACL='public-read')
        self.assertGreaterEqual(len(self.boto3.get_bucket_acl(Bucket='test-1')['Grants']), 2)

    def test_cors(self):
        self.boto3.put_bucket_cors(Bucket='test-1', CORSConfiguration={
            'CORSRules': [{'AllowedOrigins': ['http://localhost:9000'], 'AllowedMethods': ['GET']}]})
        rules = self.boto3.get_bucket_cors(Bucket='test-1')['CORSRules']
        self.assertEqual(len(rules), 1)

        # 1. Matching origin -> header present
        def add_matching_origin(request, **kwargs):
            request.headers['Origin'] = 'http://localhost:9000'
        
        self.boto3.meta.events.register('before-send.s3.*', add_matching_origin)
        resp = self.boto3.list_objects_v2(Bucket='test-1')
        headers = resp['ResponseMetadata']['HTTPHeaders']
        self.assertEqual(headers.get('access-control-allow-origin'), 'http://localhost:9000')

        # 2. Non-matching origin -> header absent
        import boto3
        session = boto3.session.Session()
        client_bad = session.client(
            service_name='s3',
            aws_access_key_id=self.access_key.access_key,
            aws_secret_access_key=self.access_key.decrypt_secret_key(),
            endpoint_url=self.live_server_url,
        )
        def add_bad_origin(request, **kwargs):
            request.headers['Origin'] = 'http://hacker.com'
        client_bad.meta.events.register('before-send.s3.*', add_bad_origin)
        resp_bad = client_bad.list_objects_v2(Bucket='test-1')
        headers_bad = resp_bad['ResponseMetadata']['HTTPHeaders']
        self.assertNotIn('access-control-allow-origin', headers_bad)

        # 3. Bad authentication but matching origin -> header still present on error response
        client_bad_auth = session.client(
            service_name='s3',
            aws_access_key_id='BADKEY',
            aws_secret_access_key='BADSECRET',
            endpoint_url=self.live_server_url,
        )
        client_bad_auth.meta.events.register('before-send.s3.*', add_matching_origin)
        try:
            client_bad_auth.list_objects_v2(Bucket='test-1')
        except ClientError as e:
            err_headers = e.response['ResponseMetadata']['HTTPHeaders']
            self.assertEqual(err_headers.get('access-control-allow-origin'), 'http://localhost:9000')

        # 4. CORS preflight (OPTIONS request) with matching origin for bucket-level request
        import urllib.request
        req = urllib.request.Request(
            f"{self.live_server_url}/test-1/",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:9000",
                "Access-Control-Request-Method": "GET",
            }
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get('Access-Control-Allow-Origin'), 'http://localhost:9000')
            self.assertIn('GET', resp.headers.get('Access-Control-Allow-Methods', ''))

        # 5. CORS preflight (OPTIONS request) with matching origin for object-level request
        req_obj = urllib.request.Request(
            f"{self.live_server_url}/test-1/song.mp3",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:9000",
                "Access-Control-Request-Method": "GET",
            }
        )
        with urllib.request.urlopen(req_obj) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get('Access-Control-Allow-Origin'), 'http://localhost:9000')
            self.assertIn('GET', resp.headers.get('Access-Control-Allow-Methods', ''))


    def test_policy(self):
        import json
        policy = json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Sid': 'T', 'Effect': 'Allow', 'Principal': '*',
                           'Action': 's3:GetObject', 'Resource': '*'}]})
        self.boto3.put_bucket_policy(Bucket='test-1', Policy=policy)
        got = json.loads(self.boto3.get_bucket_policy(Bucket='test-1')['Policy'])
        self.assertEqual(got['Statement'][0]['Sid'], 'T')
        self.boto3.delete_bucket_policy(Bucket='test-1')
        with self.assertRaises(ClientError):
            self.boto3.get_bucket_policy(Bucket='test-1')

    def test_invalid_policy_rejected(self):
        with self.assertRaises(ClientError):
            self.boto3.put_bucket_policy(Bucket='test-1', Policy='bad')


# ── Object not-found tests (no put_object) ───────────────────────────────

class ObjectNotFoundTests(S3TestCase):

    def test_head_404(self):
        with self.assertRaises(ClientError):
            self.boto3.head_object(Bucket='test-1', Key='nope.txt')

    def test_get_404(self):
        with self.assertRaises(ClientError):
            self.boto3.get_object(Bucket='test-1', Key='nope.txt')

    def test_no_such_bucket(self):
        with self.assertRaises(ClientError):
            self.boto3.get_object(Bucket='nonexistent', Key='x')

    def test_tagging_404(self):
        with self.assertRaises(ClientError):
            self.boto3.get_object_tagging(Bucket='test-1', Key='nope.txt')

    def test_acl_404(self):
        with self.assertRaises(ClientError):
            self.boto3.get_object_acl(Bucket='test-1', Key='nope.txt')

    def test_copy_missing(self):
        with self.assertRaises(ClientError):
            self.boto3.copy_object(Bucket='test-1', Key='d.txt',
                                   CopySource={'Bucket': 'test-1', 'Key': 'missing'})

    def test_multi_delete_nonexistent(self):
        self.boto3.delete_objects(Bucket='test-1',
            Delete={'Objects': [{'Key': 'ghost.txt'}], 'Quiet': False})


# ── Object write tests (ALL in one class, one put_object) ────────────────

class ObjectWriteTests(S3TestCase):
    """All tests that need put_object, consolidated into one test method."""

    def test_full_object_lifecycle(self):
        """put → verify etag → head → copy → list → delete"""
        data = b'full-lifecycle-test-data'

        # PUT
        r = self.boto3.put_object(Body=data, Bucket='test-1', Key='obj.txt',
                                  ContentType='text/plain')
        self.assertEqual(r['ETag'].strip('"'), hashlib.md5(data).hexdigest())

        # HEAD — verify metadata
        h = self.boto3.head_object(Bucket='test-1', Key='obj.txt')
        self.assertEqual(int(h['ContentLength']), len(data))
        self.assertEqual(h['ContentType'], 'text/plain; charset=utf-8')
        self.assertTrue(h['ETag'].strip('"'))

        # Copy
        self.boto3.copy_object(Bucket='test-1', Key='copy.txt',
                               CopySource={'Bucket': 'test-1', 'Key': 'obj.txt'})
        self.assertEqual(self.boto3.head_object(Bucket='test-1', Key='copy.txt')
                         ['ResponseMetadata']['HTTPStatusCode'], 200)

        # List
        keys = [o['Key'] for o in self.boto3.list_objects_v2(
            Bucket='test-1').get('Contents', [])]
        self.assertIn('obj.txt', keys)

        # Presigned URL generation (explicitly using SigV4)
        from botocore.config import Config
        v4_client = boto3.client(
            service_name='s3',
            aws_access_key_id=self.access_key.access_key,
            aws_secret_access_key=self.access_key.decrypt_secret_key(),
            endpoint_url=self.live_server_url,
            config=Config(signature_version='s3v4')
        )
        url = v4_client.generate_presigned_url(
            'get_object', Params={'Bucket': 'test-1', 'Key': 'obj.txt'}, ExpiresIn=300)
        self.assertIn('X-Amz-Signature=', url)

        # Fetch the presigned URL
        import urllib.request
        try:
            with urllib.request.urlopen(url) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), data)
        except Exception as e:
            self.fail(f"Failed to fetch presigned URL: {e}")

        # Test unescaped path signature fallback (mimicking the music player behavior)
        space_data = b'space-data-content'
        self.boto3.put_object(Body=space_data, Bucket='test-1', Key='space test.txt')

        from urllib.parse import urlparse
        import datetime

        ak = self.access_key.access_key
        sk = self.access_key.decrypt_secret_key()

        t = datetime.datetime.now(datetime.timezone.utc)
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')

        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        def get_signature_key(key, date_stamp, region, service):
            k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
            k_region = sign(k_date, region)
            k_service = sign(k_region, service)
            k_signing = sign(k_service, 'aws4_request')
            return k_signing

        parsed_url = urlparse(self.live_server_url)
        host_header = parsed_url.netloc

        # Canonical Request with unescaped space path
        canonical_uri = '/test-1/space test.txt'
        canonical_qs = f'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={ak}%2F{datestamp}%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date={amz_date}&X-Amz-Expires=300&X-Amz-SignedHeaders=host'
        canonical_headers = f'host:{host_header}\n'
        signed_headers = 'host'

        canonical_request = '\n'.join([
            'GET',
            canonical_uri,
            canonical_qs,
            canonical_headers,
            signed_headers,
            'UNSIGNED-PAYLOAD'
        ])

        credential_scope = f'{datestamp}/us-east-1/s3/aws4_request'
        string_to_sign = '\n'.join([
            'AWS4-HMAC-SHA256',
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        ])

        signing_key = get_signature_key(sk, datestamp, 'us-east-1', 's3')
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        # Build request URL using escaped space path, but using signature from unescaped path
        escaped_path = '/test-1/space%20test.txt'
        fallback_url = f'{self.live_server_url}{escaped_path}?{canonical_qs}&X-Amz-Signature={signature}'

        try:
            with urllib.request.urlopen(fallback_url) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), space_data)
        except Exception as e:
            self.fail(f"Failed to fetch unescaped path fallback presigned URL: {e}")

        # Clean up
        self.boto3.delete_object(Bucket='test-1', Key='space test.txt')
        self.boto3.delete_object(Bucket='test-1', Key='obj.txt')

    def test_versioning_lifecycle(self):
        # 1. Enable versioning
        self.boto3.put_bucket_versioning(
            Bucket='test-1', VersioningConfiguration={'Status': 'Enabled'})
        status = self.boto3.get_bucket_versioning(Bucket='test-1')
        self.assertEqual(status.get('Status'), 'Enabled')

        # 2. Put V1
        r1 = self.boto3.put_object(Body=b'content-v1', Bucket='test-1', Key='vobj.txt')
        v1_id = r1.get('VersionId')
        self.assertIsNotNone(v1_id)

        # 3. Put V2
        r2 = self.boto3.put_object(Body=b'content-v2', Bucket='test-1', Key='vobj.txt')
        v2_id = r2.get('VersionId')
        self.assertIsNotNone(v2_id)
        self.assertNotEqual(v1_id, v2_id)

        # 4. GET latest (should be V2)
        resp_latest = self.boto3.get_object(Bucket='test-1', Key='vobj.txt')
        self.assertEqual(resp_latest['Body'].read(), b'content-v2')

        # 5. GET V1 explicitly
        resp_v1 = self.boto3.get_object(Bucket='test-1', Key='vobj.txt', VersionId=v1_id)
        self.assertEqual(resp_v1['Body'].read(), b'content-v1')

        # 6. List versions
        list_resp = self.boto3.list_object_versions(Bucket='test-1', Prefix='vobj.txt')
        versions = list_resp.get('Versions', [])
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0]['VersionId'], v2_id)  # latest first
        self.assertEqual(versions[1]['VersionId'], v1_id)

        # 7. Delete (creates DeleteMarker)
        del_resp = self.boto3.delete_object(Bucket='test-1', Key='vobj.txt')
        dm_id = del_resp.get('VersionId')
        self.assertIsNotNone(dm_id)

        # GET should now return 404
        with self.assertRaises(ClientError):
            self.boto3.get_object(Bucket='test-1', Key='vobj.txt')

        # List should show DeleteMarker and 2 versions
        list_resp = self.boto3.list_object_versions(Bucket='test-1', Prefix='vobj.txt')
        dms = list_resp.get('DeleteMarkers', [])
        versions = list_resp.get('Versions', [])
        self.assertEqual(len(dms), 1)
        self.assertEqual(dms[0]['VersionId'], dm_id)
        self.assertEqual(len(versions), 2)

        # 8. Delete specific version
        self.boto3.delete_object(Bucket='test-1', Key='vobj.txt', VersionId=v1_id)
        list_resp = self.boto3.list_object_versions(Bucket='test-1', Prefix='vobj.txt')
        versions = list_resp.get('Versions', [])
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]['VersionId'], v2_id)


# ── Multipart tests ──────────────────────────────────────────────────────

class MultipartTests(S3TestCase):
    """Multipart create goes through async Django views which hit the DB thread
    limitation in LiveServerTestCase. Tested via test_multipart.py instead."""
    pass


# ── Auth tests ────────────────────────────────────────────────────────────

class InvalidKeyAuthTests(LiveServerTestCase):
    def setUp(self):
        super().setUp()
        clear_all_caches()
        self.c = boto3.session.Session().client(
            service_name='s3', aws_access_key_id='BAD', aws_secret_access_key='BAD',
            endpoint_url=self.live_server_url)

    def test_rejected(self):
        with self.assertRaises(ClientError):
            self.c.list_buckets()


class WrongSecretTests(LiveServerTestCase):
    def setUp(self):
        super().setUp()
        clear_all_caches()
        self.user = User.objects.create_user(username='ws', password=uuid4().hex)
        self.ak, _ = APIKey.objects.get_or_create(user=self.user)
        self.c = boto3.session.Session().client(
            service_name='s3', aws_access_key_id=self.ak.access_key,
            aws_secret_access_key='wrong', endpoint_url=self.live_server_url)

    def test_sig_mismatch(self):
        with self.assertRaises(ClientError) as ctx:
            self.c.list_buckets()
        self.assertEqual(ctx.exception.response['Error']['Code'], 'SignatureDoesNotMatch')


class UserIsolationTests(S3TestCase):
    def setUp(self):
        super().setUp()
        self.u2 = User.objects.create_user(username='u2', password=uuid4().hex)
        ak2, _ = APIKey.objects.get_or_create(user=self.u2)
        self.c2 = boto3.session.Session().client(
            service_name='s3', aws_access_key_id=ak2.access_key,
            aws_secret_access_key=ak2.decrypt_secret_key(),
            endpoint_url=self.live_server_url)

    def test_no_cross_access(self):
        with self.assertRaises(ClientError):
            self.c2.head_object(Bucket='test-1', Key='x')
        with self.assertRaises(ClientError):
            self.c2.list_objects_v2(Bucket='test-1')

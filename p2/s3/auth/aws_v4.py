"""p2 s3 authentication mixin"""
import hashlib
import hmac
import time
from typing import Any, List, Optional
from urllib.parse import quote

from django.contrib.auth.models import User
from django.http import HttpRequest, QueryDict
import logging

from p2.api.models import APIKey
from p2.s3.auth.base import BaseAuth
from p2.s3.errors import (AWSAccessDenied, AWSContentSignatureMismatch,
                          AWSSignatureMismatch)

LOGGER = logging.getLogger(__name__)
UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'

# Use Rust HMAC extension when available — ~10x faster key derivation.
from p2.s3._native import crypto as _rust_crypto

_RUST_AVAILABLE = _rust_crypto is not None

_SIGNING_KEY_CACHE: dict[tuple[str, str, str, str], tuple[bytes, float]] = {}
_SIGNING_KEY_TTL_SECONDS = 900.0

# Remembers which (quote_path, use_fallback_hash) signing variant last matched
# for a given access key. A given SDK/client consistently uses the same
# canonicalization, so trying the remembered variant first collapses the
# 4-way retry loop into a single canonical-request + SHA256 + HMAC on the
# hot path. Keyed by access_key -> (quote_path, use_fallback_hash).
_SIG_VARIANT_HINT: dict[str, tuple[bool, bool]] = {}


def _hmac_sign(key: bytes, msg: str) -> bytes:
    if _RUST_AVAILABLE:
        return bytes(_rust_crypto.hmac_sha256_bytes(key, msg))
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _derive_signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    cache_key = (secret_key, date, region, service)
    cached = _SIGNING_KEY_CACHE.get(cache_key)
    now_mono = time.monotonic()
    if cached and cached[1] > now_mono:
        return cached[0]

    if _RUST_AVAILABLE:
        key = bytes(_rust_crypto.derive_signing_key(secret_key, date, region, service))
        _SIGNING_KEY_CACHE[cache_key] = (key, now_mono + _SIGNING_KEY_TTL_SECONDS)
        return key
    k_date = _hmac_sign(('AWS4' + secret_key).encode('utf-8'), date)
    k_region = _hmac_sign(k_date, region)
    k_service = _hmac_sign(k_region, service)
    key = _hmac_sign(k_service, 'aws4_request')
    _SIGNING_KEY_CACHE[cache_key] = (key, now_mono + _SIGNING_KEY_TTL_SECONDS)
    # Simple bounded cache eviction to avoid unbounded growth.
    if len(_SIGNING_KEY_CACHE) > 2048:
        for k, (_, exp) in list(_SIGNING_KEY_CACHE.items()):
            if exp <= now_mono:
                _SIGNING_KEY_CACHE.pop(k, None)
    return key


class SignatureMismatch(Exception):
    """Exception raised when given Hash does not match request body's hash"""


class CachedAPIKey:
    __slots__ = ("access_key", "_secret", "user")

    def __init__(self, access_key, secret, user):
        self.access_key = access_key
        self._secret = secret
        self.user = user

    def decrypt_secret_key(self):
        return self._secret

# pylint: disable=too-many-instance-attributes
class AWSv4AuthenticationRequest:
    """Holds all pieces of an AWSv4 Authenticated Request"""

    algorithm: str = ""
    signed_headers: str = ""
    signature: str = ""
    access_key: str = ""
    date: str = ""
    date_long: str = ""
    region: str = ""
    service: str = ""
    request: str = ""
    hash: str = ""

    def __init__(self):
        self.algorithm = self.date = self.signed_headers = self.signature = self.hash = ""
        self.access_key = self.date_long = self.region = self.service = self.request = ""

    @property
    def credentials(self) -> str:
        """Join properties together to re-construct credential string"""
        return "/".join([
            self.date,
            self.region,
            self.service,
            self.request
        ])

    @credentials.setter
    def credentials(self, value: str):
        # Further split credential value
        self.access_key, self.date, self.region, self.service, self.request = value.split('/')

    @staticmethod
    def from_querystring(get_dict: QueryDict) -> Optional['AWSv4AuthenticationRequest']:
        """Check if AWSv4 Authentication information was sent via Querystring,
        abd parse it into an AWSv4AuthenticationRequest object. If querystring doesn't
        contain necessary parameters, None is returned."""
        required_parameters = ['X-Amz-Date', 'X-Amz-Credential',
                               'X-Amz-SignedHeaders', 'X-Amz-Signature']
        for required_parameter in required_parameters:
            if required_parameter not in get_dict:
                return None
        auth_request = AWSv4AuthenticationRequest()
        auth_request.algorithm = 'AWS4-HMAC-SHA256'
        auth_request.credentials = get_dict.get('X-Amz-Credential')
        auth_request.signed_headers = get_dict.get('X-Amz-SignedHeaders')
        auth_request.date_long = get_dict.get('X-Amz-Date')
        auth_request.signature = get_dict.get('X-Amz-Signature')
        return auth_request

    @staticmethod
    def from_header(headers: dict) -> Optional['AWSv4AuthenticationRequest']:
        """Check if AWSv4 Authentication information was sent via headers,
        and parse it into an AWSv4AuthenticationRequest object. If headers don't
        contain necessary information, None is returned."""
        # Check if headers exist, otherwise return None
        if 'HTTP_AUTHORIZATION' not in headers:
            return None
        auth_request = AWSv4AuthenticationRequest()
        auth_request.algorithm, credential_container = \
            headers.get('HTTP_AUTHORIZATION').split(' ', 1)
        credential, signed_headers, signature = credential_container.split(',')
        # Remove "Credential=" from string, strip whitespace
        _, auth_request.credentials = credential.strip().split("=", 1)
        _, auth_request.signed_headers = signed_headers.strip().split("=", 1)
        _, auth_request.signature = signature.strip().split("=", 1)
        auth_request.date_long = headers.get('HTTP_X_AMZ_DATE')
        if not auth_request.date_long:
            auth_request.date_long = auth_request.date
        return auth_request

class AWSV4Authentication(BaseAuth):
    """AWS v4 Signer — uses Rust HMAC extension when available."""

    def _sign(self, key: bytes, msg: str) -> bytes:
        return _hmac_sign(key, msg)

    def _get_signature_key(self, key: str, auth_request: 'AWSv4AuthenticationRequest') -> bytes:
        return _derive_signing_key(key, auth_request.date, auth_request.region, auth_request.service)

    def _make_query_string(self) -> str:
        """Parse existing Querystring, URI-encode them and sort them and put them back together.
        X-Amz-Signature is excluded per the AWS SigV4 spec (the signature cannot sign itself)."""
        pairs = []
        if self.request.META['QUERY_STRING'] == '':
            return self.request.META['QUERY_STRING']
        for kv_pair in self.request.META['QUERY_STRING'].split('&'):
            if kv_pair.startswith('X-Amz-Signature='):
                continue
            if '=' not in kv_pair:
                kv_pair = kv_pair + '='
            pairs.append(kv_pair)
        pairs.sort()
        return '&'.join(pairs)

    def _get_canonical_headers(self, only: List[str]) -> str:
        """Build canonical headers string by direct lookup instead of iterating all META.

        Avoids O(N) string processing over ~40 META entries on every request.
        only is already a small list (typically 3-4 headers from signed_headers).
        """
        canonical_headers = ""
        has_hdrs = hasattr(self.request, 'hdrs')
        for key in sorted(only):
            if has_hdrs and key in self.request.hdrs:
                value = str(self.request.hdrs[key]).strip()
                canonical_headers += f"{key}:{value}\n"
                continue

            # Fallback to META for Django requests
            meta_key = 'HTTP_' + key.upper().replace('-', '_')
            if meta_key in self.request.META:
                value = str(self.request.META[meta_key]).strip()
                canonical_headers += f"{key}:{value}\n"
            elif key == 'content-type' and 'CONTENT_TYPE' in self.request.META:
                value = str(self.request.META['CONTENT_TYPE']).strip()
                canonical_headers += f"{key}:{value}\n"
            elif key == 'content-length' and 'CONTENT_LENGTH' in self.request.META:
                value = str(self.request.META['CONTENT_LENGTH']).strip()
                canonical_headers += f"{key}:{value}\n"
            elif key == 'host' and 'SERVER_NAME' in self.request.META and 'HTTP_HOST' not in self.request.META:
                value = str(self.request.META['SERVER_NAME']).strip()
                canonical_headers += f"{key}:{value}\n"
        return canonical_headers

    def _get_sha256(self, data: Any) -> str:
        """Get body hash in sha256"""
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

    def _get_canonical_request(self, auth_request: AWSv4AuthenticationRequest, quote_path: bool = True) -> str:
        """Create canonical request in AWS format (
        https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)"""
        signed_headers_keys = auth_request.signed_headers.split(';')

        path = self.request.META.get('PATH_INFO', '')
        if quote_path:
            path = quote(path)

        canonical_request = [
            self.request.META.get('REQUEST_METHOD', ''),
            path,
            self._make_query_string(),
            self._get_canonical_headers(signed_headers_keys),
            auth_request.signed_headers,
            auth_request.hash,
        ]
        return '\n'.join(canonical_request)

    async def _lookup_access_key(self, access_key: str) -> Optional[APIKey]:
        """Lookup access_key in database, return APIKey if found otherwise None.
        Uses in-memory cache to avoid database round-trips on hot paths."""
        from p2.s3.cache import aget_cached_apikey, aset_cached_apikey

        # Check cache first — stores the already-decrypted secret, no Fernet on hot path
        cached = await aget_cached_apikey(access_key)
        if cached:
            secret_key, user_id, username, is_superuser = cached
            from django.contrib.auth.models import User
            user = User(id=user_id, username=username, is_superuser=is_superuser)
            user._state.adding = False

            return CachedAPIKey(access_key, secret_key, user)

        # Cache miss - hit database
        apikey = await APIKey.objects.select_related('user').filter(access_key=access_key).afirst()
        if apikey:
            await aset_cached_apikey(access_key, apikey.decrypt_secret_key(), apikey.user_id,
                                     apikey.user.username, apikey.user.is_superuser)
        return apikey

    @staticmethod
    def can_handle(request: HttpRequest) -> bool:
        if request.method == 'OPTIONS':
            return False
        if 'HTTP_AUTHORIZATION' in request.META:
            return 'AWS4-HMAC-SHA256' in request.META['HTTP_AUTHORIZATION']
        if 'X-Amz-Signature' in request.GET:
            return True
        return False


    def verify_content_sha256(self, auth_request: AWSv4AuthenticationRequest):
        """Verify X-Amz-Content-Sha256 Header, if sent.

        HMAC computation is CPU-bound and completes in microseconds; no async wrapping needed.
        request.body is pre-buffered by Django ASGI handler, so no async streaming is required."""
        # Header not set -> Empty hash, no checking
        if not auth_request.hash:
            auth_request.hash = ''
            return
        # Client has not calculated SHA256 of payload, no checking
        if auth_request.hash == UNSIGNED_PAYLOAD:
            return
        # For streaming ASGI requests (PUT/POST with body), skip SHA256 body
        # verification — the body hasn't been buffered yet and reading it here
        # would consume the stream before the view can process it.
        if self.request.method in ('PUT', 'POST'):
            return

        # Shortcut empty requests bypassing lazy `.body` stream evaluation
        if self.request.method in ('GET', 'HEAD', 'OPTIONS'):
            request_body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        else:
            # For small requests (DELETE, etc.) verify the hash
            request_body_hash = hashlib.sha256(self.request.body).hexdigest()

        if auth_request.hash != request_body_hash:
            LOGGER.warning("CONTENT_SHA256 Header/param incorrect: theirs=%s ours=%s",
                           auth_request.hash, request_body_hash)
            raise AWSContentSignatureMismatch

    async def validate(self) -> Optional[User]:
        """Check Authorization Header in AWS Compatible format"""
        self.streaming_auth = None
        auth_request = AWSv4AuthenticationRequest.from_header(self.request.META)
        is_presigned = auth_request is None
        if is_presigned:
            auth_request = AWSv4AuthenticationRequest.from_querystring(self.request.GET)
        auth_request.hash = self.request.META.get('HTTP_X_AMZ_CONTENT_SHA256')
        # Presigned URLs have no X-Amz-Content-SHA256 header; AWS spec requires UNSIGNED-PAYLOAD.
        if auth_request.hash is None and is_presigned:
            auth_request.hash = UNSIGNED_PAYLOAD

        # Verify given Hash with request body.
        # HMAC computation is CPU-bound and completes in microseconds; no async wrapping needed.
        self.verify_content_sha256(auth_request)
        # Build our own signature to compare
        secret_key = await self._lookup_access_key(auth_request.access_key)
        if not secret_key:
            LOGGER.warning("No secret key found for request, access_key=%s", auth_request.access_key)
            raise AWSAccessDenied
        # _get_signature_key and _sign are pure HMAC computations (CPU-bound, microseconds).
        # No async wrapping needed.
        signing_key = self._get_signature_key(secret_key.decrypt_secret_key(), auth_request)

        # Try different path quoting and hash representation variations (e.g. quote vs no-quote, empty vs UNSIGNED)
        our_signature = None
        matched_quote_path = True
        matched_hash = auth_request.hash
        matched_canonical_request = None
        matched_string_to_sign = None

        # Standard hash and empty body fallback hash
        candidate_hashes = [auth_request.hash]
        if auth_request.hash == UNSIGNED_PAYLOAD:
            candidate_hashes.append("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        # Build the list of (quote_path, hash) variants to try. A client uses a
        # stable canonicalization, so if we've matched this access key before we
        # try that exact variant first and usually finish in one HMAC.
        variants: list[tuple[bool, str]] = []
        hint = _SIG_VARIANT_HINT.get(auth_request.access_key)
        if hint is not None:
            hint_qp, hint_fallback = hint
            hint_hval = candidate_hashes[1] if (hint_fallback and len(candidate_hashes) > 1) else candidate_hashes[0]
            variants.append((hint_qp, hint_hval))
        for qp in (True, False):
            for hval in candidate_hashes:
                if (qp, hval) not in variants:
                    variants.append((qp, hval))

        for qp, hval in variants:
            # Temporarily swap hash for canonical request construction
            original_hash = auth_request.hash
            auth_request.hash = hval
            canonical_request = self._get_canonical_request(auth_request, quote_path=qp)
            auth_request.hash = original_hash

            string_to_sign = '\n'.join([
                auth_request.algorithm,
                auth_request.date_long,
                auth_request.credentials,
                self._get_sha256(canonical_request.encode('utf-8')),
            ])
            sig = self._sign(signing_key, string_to_sign).hex()
            if auth_request.signature == sig:
                our_signature = sig
                matched_quote_path = qp
                matched_hash = hval
                matched_canonical_request = canonical_request
                matched_string_to_sign = string_to_sign
                # Remember which variant matched so subsequent requests from
                # this client skip straight to it.
                use_fallback = (len(candidate_hashes) > 1 and hval == candidate_hashes[1])
                _SIG_VARIANT_HINT[auth_request.access_key] = (qp, use_fallback)
                break

        if auth_request.signature != our_signature:
            # Only re-canonicalize on mismatch (for debug logging)
            auth_request.hash = matched_hash
            canonical_request = self._get_canonical_request(auth_request, quote_path=matched_quote_path)
            string_to_sign = '\n'.join([
                auth_request.algorithm,
                auth_request.date_long,
                auth_request.credentials,
                self._get_sha256(canonical_request.encode('utf-8')),
            ])
            LOGGER.warning("Signature mismatch debug: path=%s, method=%s, query=%s, signed_headers=%s",
                        self.request.META.get('PATH_INFO'), self.request.META.get('REQUEST_METHOD'),
                        self.request.META.get('QUERY_STRING'), auth_request.signed_headers)
            LOGGER.warning("Canonical request:\n%s", canonical_request)
            LOGGER.warning("String to sign:\n%s", string_to_sign)
            LOGGER.warning("Their sig: %s, Our sig: %s", auth_request.signature, our_signature)
            LOGGER.warning("Signature mismatch for access_key=%s", auth_request.access_key)
            raise AWSSignatureMismatch
        # Make the verified seed context available to the bounded RSGI body
        # decoder. Never derive or trust chunk context before this comparison.
        if auth_request.hash in (
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        ):
            from p2.s3.put_body import StreamingAuth
            self.streaming_auth = StreamingAuth(
                signing_key, auth_request.date_long, auth_request.credentials, our_signature,
            )
        return secret_key.user

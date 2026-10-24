"""SDK framing, checksum validation, and metadata preservation regressions."""
import base64
import binascii
import hashlib

import pytest

from p2.s3.errors import AWSBadDigest, AWSError, AWSInvalidArgument, AWSSignatureMismatch
from p2.s3.fastpath import put_user_metadata, validate_fast_put_integrity
from p2.s3.put_body import (
    StreamingAuth, decode_chunked_put, decode_unsigned_trailers, supports_chunked_put,
    supports_unsigned_trailers,
)


def framed_put(payload=b"abcdef", algorithm="crc32"):
    from p2.s3.checksum import _py_compute_crc32c
    name = "x-amz-checksum-" + algorithm
    values = {
        "crc32": base64.b64encode((binascii.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")),
        "crc32c": _py_compute_crc32c(payload).encode(),
        "sha1": base64.b64encode(hashlib.sha1(payload).digest()),
        "sha256": base64.b64encode(hashlib.sha256(payload).digest()),
    }
    value = values[algorithm]
    raw = b"2\r\n" + payload[:2] + b"\r\n4\r\n" + payload[2:] + b"\r\n0\r\n" + name.encode() + b":" + value + b"\r\n\r\n"
    headers = {
        "content-encoding": "aws-chunked",
        "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "x-amz-decoded-content-length": str(len(payload)),
        "x-amz-trailer": name,
    }
    return raw, headers


@pytest.mark.parametrize("algorithm", ["crc32", "crc32c", "sha1", "sha256"])
def test_strict_multi_chunk_decode_checks_all_supported_algorithms(algorithm):
    raw, headers = framed_put(algorithm=algorithm)
    payload, integrity_headers = decode_unsigned_trailers(raw, headers)
    assert payload == b"abcdef"
    assert "x-amz-checksum-" + algorithm not in headers
    validate_fast_put_integrity(
        integrity_headers, payload, hashlib.md5(payload).hexdigest(), hashlib.sha256(payload).hexdigest(),
    )


@pytest.mark.parametrize("change", [
    lambda raw: raw[:-1],
    lambda raw: raw + b"trailing",
    lambda raw: raw.replace(b"4\r\n", b"5\r\n", 1),
    lambda raw: raw.replace(b"2\r\n", b"-2\r\n", 1),
    lambda raw: raw.replace(b"2\r\n", b"2;chunk-signature=not-verified\r\n", 1),
    lambda raw: raw.replace(b"2\r\n", b"2" * 300 + b"\r\n", 1),
    lambda raw: raw.replace(b"cdef", b"def"),
    lambda raw: raw.replace(b"ab\r\n", b"ab--", 1),
    lambda raw: raw.replace(b"x-amz-checksum-crc32:", b"authorization:"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n"),
    lambda raw: raw.split(b"x-amz-checksum-crc32:")[0] + b"\r\n",
])
def test_malformed_or_ambiguous_framing_is_rejected(change):
    raw, headers = framed_put()
    modified = change(raw)
    with pytest.raises(AWSError):
        decode_unsigned_trailers(modified, headers)


@pytest.mark.parametrize("length", ["-1", "5", "7", "invalid", "1000000000000"])
def test_decoded_size_must_match(length):
    raw, headers = framed_put()
    headers["x-amz-decoded-content-length"] = length
    with pytest.raises(AWSError):
        decode_unsigned_trailers(raw, headers)


def test_mismatched_trailer_is_never_accepted_as_valid_data():
    raw, headers = framed_put()
    raw = raw.replace(b"cdef", b"xxxx")
    payload, integrity_headers = decode_unsigned_trailers(raw, headers)
    with pytest.raises(AWSBadDigest):
        validate_fast_put_integrity(
            integrity_headers, payload, hashlib.md5(payload).hexdigest(), hashlib.sha256(payload).hexdigest(),
        )


def test_conflicting_header_and_trailer_checksums_are_rejected():
    raw, headers = framed_put()
    headers["x-amz-checksum-crc32"] = "AAAAAA=="
    with pytest.raises(AWSBadDigest):
        decode_unsigned_trailers(raw, headers)


@pytest.mark.parametrize("hash_value", [
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
])
def test_signed_chunks_are_not_treated_as_unsigned(hash_value):
    _, headers = framed_put()
    headers["x-amz-content-sha256"] = hash_value
    assert not supports_unsigned_trailers(headers)


def test_metadata_limit_and_normalized_names():
    assert put_user_metadata({"X-Amz-Meta-Warp-Tag": "benchmark", "content-type": "text/plain"}) == {
        "warp-tag": "benchmark",
    }
    with pytest.raises(AWSInvalidArgument):
        put_user_metadata({"x-amz-meta-key": "x" * 2048})


def test_many_tiny_chunks_do_not_require_a_list_of_retained_slices():
    payload = b"x" * 10000
    headers = {
        "content-encoding": "aws-chunked",
        "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "x-amz-decoded-content-length": str(len(payload)),
        "x-amz-trailer": "x-amz-checksum-crc32",
    }
    value = base64.b64encode((binascii.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big"))
    raw = b"1\r\nx\r\n" * len(payload) + b"0\r\nx-amz-checksum-crc32:" + value + b"\r\n\r\n"
    body, _ = decode_unsigned_trailers(raw, headers)
    assert isinstance(body, bytes)
    assert body == payload

@pytest.mark.parametrize("name", ["crc32", "crc32c", "sha1"])
def test_empty_body_checksums_are_verified(name):
    with pytest.raises(AWSBadDigest):
        validate_fast_put_integrity(
            {"x-amz-checksum-" + name: "invalid"}, b"",
            hashlib.md5(b"").hexdigest(), hashlib.sha256(b"").hexdigest(),
        )


@pytest.fixture(params=[False, True], ids=["signed", "signed-trailer"])
def signed_body(request):
    from botocore.credentials import Credentials
    from p2.s3.tests.streaming_signer import signed_put, signing_parts
    credentials = Credentials("test-access", "test-secret")
    raw, headers = signed_put(
        "http://example.com", "/bucket/key", credentials, b"abcdef", trailer=request.param,
        chunks=[b"ab", b"cdef"],
    )
    auth = StreamingAuth(*signing_parts(headers, credentials))
    return raw, {name.lower(): value for name, value in headers.items()}, auth


def test_signed_stream_decodes_and_checks_integrity(signed_body):
    raw, headers, auth = signed_body
    assert supports_chunked_put(headers)
    body, checks = decode_chunked_put(raw, headers, auth)
    assert body == b"abcdef"
    validate_fast_put_integrity(checks, body, hashlib.md5(body).hexdigest(), hashlib.sha256(body).hexdigest())


def test_signed_stream_requires_an_authenticated_context(signed_body):
    raw, headers, _ = signed_body
    with pytest.raises(AWSSignatureMismatch):
        decode_chunked_put(raw, headers)


@pytest.mark.parametrize("change", [
    lambda raw: raw.replace(b"cdef", b"xxxx"),
    lambda raw: raw.replace(b"ab", b"zz"),
    lambda raw: raw.replace(b";chunk-signature=", b";ignored="),
    lambda raw: raw.replace(b";chunk-signature=", b";chunk-signature=f", 1),
    lambda raw: raw[:-1],
    lambda raw: raw + b"trailing",
    lambda raw: raw.replace(b"ab\r\n", b"abXX", 1),
])
def test_signed_stream_rejects_corruption_and_malformed_framing(signed_body, change):
    raw, headers, auth = signed_body
    with pytest.raises(AWSError):
        decode_chunked_put(change(raw), headers, auth)


@pytest.mark.parametrize("chunk", [0, 1, 2])
def test_every_chunk_signature_including_terminal_is_verified(signed_body, chunk):
    raw, headers, auth = signed_body
    start = [pos for pos in range(len(raw)) if raw.startswith(b";chunk-signature=", pos)][chunk] + 17
    changed = raw[:start] + (b"0" if raw[start:start + 1] != b"0" else b"1") + raw[start + 1:]
    with pytest.raises(AWSSignatureMismatch):
        decode_chunked_put(changed, headers, auth)


def test_signed_trailer_signature_covers_checksum_values(signed_body):
    raw, headers, auth = signed_body
    if "x-amz-trailer" not in headers:
        return
    signature_line = b"x-amz-trailer-signature:" + raw.split(b"x-amz-trailer-signature:")[1].split(b"\r\n")[0]
    for changed in (
        raw.replace(b"x-amz-checksum-crc32:", b"x-amz-checksum-crc32:AAAA"),
        raw.replace(b"x-amz-trailer-signature:", b"x-amz-trailer-signature:0"),
        raw.split(b"x-amz-trailer-signature:")[0] + b"\r\n",
        raw.replace(b"\r\n\r\n", b"\r\n" + signature_line + b"\r\n\r\n"),
    ):
        with pytest.raises(AWSError):
            decode_chunked_put(changed, headers, auth)


def test_chunks_cannot_be_reordered(signed_body):
    raw, headers, auth = signed_body
    first, rest = raw.split(b"ab\r\n", 1)
    second, terminal = rest.split(b"cdef\r\n", 1)
    with pytest.raises(AWSSignatureMismatch):
        decode_chunked_put(second + b"cdef\r\n" + first + b"ab\r\n" + terminal, headers, auth)


@pytest.mark.parametrize("length", ["-1", "5", "7", "invalid", "1000000000000"])
def test_signed_decoded_size_must_match(signed_body, length):
    raw, headers, auth = signed_body
    with pytest.raises(AWSError):
        decode_chunked_put(raw, {**headers, "x-amz-decoded-content-length": length}, auth)


def test_multiple_signed_trailers_are_canonicalized_and_all_checked():
    from p2.s3.tests.streaming_signer import encode_chunks
    body = b"abcdef"
    auth = StreamingAuth(b"test-key", "date", "scope", "0" * 64)
    trailers = {
        "x-amz-checksum-sha256": base64.b64encode(hashlib.sha256(body).digest()).decode(),
        "x-amz-checksum-crc32": base64.b64encode(binascii.crc32(body).to_bytes(4, "big")).decode(),
    }
    raw = encode_chunks([body], auth.signing_key, auth.date, auth.scope, auth.seed_signature, trailers)
    headers = {
        "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        "x-amz-decoded-content-length": str(len(body)), "x-amz-trailer": ",".join(trailers),
    }
    decoded, checks = decode_chunked_put(raw, headers, auth)
    validate_fast_put_integrity(checks, decoded, hashlib.md5(decoded).hexdigest(), hashlib.sha256(decoded).hexdigest())
    with pytest.raises(AWSError):
        decode_chunked_put(raw.replace(b"x-amz-checksum-crc32:", b"x-amz-checksum-crc32:AAAA"), headers, auth)


def test_context_repr_does_not_disclose_derived_key():
    assert "test-secret" not in repr(StreamingAuth(b"test-secret", "date", "scope", "seed"))


def test_aws_published_signed_trailer_vector():
    # AWS public example credentials, not deployment credentials.
    # https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html
    import hmac
    from p2.s3.tests.streaming_signer import encode_chunks
    key = b"AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    for component in ("20130524", "us-east-1", "s3", "aws4_request"):
        key = hmac.digest(key, component.encode(), "sha256")
    auth = StreamingAuth(
        key, "20130524T000000Z", "20130524/us-east-1/s3/aws4_request",
        "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e",
    )
    raw = encode_chunks(
        [b"a" * 65536, b"a" * 1024], key, auth.date, auth.scope, auth.seed_signature,
        {"x-amz-checksum-crc32c": "sOO8/Q=="},
    )
    # Fixed independently published chain anchors, not generated expectations.
    assert raw.startswith(b"10000;chunk-signature=b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2\r\n")
    assert b"0;chunk-signature=2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992\r\n" in raw
    assert hashlib.sha256(b"x-amz-checksum-crc32c:sOO8/Q==\n").hexdigest() == (
        "1e376db7e1a34a8ef1c4bcee131a2d60a1cb62503747488624e10995f448d774"
    )
    headers = {
        "content-encoding": "aws-chunked", "x-amz-decoded-content-length": "66560",
        "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        "x-amz-trailer": "x-amz-checksum-crc32c",
    }
    body, checks = decode_chunked_put(raw, headers, auth)
    assert body == b"a" * 66560
    validate_fast_put_integrity(checks, body, hashlib.md5(body).hexdigest(), hashlib.sha256(body).hexdigest())

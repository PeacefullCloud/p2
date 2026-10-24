"""Strict decoding and signature checks for bounded AWS chunked PUT bodies."""
from dataclasses import dataclass, field
import hashlib
import hmac
from io import BytesIO

from p2.s3.errors import AWSBadDigest, AWSIncompleteBody, AWSInvalidArgument, AWSSignatureMismatch

SIGNED_PAYLOAD = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
SIGNED_TRAILERS = SIGNED_PAYLOAD + "-TRAILER"
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, slots=True)
class StreamingAuth:
    # Never include derived credentials in reprs or diagnostics.
    signing_key: bytes = field(repr=False)
    date: str
    scope: str
    seed_signature: str

    def sign(self, algorithm: str, previous: str, digest: str, chunk: bool = False) -> str:
        fields = [algorithm, self.date, self.scope, previous]
        if chunk:
            fields.append(_EMPTY_HASH)
        fields.append(digest)
        return hmac.new(self.signing_key, "\n".join(fields).encode("ascii"), hashlib.sha256).hexdigest()


CHECKSUM_HEADERS = frozenset({
    "x-amz-checksum-crc32", "x-amz-checksum-crc32c",
    "x-amz-checksum-sha1", "x-amz-checksum-sha256",
})


def supports_unsigned_trailers(headers):
    if headers.get("x-amz-content-sha256") != "STREAMING-UNSIGNED-PAYLOAD-TRAILER":
        return False
    declared = [name.strip().lower() for name in headers.get("x-amz-trailer", "").split(",")]
    return (
        headers.get("content-encoding", "").strip().lower() == "aws-chunked"
        and headers.get("x-amz-content-sha256") == "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
        and "x-amz-decoded-content-length" in headers
        and bool(declared) and all(name in CHECKSUM_HEADERS for name in declared)
        and len(set(declared)) == len(declared)
    )


def supports_chunked_put(headers):
    if supports_unsigned_trailers(headers):
        return True
    scheme = headers.get("x-amz-content-sha256")
    if scheme not in (SIGNED_PAYLOAD, SIGNED_TRAILERS) or "x-amz-decoded-content-length" not in headers:
        return False
    if headers.get("content-encoding", "").strip().lower() not in ("", "aws-chunked"):
        return False
    declared = [name.strip().lower() for name in headers.get("x-amz-trailer", "").split(",")]
    if scheme == SIGNED_PAYLOAD:
        return "x-amz-trailer" not in headers
    return all(name in CHECKSUM_HEADERS for name in declared) and len(set(declared)) == len(declared)


def decode_chunked_put(raw, headers, auth=None):
    """Decode complete AWS framing, rejecting truncation and undeclared trailers.

    Signed modes verify every chunk, including the empty terminal chunk, using
    the context established only after successful request authentication. The
    trailer signature then covers sorted, normalized checksum trailer fields.
    BytesIO keeps memory linear in payload size, even with many tiny chunks.
    Its immutable result is retained by the native writer through completion.
    """
    if not supports_chunked_put(headers):
        raise AWSInvalidArgument
    scheme = headers["x-amz-content-sha256"]
    signed = scheme in (SIGNED_PAYLOAD, SIGNED_TRAILERS)
    if signed and not isinstance(auth, StreamingAuth):
        raise AWSSignatureMismatch
    previous = auth.seed_signature if signed else None
    try:
        expected = int(headers["x-amz-decoded-content-length"])
    except ValueError as exc:
        raise AWSInvalidArgument from exc
    if expected < 0 or expected > len(raw):
        raise AWSIncompleteBody
    declared = {name.strip().lower() for name in headers.get("x-amz-trailer", "").split(",") if name.strip()}
    view, output, pos, size = memoryview(raw), BytesIO(), 0, 0

    def line():
        nonlocal pos
        end = raw.find(b"\r\n", pos, pos + 258)
        if end < 0:
            if len(raw) - pos > 256:
                raise AWSInvalidArgument
            raise AWSIncompleteBody
        result = raw[pos:end]
        pos = end + 2
        return result

    while True:
        header = line()
        signature = None
        if signed:
            header, separator, signature = header.partition(b";chunk-signature=")
            if not separator or len(signature) != 64 or any(byte not in b"0123456789abcdef" for byte in signature):
                raise AWSInvalidArgument
        if not header or len(header) > 16 or any(byte not in b"0123456789abcdefABCDEF" for byte in header):
            raise AWSInvalidArgument
        length = int(header, 16)
        if size + length > expected or pos + length > len(raw):
            raise AWSIncompleteBody
        if signed:
            expected_signature = auth.sign(
                "AWS4-HMAC-SHA256-PAYLOAD", previous,
                hashlib.sha256(view[pos:pos + length]).hexdigest(), chunk=True,
            )
            if not hmac.compare_digest(signature.decode("ascii"), expected_signature):
                raise AWSSignatureMismatch
            previous = expected_signature
        if length == 0:
            break
        size += length
        if size > expected or pos + length + 2 > len(raw):
            raise AWSIncompleteBody
        if raw[pos + length:pos + length + 2] != b"\r\n":
            raise AWSInvalidArgument
        output.write(view[pos:pos + length])
        pos += length + 2
    if size != expected:
        raise AWSIncompleteBody

    trailers, trailer_signature = {}, None
    while trailer := line():
        name, separator, value = trailer.partition(b":")
        try:
            name, value = name.decode("ascii").lower(), value.strip().decode("ascii")
        except UnicodeDecodeError as exc:
            raise AWSInvalidArgument from exc
        if not separator:
            raise AWSInvalidArgument
        if signed and scheme == SIGNED_TRAILERS and name == "x-amz-trailer-signature":
            if trailer_signature is not None:
                raise AWSInvalidArgument
            trailer_signature = value
            continue
        if name not in declared or name in trailers:
            raise AWSInvalidArgument
        if name in headers and headers[name] != value:
            raise AWSBadDigest
        trailers[name] = value
    if pos != len(raw):
        raise AWSInvalidArgument
    if set(trailers) != declared or not all(trailers.values()):
        raise AWSBadDigest
    if scheme == SIGNED_TRAILERS:
        canonical = "".join(f"{name}:{' '.join(trailers[name].split())}\n" for name in sorted(trailers))
        expected_signature = auth.sign(
            "AWS4-HMAC-SHA256-TRAILER", previous, hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        )
        if trailer_signature is None or not hmac.compare_digest(trailer_signature, expected_signature):
            raise AWSSignatureMismatch
    return output.getvalue(), {**dict(headers.items()), **trailers}


def decode_unsigned_trailers(raw, headers):
    if not supports_unsigned_trailers(headers):
        raise AWSInvalidArgument
    return decode_chunked_put(raw, headers)

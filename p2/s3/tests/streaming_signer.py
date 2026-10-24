"""Independent test client: botocore seed signing and stdlib AWS chunk signing.

No production decoder or signing-context helpers are used here.
"""
import base64
import binascii
import hashlib
import hmac

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def signing_parts(headers, credentials):
    authorization = headers["Authorization"]
    scope = authorization.split("Credential=", 1)[1].split(",", 1)[0].split("/", 1)[1]
    key = ("AWS4" + credentials.secret_key).encode()
    for component in scope.split("/"):
        key = hmac.digest(key, component.encode(), "sha256")
    return key, headers["X-Amz-Date"], scope, authorization.split("Signature=", 1)[1]


def encode_chunks(chunks, key, date, scope, seed, trailers=None):
    previous, wire = seed, bytearray()
    for chunk in [*(chunk for chunk in chunks if chunk), b""]:
        message = "\n".join([
            "AWS4-HMAC-SHA256-PAYLOAD", date, scope, previous,
            hashlib.sha256(b"").hexdigest(), hashlib.sha256(chunk).hexdigest(),
        ])
        previous = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        wire.extend(f"{len(chunk):x};chunk-signature={previous}\r\n".encode())
        if chunk:
            wire.extend(chunk + b"\r\n")
    if trailers is not None:
        canonical = "".join(f"{name}:{value}\n" for name, value in sorted(trailers.items()))
        message = "\n".join([
            "AWS4-HMAC-SHA256-TRAILER", date, scope, previous,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ])
        signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        for name, value in trailers.items():
            wire.extend(f"{name}:{value}\r\n".encode())
        wire.extend(f"x-amz-trailer-signature:{signature}\r\n".encode())
    wire.extend(b"\r\n")
    return bytes(wire)


def signed_put(endpoint, path, credentials, payload, trailer=False, extra=None, chunks=None):
    chunks = chunks if chunks is not None else [payload]
    assert b"".join(chunks) == payload
    trailers = None
    headers = {
        "content-encoding": "aws-chunked",
        "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" + ("-TRAILER" if trailer else ""),
        "x-amz-decoded-content-length": str(len(payload)),
        **(extra or {}),
    }
    if trailer:
        checksum = base64.b64encode((binascii.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")).decode()
        trailers = {"x-amz-checksum-crc32": checksum}
        headers["x-amz-trailer"] = "x-amz-checksum-crc32"
    encoded_length = sum(len(chunk) + len(f"{len(chunk):x}") + 85 for chunk in chunks if chunk) + 86
    if trailers is not None:
        encoded_length += sum(len(f"{name}:{value}\r\n") for name, value in trailers.items())
        encoded_length += len("x-amz-trailer-signature:") + 64 + 2
    headers["content-length"] = str(encoded_length)
    request = AWSRequest(method="PUT", url=endpoint + path, data=b"", headers=headers)
    SigV4Auth(credentials, "s3", "us-east-1").add_auth(request)
    headers = dict(request.headers.items())
    body = encode_chunks(chunks, *signing_parts(headers, credentials), trailers)
    assert len(body) == encoded_length
    return body, headers

"""Type stubs for the p2_s3_crypto Rust extension (PyO3)."""

def write_blocks_shared(jobs: list[tuple[int, int, bytes]]) -> None:
    """Write a batch while retaining immutable Python buffers without copying them."""
    ...

def derive_signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    """Derive the AWS v4 signing key from secret key, date, region, and service.

    Returns the 32-byte HMAC-SHA256 signing key.
    """
    ...

def hmac_sha256_hex(key: bytes, msg: str) -> str:
    """Compute HMAC-SHA256 of msg using key, return lowercase hex string."""
    ...

def hmac_sha256_bytes(key: bytes, msg: str) -> bytes:
    """Compute HMAC-SHA256 of msg using key, return raw bytes."""
    ...

def md5_hex(data: bytes) -> str:
    """Compute MD5 of data, return lowercase hex string."""
    ...

def md5_bytes(data: bytes) -> bytes:
    """Compute MD5 of data, return raw 16 bytes."""
    ...

def write_and_hash_small(path: str, data: bytes) -> tuple[str, str]:
    """Write payload to disk and compute (md5_hex, sha256_hex) hashes.

    Releases the Python GIL during file I/O via py.allow_threads(),
    so it is safe to call directly from async event-loop contexts
    without asyncio.to_thread() for small payloads.
    """
    ...

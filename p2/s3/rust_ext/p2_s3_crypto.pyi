"""Type stubs for the p2_s3_crypto Rust extension (PyO3).

Keep this in sync with the ``#[pymodule]`` registrations in src/lib.rs.

maturin packages this file into the wheel as ``p2_s3_crypto/__init__.pyi``
alongside a ``py.typed`` marker, which makes it authoritative for type
checkers. A symbol missing here is reported as an unknown attribute even
though it exists at runtime, so an incomplete stub is worse than none.
p2/s3/_native.py validates the same surface at import time.
"""

from typing import Optional

# ---------------------------------------------------------------------------
# AWS SigV4 / hashing
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    *key* must be 32 bytes. Returns ``(ciphertext, tag)``.
    """
    ...

def aes_gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes
) -> bytes:
    """Decrypt AES-256-GCM *ciphertext*, verifying *tag*.

    *key* must be 32 bytes. Raises on authentication failure.
    """
    ...

# ---------------------------------------------------------------------------
# Volume allocation
# ---------------------------------------------------------------------------

class VolumePool:
    """Native allocator for append-only volume files.

    Owns the open ``std::fs::File`` handles for the active volume set and hands
    out (uuid, offset, fd) triples. Note that the raw ``fd`` it returns is a
    Unix file descriptor, which is the main obstacle to running this on Windows.
    """

    def __init__(
        self,
        vol_dir: str,
        volume_size_bytes: int = 10737418240,
        pool_size: int = 4,
    ) -> None: ...
    def allocate_block(self, length: int) -> tuple[str, int, int]:
        """Reserve *length* bytes. Returns ``(vol_uuid, offset, owned_fd)``.

        The caller must close the descriptor after its write/sync completes.
        The lease remains valid if the allocator rotates the original volume.
        """
        ...

    def seal_full_volumes(self) -> list[str]:
        """Mark near-full volumes read-only and refill the pool.

        Returns the UUIDs that were sealed.
        """
        ...

    def get_volume_path(self, vol_uuid: str) -> str:
        """Return the on-disk path for *vol_uuid*."""
        ...

    def get_active_uuids(self) -> list[str]:
        """Return the UUIDs of the currently writable volumes."""
        ...

    def list_sealed_volumes(self) -> list[str]:
        """Return the UUIDs of volumes that are no longer writable."""
        ...

# ---------------------------------------------------------------------------
# io_uring I/O
# ---------------------------------------------------------------------------

def write_block_uring(fd: int, offset: int, data: bytes) -> tuple[str, str]:
    """Write one block at *offset*, returning ``(md5_hex, sha256_hex)``.

    Single-block path. p2 uses ``write_blocks_uring`` instead; this is retained
    for completeness and is only reachable via GroupCommitter.
    """
    ...

def write_blocks_uring(jobs: list[tuple[int, int, bytes]]) -> None:
    """Submit ``(fd, offset, data)`` writes as one batch.

    Returns once every write has completed, or raises the first I/O error.
    Retained copying interface; p2.s3.volume_writer uses write_blocks_shared.
    """
    ...

def write_blocks_shared(jobs: list[tuple[int, int, bytes]]) -> None:
    """Write a batch while retaining immutable Python bytes through completion.

    No payload Vec copies are made. The blocking wait releases the GIL.
    """
    ...

def fdatasync_uring(fd: int) -> None:
    """fdatasync(2) on *fd*, with the GIL released.

    Despite the name this is a blocking libc call, not an io_uring operation.
    """
    ...

def read_block_uring(fd: int, offset: int, length: int) -> bytes:
    """Read up to *length* bytes at *offset*. Falls back to pread on failure."""
    ...

class RustUringBlockStreamer:
    """Iterate object bytes across a block list, chunk by chunk."""

    def __init__(
        self,
        blocks_raw: list[dict],
        vol_dir: str,
        chunk_size: int,
    ) -> None:
        """*blocks_raw* entries need ``vol_uuid``, ``offset`` and ``length`` keys."""
        ...

    def next_chunk(self) -> Optional[bytes]:
        """Return the next chunk, or ``None`` once every block is consumed."""
        ...

# ---------------------------------------------------------------------------
# Group commit
# ---------------------------------------------------------------------------

class GroupCommitter:
    """Batching write coordinator.

    Not used by p2: the batching lives in Python in p2.s3.volume_writer. This
    implementation spawns an OS thread per queued write and reacquires the GIL
    inside each one, so do not wire it up without reworking it first.
    """

    def __init__(self, batch_size: int = 64, batch_window_ms: int = 4) -> None: ...
    def submit(self, fd: int, offset: int, data: bytes) -> tuple[str, str]:
        """Queue a write and block until it completes.

        Returns ``(md5_hex, sha256_hex)``.
        """
        ...

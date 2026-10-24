"""Fixed-Size Volume Pool — Active Volume Allocator.

Architecture
------------
Instead of one file per object, p2 uses a pool of preallocated flat binary
volume files (``vol_<uuid>.bin``).  Each file is preallocated to a fixed size
(default 10 GiB) via ``fallocate(2)`` / ``os.truncate``.

Lifecycle:
  ACTIVE    — currently being written to (append-only, sequential)
  SEALED    — full; marked read-only (immutable, safe for caching)

Multiple active volumes are maintained concurrently (one per write slot) so
incoming PUTs do NOT contend on a single file lock.

Thread-safety
-------------
``_allocate_offset`` uses a ``threading.Lock`` per volume so concurrent PUT
requests get unique, non-overlapping byte ranges.  LMDB commits are handled
by the Group Committer (``volume_writer.py``) separately.

Zero-copy reads
---------------
Reading is done via ``pread(2)`` directly on the sealed/active ``.bin`` files
at the exact ``(offset, length)`` block coordinates stored in LMDB metadata.
No file-level copy is ever needed.
"""
from __future__ import annotations

import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from typing import Optional

from django.conf import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _volume_size_bytes() -> int:
    """Max size of a single volume file before it is sealed (default 10 GiB)."""
    return int(getattr(settings, "VOLUME_SIZE_BYTES", 10 * 1024 * 1024 * 1024))


def _active_pool_size() -> int:
    """Number of concurrently active write volumes per process (default 4)."""
    return max(1, int(getattr(settings, "VOLUME_ACTIVE_POOL_SIZE", 4)))


def _volume_dir() -> str:
    """Filesystem path where .bin volume files are stored."""
    root = getattr(settings, "STORAGE_ROOT", "/storage")
    return os.path.join(os.path.abspath(root), "volumes")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BlockCoord:
    """A single contiguous block within a volume file."""
    vol_uuid: str        # hex UUID of the volume file
    offset: int          # byte offset within the volume
    length: int          # number of bytes in this block

    def to_dict(self) -> dict:
        return {"vol_uuid": self.vol_uuid, "offset": self.offset, "length": self.length}

    @classmethod
    def from_dict(cls, d: dict) -> "BlockCoord":
        return cls(vol_uuid=d["vol_uuid"], offset=int(d["offset"]), length=int(d["length"]))


@dataclass
class VolumeHandle:
    """In-memory handle for an active volume file."""
    uuid_hex: str
    path: str
    size_limit: int
    _offset: int = field(default=0, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _fd: Optional[int] = field(default=None, repr=False)

    def open(self) -> None:
        """Open the volume file for writing (O_WRONLY | O_CREAT)."""
        flags = os.O_WRONLY | os.O_CREAT
        self._fd = os.open(self.path, flags, 0o644)
        # Determine current write position from file size
        stat = os.fstat(self._fd)
        self._offset = stat.st_size

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __del__(self):
        self.close()

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise RuntimeError(f"VolumeHandle {self.uuid_hex} is not open")
        return self._fd

    @property
    def is_full(self) -> bool:
        with self._lock:
            return self._offset >= self.size_limit

    def allocate(self, length: int) -> Optional[int]:
        """Claim *length* bytes.  Returns the starting offset, or None if full.

        Thread-safe.  Multiple concurrent callers each get a unique range.
        """
        with self._lock:
            if self._offset + length > self.size_limit:
                return None
            start = self._offset
            self._offset += length
            return start


# ---------------------------------------------------------------------------
# Global volume pool registry (one per process)
# ---------------------------------------------------------------------------

from p2.s3._native import crypto as _native_crypto

RustVolumePool = getattr(_native_crypto, "VolumePool", None)


class VolumePool:
    """Manages the pool of active volume files.

    Call ``VolumePool.get()`` to obtain the singleton for this process.
    Internally keeps ``_active_pool_size()`` active handles and rotates them
    when they become full.
    """

    _instance: Optional["VolumePool"] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._pool: list[VolumeHandle] = []
        self._pool_lock = threading.Lock()
        self._vol_dir = _volume_dir()
        os.makedirs(self._vol_dir, exist_ok=True)
        if RustVolumePool is not None:
            self._rust_pool = RustVolumePool(self._vol_dir, _volume_size_bytes(), _active_pool_size())
        else:
            self._rust_pool = None
            self._fill_pool()

    @classmethod
    def get(cls) -> "VolumePool":
        """Return the process-singleton VolumePool, creating it on first call."""
        if cls._instance is not None:
            return cls._instance
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _volume_path(self, uuid_hex: str) -> str:
        return os.path.join(self._vol_dir, f"vol_{uuid_hex}.bin")

    def _create_volume(self) -> VolumeHandle:
        """Allocate a new preallocated volume file and return its handle."""
        uid = uuid.uuid4().hex
        path = self._volume_path(uid)
        size = _volume_size_bytes()

        # Preallocate file to full size (creates sparse file on most FS).
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            os.truncate(fd, size)
        finally:
            os.close(fd)

        logger.info("VolumePool: created new volume %s (%d MiB)", uid, size // (1024 * 1024))

        handle = VolumeHandle(uuid_hex=uid, path=path, size_limit=size)
        handle.open()
        return handle

    def _fill_pool(self) -> None:
        """Ensure the pool has ``_active_pool_size()`` open volumes."""
        target = _active_pool_size()
        while len(self._pool) < target:
            self._pool.append(self._create_volume())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def allocate_block(self, length: int) -> tuple[VolumeHandle, int]:
        """Reserve *length* bytes in an active volume.

        Returns ``(handle, offset)``.  Seals full volumes transparently and
        opens new ones as needed.
        """
        if length <= 0:
            raise ValueError("allocate_block: length must be > 0")

        if self._rust_pool is not None:
            # The native pool returns an owned descriptor lease. WriteJob keeps
            # this handle alive until data sync and metadata commit finish.
            uuid_hex, offset, fd = self._rust_pool.allocate_block(length)
            path = self._volume_path(uuid_hex)
            handle = VolumeHandle(uuid_hex=uuid_hex, path=path, size_limit=_volume_size_bytes())
            handle._fd = fd
            return handle, offset

        with self._pool_lock:
            for handle in self._pool:
                offset = handle.allocate(length)
                if offset is not None:
                    return handle, offset

            # All current volumes are full — rotate and create a new one.
            self._seal_full_volumes()
            self._fill_pool()

            for handle in self._pool:
                offset = handle.allocate(length)
                if offset is not None:
                    return handle, offset

        raise RuntimeError("VolumePool: unable to allocate block — pool exhausted")

    def _seal_full_volumes(self) -> None:
        """Close and remove full volumes from the active pool."""
        still_active = []
        for handle in self._pool:
            if handle.is_full:
                handle.close()
                # Mark file read-only so it can be cached and is immutable
                try:
                    os.chmod(handle.path, 0o444)
                except OSError:
                    pass
                logger.info("VolumePool: sealed volume %s", handle.uuid_hex)
            else:
                still_active.append(handle)
        self._pool = still_active

    def get_volume_path(self, uuid_hex: str) -> str:
        """Return the filesystem path for any volume (active or sealed)."""
        return self._volume_path(uuid_hex)

    def list_sealed_volumes(self) -> list[str]:
        """Return uuid_hex strings for all sealed (read-only) vol_*.bin files."""
        if self._rust_pool is not None:
            return self._rust_pool.list_sealed_volumes()

        sealed = []
        try:
            for name in os.listdir(self._vol_dir):
                if not name.startswith("vol_") or not name.endswith(".bin"):
                    continue
                path = os.path.join(self._vol_dir, name)
                mode = os.stat(path).st_mode
                # Read-only = sealed
                if not (mode & 0o200):
                    uid = name[4:-4]  # strip "vol_" prefix and ".bin" suffix
                    sealed.append(uid)
        except OSError:
            pass
        return sealed

    def get_active_uuids(self) -> list[str]:
        """Return uuid_hex strings for currently active (writable) volumes."""
        if self._rust_pool is not None:
            return self._rust_pool.get_active_uuids()

        with self._pool_lock:
            return [h.uuid_hex for h in self._pool]


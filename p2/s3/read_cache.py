"""Bounded RSGI read cache validated against LMDB's committed transaction ID."""
from collections import OrderedDict
from dataclasses import dataclass
import json
import os

import lmdb

from p2.s3.engine import get_engine


class VolumePaths:
    """Resolve read paths without initializing/preallocating a write pool."""

    def __init__(self, storage_root):
        self._vol_dir = os.path.join(os.path.abspath(storage_root), "volumes")

    def get_volume_path(self, volume_uuid):
        return os.path.join(self._vol_dir, f"vol_{volume_uuid}.bin")


@dataclass(slots=True)
class ReadEntry:
    engine: object
    transaction_id: int
    metadata: dict
    body: bytes | None = None
    headers: tuple | None = None


def load_read(volume, key, paths, small_limit, include_body):
    """One off-loop call for a metadata snapshot plus optional small payload."""
    engine = get_engine(volume)
    # A compactor can move an object's blocks between metadata lookup and open.
    # Retry the snapshot once if its old volume file has already disappeared.
    for attempt in range(2):
        with engine.env.begin(db=engine.db) as txn:
            raw = txn.get(key.encode("utf-8"))
            transaction_id = txn.id()
        if raw is None:
            return None
        metadata = json.loads(raw)
        entry = ReadEntry(engine, transaction_id, metadata)
        size = int(metadata.get("size", metadata.get("blob.p2.io/size/bytes", 0)) or 0)
        if (
            not include_body or size > small_limit or "blocks" not in metadata
            or metadata.get("sse_algorithm") or metadata.get("compressed")
        ):
            return entry
        blocks = metadata["blocks"]
        if size < 0 or any(int(block["length"]) < 0 or int(block["offset"]) < 0 for block in blocks):
            raise OSError("Invalid object block coordinates")
        if sum(int(block["length"]) for block in blocks) != size:
            raise OSError("Object metadata and block lengths disagree")
        try:
            parts = []
            for block in blocks:
                length = int(block["length"])
                with open(paths.get_volume_path(block["vol_uuid"]), "rb") as file:
                    part = os.pread(file.fileno(), length, int(block["offset"]))
                if len(part) != length:
                    raise OSError("Short volume block read")
                parts.append(part)
            entry.body = b"".join(parts)
            if len(entry.body) != size:
                raise OSError("Object metadata and block lengths disagree")
            return entry
        except FileNotFoundError:
            if attempt:
                raise


class ReadCache:
    """Event-loop-owned LRU with independent payload-byte and entry limits."""

    def __init__(self, max_entries, max_bytes):
        self.max_entries = max(0, max_entries)
        self.max_bytes = max(0, max_bytes)
        self.entries = OrderedDict()
        self.payload_bytes = 0

    def _remove(self, key):
        entry = self.entries.pop(key, None)
        if entry is not None and entry.body is not None:
            self.payload_bytes -= len(entry.body)

    def get(self, key, need_body, small_limit):
        entry = self.entries.get(key)
        if entry is None:
            return None
        try:
            # This inspects LMDB's environment metadata, not the object's B-tree
            # pages. Any committed write, from any process, invalidates old
            # snapshots. Authorization is still checked before every lookup.
            current = entry.engine.env.info()["last_txnid"]
        except lmdb.Error:
            self._remove(key)
            return None
        if current != entry.transaction_id:
            self._remove(key)
            return None
        size = int(entry.metadata.get("size", entry.metadata.get("blob.p2.io/size/bytes", 0)) or 0)
        if need_body and size <= small_limit and entry.body is None:
            return None
        self.entries.move_to_end(key)
        return entry

    def put(self, key, entry):
        self._remove(key)
        if not self.max_entries:
            return
        if entry.body is not None and len(entry.body) > self.max_bytes:
            return
        self.entries[key] = entry
        self.payload_bytes += len(entry.body) if entry.body is not None else 0
        while len(self.entries) > self.max_entries or self.payload_bytes > self.max_bytes:
            self._remove(next(iter(self.entries)))

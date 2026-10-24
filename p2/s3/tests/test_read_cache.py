"""Snapshot freshness, bounded memory, and cold-read regressions."""
import json
from unittest.mock import Mock, patch

import pytest

from p2.s3.engine import LMDbEngine
from p2.s3 import read_cache
from p2.s3.read_cache import ReadCache, ReadEntry, VolumePaths, load_read


@pytest.fixture
def engine(tmp_path):
    result = LMDbEngine(str(tmp_path / "metadata.lmdb"))
    yield result
    result.env.close()


def snapshot(engine, body=b"body"):
    return ReadEntry(engine, engine.env.info()["last_txnid"], {"size": len(body)}, body)


def test_commits_invalidate_reads_including_raw_updates_and_deletes(engine):
    cache = ReadCache(10, 100)
    cache.put("key", snapshot(engine))
    assert cache.get("key", True, 64).body == b"body"
    engine.put_raw(b"key", b'{"size":4,"blocks":[]}')
    assert cache.get("key", True, 64) is None
    assert cache.payload_bytes == 0
    cache.put("key", snapshot(engine))
    engine.delete("key")
    assert cache.get("key", True, 64) is None


def test_closed_environment_is_a_cache_miss(tmp_path):
    engine = LMDbEngine(str(tmp_path / "metadata.lmdb"))
    cache = ReadCache(10, 100)
    cache.put("key", snapshot(engine))
    engine.env.close()
    assert cache.get("key", True, 64) is None


def test_lru_enforces_bytes_and_entries_and_counts_replacements(engine):
    cache = ReadCache(2, 8)
    cache.put("first", snapshot(engine))
    cache.put("second", snapshot(engine))
    assert cache.get("first", True, 64)
    cache.put("third", snapshot(engine))
    assert cache.get("second", True, 64) is None
    assert cache.payload_bytes == 8
    cache.put("first", snapshot(engine, b"x"))
    assert cache.payload_bytes == 5
    cache.put("oversize", snapshot(engine, b"x" * 9))
    assert cache.get("oversize", True, 64) is None
    assert cache.payload_bytes == 5
    for index in range(3):
        cache.put(index, ReadEntry(engine, engine.env.info()["last_txnid"], {"size": 0}))
    assert len(cache.entries) == 2
    assert cache.payload_bytes == 0


@pytest.mark.parametrize("entries,budget", [(0, 100), (10, 0)])
def test_cache_can_be_disabled(engine, entries, budget):
    cache = ReadCache(entries, budget)
    cache.put("key", snapshot(engine))
    assert cache.get("key", True, 64) is None
    assert cache.payload_bytes == 0


def test_small_multiblock_load_uses_exact_ranges_and_snapshot(tmp_path, engine):
    paths = VolumePaths(tmp_path)
    (tmp_path / "volumes").mkdir()
    (tmp_path / "volumes" / "vol_first.bin").write_bytes(b"__abc__")
    (tmp_path / "volumes" / "vol_second.bin").write_bytes(b"_____def")
    metadata = {"size": 6, "blocks": [
        {"vol_uuid": "first", "offset": 2, "length": 3},
        {"vol_uuid": "second", "offset": 5, "length": 3},
    ]}
    engine.put_raw(b"key", json.dumps(metadata).encode())
    with patch.object(read_cache, "get_engine", return_value=engine):
        entry = load_read(None, "key", paths, 64, True)
    assert entry.body == b"abcdef"
    assert entry.transaction_id == engine.env.info()["last_txnid"]


@pytest.mark.parametrize("metadata,include_body", [
    ({"size": 7, "blocks": []}, False),
    ({"size": 100, "blocks": []}, True),
    ({"size": 7, "blocks": [], "sse_algorithm": "AES256"}, True),
    ({"size": 7, "blocks": [], "compressed": True}, True),
    ({"size": 7}, True),
])
def test_head_large_and_fallback_objects_do_not_read_data(engine, metadata, include_body):
    engine.put_raw(b"key", json.dumps(metadata).encode())
    with patch.object(read_cache, "get_engine", return_value=engine), \
            patch.object(read_cache.os, "pread", side_effect=AssertionError("unexpected read")):
        entry = load_read(None, "key", Mock(), 64, include_body)
    assert entry.metadata == metadata
    assert entry.body is None


def test_head_snapshot_does_not_satisfy_small_get(engine):
    cache = ReadCache(10, 100)
    cache.put("key", ReadEntry(engine, engine.env.info()["last_txnid"], {"size": 4}))
    assert cache.get("key", False, 64)
    assert cache.get("key", True, 64) is None


def test_invalid_blocks_are_rejected_before_allocating_body(engine):
    engine.put_raw(b"key", b'{"size":4,"blocks":[{"length":1000000000,"offset":0}]}')
    with patch.object(read_cache, "get_engine", return_value=engine), \
            patch.object(read_cache.os, "pread", side_effect=AssertionError("unexpected read")):
        with pytest.raises(OSError, match="lengths disagree"):
            load_read(None, "key", Mock(), 64, True)


def test_short_read_does_not_enter_cache(tmp_path, engine):
    paths = VolumePaths(tmp_path)
    (tmp_path / "volumes").mkdir()
    (tmp_path / "volumes" / "vol_first.bin").write_bytes(b"abc")
    engine.put_raw(b"key", b'{"size":4,"blocks":[{"vol_uuid":"first","length":4,"offset":0}]}')
    with patch.object(read_cache, "get_engine", return_value=engine):
        with pytest.raises(OSError, match="Short volume block read"):
            load_read(None, "key", paths, 64, True)


def test_compacted_file_missing_retries_latest_metadata(tmp_path, engine):
    paths = VolumePaths(tmp_path)
    (tmp_path / "volumes").mkdir()
    (tmp_path / "volumes" / "vol_new.bin").write_bytes(b"data")
    old = {"size": 4, "blocks": [{"vol_uuid": "old", "offset": 0, "length": 4}]}
    new = {"size": 4, "blocks": [{"vol_uuid": "new", "offset": 0, "length": 4}]}
    engine.put_raw(b"key", json.dumps(old).encode())
    original = paths.get_volume_path

    def compacted(volume_uuid):
        if volume_uuid == "old":
            engine.put_raw(b"key", json.dumps(new).encode())
        return original(volume_uuid)

    with patch.object(read_cache, "get_engine", return_value=engine), \
            patch.object(paths, "get_volume_path", side_effect=compacted):
        entry = load_read(None, "key", paths, 64, True)
    assert entry.body == b"data"
    assert entry.transaction_id == engine.env.info()["last_txnid"]

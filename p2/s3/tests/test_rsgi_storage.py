"""Native buffer ownership and batch durability regressions."""
import asyncio
import os
from time import perf_counter
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from p2.s3._native import crypto
from p2.s3 import volume_writer
from p2.s3.volume_pool import VolumePool


def test_shared_native_batch_preserves_offsets_and_surrounding_bytes(tmp_path):
    path = tmp_path / "volume"
    with path.open("w+b") as file:
        file.write(b"_" * 32)
        file.flush()
        crypto.write_blocks_shared([
            (file.fileno(), 3, b"first"),
            (file.fileno(), 17, b"second"),
        ])
        file.seek(0)
        assert file.read() == b"___first_________second_________"
    crypto.write_blocks_shared([])


def test_native_write_error_does_not_stop_the_writer(tmp_path):
    with pytest.raises(OSError):
        crypto.write_blocks_shared([(-1, 0, b"invalid")])
    with (tmp_path / "valid").open("w+b") as file:
        crypto.write_blocks_shared([(file.fileno(), 0, b"still alive")])
        file.seek(0)
        assert file.read() == b"still alive"


def test_allocation_fd_leases_survive_rotation_and_close_with_handles(tmp_path, settings):
    settings.STORAGE_ROOT = str(tmp_path)
    settings.VOLUME_SIZE_BYTES = 8
    settings.VOLUME_ACTIVE_POOL_SIZE = 1
    pool = VolumePool()
    first, first_offset = pool.allocate_block(8)
    second, second_offset = pool.allocate_block(8)
    try:
        crypto.write_blocks_shared([
            (first.fd, first_offset, b"first123"),
            (second.fd, second_offset, b"second12"),
        ])
        assert (tmp_path / "volumes" / f"vol_{first.uuid_hex}.bin").read_bytes() == b"first123"
        fd = first.fd
        first.close()
        with pytest.raises(OSError):
            os.fstat(fd)
        with pytest.raises(ValueError):
            pool.allocate_block(9)
    finally:
        first.close()
        second.close()


async def test_group_commit_syncs_once_per_file_before_metadata_and_resolve(settings):
    settings.S3_VOLUME_FDATASYNC = True
    events = []
    engine = Mock()
    engine.env.begin.side_effect = lambda **kwargs: events.append("begin") or Mock(
        __enter__=Mock(return_value=Mock()), __exit__=Mock(return_value=False),
    )
    loop = asyncio.get_running_loop()
    jobs = [
        volume_writer.WriteJob(
            SimpleNamespace(fd=fd, uuid_hex="same-volume"), offset, b"body",
            engine, f"key-{fd}", {}, loop.create_future(), {}, perf_counter(),
        )
        for fd, offset in [(11, 0), (12, 4)]
    ]
    with patch.object(crypto, "write_blocks_shared", side_effect=lambda batch: events.append("write")), \
            patch.object(crypto, "fdatasync_uring", side_effect=lambda fd: events.append("sync")):
        volume_writer._write_and_commit_batch(jobs, lambda job, exc: events.append("resolve"))
    assert events == ["write", "sync", "begin", "resolve", "resolve"]
    for job in jobs:
        assert {"write_queue", "data_write", "data_sync", "metadata_lock", "metadata_commit"} <= job.timings.keys()
        assert all(value >= 0 for value in job.timings.values())

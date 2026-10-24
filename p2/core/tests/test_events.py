"""Redis Streams field encoding across direct, queued, and retry delivery."""
import asyncio
import json
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest

from p2.core import events


@pytest.fixture
async def redis_events(monkeypatch, settings):
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(events, "_get_redis", lambda: redis)
    for name in ("_PUBLISH_QUEUE", "_PUBLISH_WORKER_TASK", "_PUBLISH_INIT_LOCK"):
        monkeypatch.setattr(events, name, None)
    settings.S3_EVENT_QUEUE_ENABLED = False
    settings.S3_EVENT_QUEUE_WAIT_FOR_ACK = True
    yield redis
    worker = events._PUBLISH_WORKER_TASK
    if worker is not None:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
    await redis.aclose()


@pytest.mark.parametrize("queued,retry", [(False, False), (True, False), (True, True)])
async def test_structured_event_fields_roundtrip(redis_events, settings, monkeypatch, queued, retry):
    settings.S3_EVENT_QUEUE_ENABLED = queued
    if retry:
        monkeypatch.setattr(events, "_publish_batch", AsyncMock(side_effect=RuntimeError("retry test")))
    event = events.make_event("blob", "volume", "blob_post_save")
    event.update({
        "blob_path": "folder/key", "blocks": [{"vol_uuid": "file", "offset": 7, "length": 4}],
        "details": {"tags": ["a", "b"]}, "enabled": True, "optional": None, "size": 4,
    })
    msg_id = await asyncio.wait_for(events.publish_event(events.STREAM_BLOB_POST_SAVE, event), 5)
    [(stored_id, fields)] = await redis_events.xrange(events.STREAM_BLOB_POST_SAVE)
    assert stored_id == msg_id
    assert fields["blob_uuid"] == "blob"
    assert fields["blob_path"] == "folder/key"
    assert fields["size"] == "4"
    for name in ("blocks", "details", "enabled", "optional"):
        assert json.loads(fields[name]) == event[name]
    assert isinstance(event["blocks"], list)  # Do not mutate the caller's event.


async def test_queued_event_snapshots_mutable_fields(redis_events, settings):
    settings.S3_EVENT_QUEUE_ENABLED = True
    settings.S3_EVENT_QUEUE_WAIT_FOR_ACK = False
    event = {"blocks": [{"length": 4}]}
    assert await events.publish_event(events.STREAM_BLOB_POST_SAVE, event) == "queued"
    event["blocks"][0]["length"] = 999
    async with asyncio.timeout(5):
        while not await redis_events.xlen(events.STREAM_BLOB_POST_SAVE):
            await asyncio.sleep(0)
    [(_, fields)] = await redis_events.xrange(events.STREAM_BLOB_POST_SAVE)
    assert json.loads(fields["blocks"]) == [{"length": 4}]


async def test_full_queue_fallback_encodes_structured_fields(redis_events, settings, monkeypatch):
    settings.S3_EVENT_QUEUE_ENABLED = True
    queue = asyncio.Queue(maxsize=1)
    queue.put_nowait(("unused", {}, None))
    monkeypatch.setattr(events, "_PUBLISH_QUEUE", queue)
    monkeypatch.setattr(events, "_ensure_publish_worker", AsyncMock())
    await events.publish_event(events.STREAM_BLOB_POST_SAVE, {"blocks": [{"length": 4}]})
    [(_, fields)] = await redis_events.xrange(events.STREAM_BLOB_POST_SAVE)
    assert json.loads(fields["blocks"]) == [{"length": 4}]


async def test_dead_letter_preserves_structured_fields(redis_events):
    stream, group = events.STREAM_BLOB_POST_SAVE, "test"
    msg_id = await events.publish_event(stream, {"blocks": [{"length": 4}], "blob_path": "key"})
    await redis_events.xgroup_create(stream, group, id="0")
    [(_, [(_, fields)])] = await redis_events.xreadgroup(group, "worker", {stream: ">"})
    handler = AsyncMock(side_effect=ValueError("test handler failure"))
    failures = {}
    for _ in range(events.MAX_DELIVERY_ATTEMPTS):
        await events._process_message(redis_events, stream, group, msg_id, fields, handler, failures)
    [(_, dead)] = await redis_events.xrange(events.STREAM_DEAD_LETTER)
    assert json.loads(dead["blocks"]) == [{"length": 4}]
    assert dead["original_msg_id"] == msg_id
    assert dead["blob_path"] == "key"
    assert not failures
    assert (await redis_events.xpending(stream, group))["pending"] == 0

"""
Event bus implementation using Redis Streams.

Provides publish/consume primitives for blob lifecycle events:
- STREAM_BLOB_POST_SAVE: fired after a blob is saved
- STREAM_BLOB_PAYLOAD_UPDATED: fired after blob payload changes

Event payload schema:
    blob_uuid    (str) hex UUID of the blob
    volume_uuid  (str) hex UUID of the volume
    event_type   (str) "blob_post_save" | "blob_payload_updated"
    timestamp    (str) ISO-8601 UTC timestamp

Delivery guarantees:
- At-least-once via XREADGROUP + XACK (consumer groups)
- Dead-letter after MAX_DELIVERY_ATTEMPTS failed processing attempts
"""

import logging
import asyncio
import json
from datetime import datetime, timezone

import redis.asyncio as aioredis
from django.conf import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stream names
# ---------------------------------------------------------------------------

STREAM_BLOB_POST_SAVE = "p2:events:blob_post_save"
STREAM_BLOB_PAYLOAD_UPDATED = "p2:events:blob_payload_updated"
STREAM_DEAD_LETTER = "p2:events:dead_letter"

MAX_DELIVERY_ATTEMPTS = 5
STREAM_MAX_LEN = 100_000
_REDIS_CLIENT = None
_PUBLISH_QUEUE = None
_PUBLISH_WORKER_TASK = None
_PUBLISH_INIT_LOCK = None


def _queue_enabled() -> bool:
    return bool(getattr(settings, "S3_EVENT_QUEUE_ENABLED", False))


def _queue_max_size() -> int:
    return max(1, int(getattr(settings, "S3_EVENT_QUEUE_MAX_SIZE", 8192)))


def _queue_batch_size() -> int:
    return max(1, int(getattr(settings, "S3_EVENT_QUEUE_BATCH_SIZE", 64)))


def _queue_flush_seconds() -> float:
    flush_ms = max(1, int(getattr(settings, "S3_EVENT_QUEUE_FLUSH_MS", 5)))
    return flush_ms / 1000.0


def _queue_wait_for_ack() -> bool:
    return bool(getattr(settings, "S3_EVENT_QUEUE_WAIT_FOR_ACK", False))


def _get_redis() -> aioredis.Redis:
    """Return a process-local async Redis client from the configured REDIS_URL."""
    global _REDIS_CLIENT
    if _REDIS_CLIENT is None:
        _REDIS_CLIENT = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            health_check_interval=30,
        )
    return _REDIS_CLIENT


async def _ensure_publish_worker() -> None:
    global _PUBLISH_QUEUE, _PUBLISH_WORKER_TASK, _PUBLISH_INIT_LOCK
    if not _queue_enabled():
        return
    if _PUBLISH_WORKER_TASK is not None and not _PUBLISH_WORKER_TASK.done():
        return
    if _PUBLISH_INIT_LOCK is None:
        _PUBLISH_INIT_LOCK = asyncio.Lock()
    async with _PUBLISH_INIT_LOCK:
        if _PUBLISH_QUEUE is None:
            _PUBLISH_QUEUE = asyncio.Queue(maxsize=_queue_max_size())
        if _PUBLISH_WORKER_TASK is None or _PUBLISH_WORKER_TASK.done():
            _PUBLISH_WORKER_TASK = asyncio.create_task(_publish_worker(), name="p2-event-publish-worker")


async def _publish_batch(r: aioredis.Redis, batch: list[tuple[str, dict, asyncio.Future | None]]) -> None:
    pipe = r.pipeline(transaction=False)
    for stream, event, _ in batch:
        pipe.xadd(stream, event, maxlen=STREAM_MAX_LEN, approximate=True)
    ids = await pipe.execute()
    for (_, event, fut), msg_id in zip(batch, ids):
        if fut is not None and not fut.done():
            fut.set_result(msg_id)
        logger.debug("published event id=%s type=%s", msg_id, event.get("event_type"))


async def _publish_worker() -> None:
    assert _PUBLISH_QUEUE is not None
    r = _get_redis()
    batch_size = _queue_batch_size()
    flush_seconds = _queue_flush_seconds()
    while True:
        batch: list[tuple[str, dict, asyncio.Future | None]] = []
        try:
            item = await asyncio.wait_for(_PUBLISH_QUEUE.get(), timeout=flush_seconds)
            batch.append(item)
            while len(batch) < batch_size:
                try:
                    batch.append(_PUBLISH_QUEUE.get_nowait())
                except asyncio.QueueEmpty:
                    break
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            raise

        if not batch:
            continue

        try:
            await _publish_batch(r, batch)
        except Exception as exc:  # noqa: BLE001
            logger.warning("event queue batch publish failed, falling back per-event: %s", exc)
            for stream, event, fut in batch:
                try:
                    msg_id = await r.xadd(stream, event, maxlen=STREAM_MAX_LEN, approximate=True)
                    if fut is not None and not fut.done():
                        fut.set_result(msg_id)
                except Exception as one_exc:  # noqa: BLE001
                    if fut is not None and not fut.done():
                        fut.set_exception(one_exc)
                    logger.error("event publish failed for stream=%s: %s", stream, one_exc)


def make_event(blob_uuid: str, volume_uuid: str, event_type: str) -> dict:
    """Build a well-formed event payload dict."""
    return {
        "blob_uuid": blob_uuid,
        "volume_uuid": volume_uuid,
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _stream_fields(event: dict) -> dict:
    """Redis stream values are scalar; structured fields use JSON on the wire.

    Keep existing scalar fields unchanged. In particular, do not JSON-quote
    identifiers or paths. Consumers can json.loads() structured fields such as
    blocks, just as they already do for exif_json.
    """
    return {
        name: json.dumps(value, separators=(",", ":"))
        if value is None or isinstance(value, (list, dict, tuple, bool))
        else value
        for name, value in event.items()
    }


async def publish_event(stream: str, event: dict) -> str:
    """Publish *event* to *stream*. Returns the Redis message ID."""
    # Normalize once, before either direct XADD or queued/pipelined delivery.
    # This also snapshots mutable structured values before queueing.
    event = _stream_fields(event)
    if _queue_enabled():
        await _ensure_publish_worker()
        try:
            if _queue_wait_for_ack():
                loop = asyncio.get_running_loop()
                fut = loop.create_future()
                _PUBLISH_QUEUE.put_nowait((stream, event, fut))
                return await fut
            _PUBLISH_QUEUE.put_nowait((stream, event, None))
            return "queued"
        except asyncio.QueueFull:
            logger.warning("event queue full; publishing directly for stream=%s", stream)

    r = _get_redis()
    msg_id = await r.xadd(stream, event, maxlen=STREAM_MAX_LEN, approximate=True)
    logger.debug("published event to %s id=%s type=%s", stream, msg_id, event.get("event_type"))
    return msg_id


async def consume_events(stream: str, group: str, consumer: str, handler) -> None:
    """Consume events from *stream* using a consumer group with at-least-once delivery."""
    r = _get_redis()
    try:
        await r.xgroup_create(stream, group, id="0", mkstream=True)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise

    failure_counts: dict[str, int] = {}
    while True:
        messages = await r.xreadgroup(group, consumer, {stream: ">"}, count=10, block=5000)
        if not messages:
            continue
        for _stream_name, entries in messages:
            for msg_id, data in entries:
                await _process_message(r, stream, group, msg_id, data, handler, failure_counts)


async def _process_message(r, stream, group, msg_id, data, handler, failure_counts):
    try:
        await handler(data)
        await r.xack(stream, group, msg_id)
        failure_counts.pop(msg_id, None)
    except Exception as exc:  # noqa: BLE001
        attempts = failure_counts.get(msg_id, 0) + 1
        failure_counts[msg_id] = attempts
        logger.warning("handler failed for %s on %s (attempt %d/%d): %s",
                       msg_id, stream, attempts, MAX_DELIVERY_ATTEMPTS, exc)
        if attempts >= MAX_DELIVERY_ATTEMPTS:
            await _dead_letter(r, stream, group, msg_id, data, exc)
            failure_counts.pop(msg_id, None)


async def _dead_letter(r, stream, group, msg_id, data, exc):
    payload = {
        **data,
        "original_stream": stream,
        "original_msg_id": msg_id,
        "error": str(exc),
        "dead_lettered_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        await r.xadd(STREAM_DEAD_LETTER, _stream_fields(payload), maxlen=STREAM_MAX_LEN, approximate=True)
        await r.xack(stream, group, msg_id)
        logger.error("dead-lettered message %s from %s: %s", msg_id, stream, exc)
    except aioredis.RedisError as redis_exc:
        logger.error("failed to dead-letter message %s: %s", msg_id, redis_exc)

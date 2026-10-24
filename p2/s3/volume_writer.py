"""Batched io_uring writes and atomic JSON metadata publication.

Each Granian worker owns a bounded queue.  PUTs wait for their own futures, but
writes arriving within a short window are submitted as one native tokio-uring
batch and their metadata is committed in one LMDB transaction per engine.
"""
from __future__ import annotations

import asyncio
import logging
import json
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING, Union, Dict, Any

from django.conf import settings

from p2.s3._native import crypto as p2_s3_crypto

if p2_s3_crypto is None:
    # This module has no pure-Python fallback: every write goes through
    # ``write_blocks_uring``. Fail at import rather than at the first PUT, which
    # is what a plain ``import p2_s3_crypto`` used to do here. See p2.s3._native
    # for the diagnostics and for P2_REQUIRE_NATIVE.
    raise ImportError(
        "p2.s3.volume_writer requires the p2_s3_crypto Rust extension, which "
        "failed to load or is stale. Build it with: bash p2/s3/rust_ext/build.sh"
    )

if TYPE_CHECKING:
    from p2.s3.volume_pool import VolumeHandle

logger = logging.getLogger(__name__)

_BATCH_WINDOW_SECONDS = 0.001
_QUEUE: asyncio.Queue["WriteJob"] | None = None
_WORKER: asyncio.Task[None] | None = None
_STATE_LOOP: asyncio.AbstractEventLoop | None = None
_INIT_LOCK: asyncio.Lock | None = None


@dataclass(slots=True)
class WriteJob:
    handle: "VolumeHandle"
    offset: int
    data: bytes
    engine: object
    lmdb_key: str
    metadata_json: Union[str, Dict[str, Any]]
    completion: asyncio.Future[bool]
    timings: dict[str, float] | None = None
    submitted_at: float = 0.0


def _queue_max_size() -> int:
    return max(1, int(getattr(settings, "S3_METADATA_WRITE_QUEUE_MAX_SIZE", 32768)))


def _batch_size() -> int:
    return max(1, int(getattr(settings, "S3_METADATA_WRITE_BATCH_SIZE", 128)))


def _batch_window_seconds() -> float:
    """Coalescing wait (seconds) for small batches.

    Reads the documented ``S3_METADATA_WRITE_BATCH_WINDOW_MS`` setting
    instead of the previous hardcoded ``_BATCH_WINDOW_SECONDS`` constant, so
    the value is actually tunable (see docs/milliscale_optimization_plan.md,
    #3). Falls back to the module constant's prior default (1ms) if unset.
    """
    ms = float(getattr(settings, "S3_METADATA_WRITE_BATCH_WINDOW_MS", _BATCH_WINDOW_SECONDS * 1000))
    return max(0.0, ms) / 1000.0


async def _ensure_batch_worker() -> asyncio.Queue[WriteJob]:
    """Return the queue associated with this Granian worker's event loop."""
    global _QUEUE, _WORKER, _STATE_LOOP, _INIT_LOCK

    loop = asyncio.get_running_loop()
    if _STATE_LOOP is loop and _QUEUE is not None and _WORKER is not None and not _WORKER.done():
        return _QUEUE

    if _STATE_LOOP is not loop:
        _QUEUE = None
        _WORKER = None
        _INIT_LOCK = None
        _STATE_LOOP = loop

    if _INIT_LOCK is None:
        _INIT_LOCK = asyncio.Lock()

    async with _INIT_LOCK:
        if _QUEUE is None:
            _QUEUE = asyncio.Queue(maxsize=_queue_max_size())
        if _WORKER is None or _WORKER.done():
            if _WORKER is not None and not _WORKER.cancelled():
                exception = _WORKER.exception()
                if exception:
                    logger.error("io_uring batch worker stopped: %s", exception)
            _WORKER = asyncio.create_task(_batch_worker(_QUEUE), name="p2-io-uring-batch-writer")
        return _QUEUE


def _resolve_future(fut: "asyncio.Future[bool]", value: bool) -> None:
    """Resolve *fut* with *value*. Safe if already done."""
    if not fut.done():
        fut.set_result(value)


def _fail_future(fut: "asyncio.Future[bool]", exc: BaseException) -> None:
    """Fail *fut* with *exc*. Safe if already done."""
    if not fut.done():
        fut.set_exception(exc)


def _threadsafe_resolver(loop: asyncio.AbstractEventLoop):
    """Build a resolver that schedules completion callbacks onto *loop*.

    Used by the batch worker, which runs this function via
    ``asyncio.to_thread`` while the loop itself is elsewhere running the
    coroutine that awaits each job's completion.
    """

    def resolve(job: WriteJob, exc: BaseException | None) -> None:
        if exc is None:
            loop.call_soon_threadsafe(_resolve_future, job.completion, True)
        else:
            loop.call_soon_threadsafe(_fail_future, job.completion, exc)

    return resolve


def _inline_resolver():
    """Build a resolver that resolves completions synchronously, in-thread.

    Used by ``_direct_write``, which calls ``_write_and_commit_batch``
    directly without an active event loop backing the future — there is no
    loop to schedule a threadsafe callback onto, so resolve immediately.
    """

    def resolve(job: WriteJob, exc: BaseException | None) -> None:
        if exc is None:
            _resolve_future(job.completion, True)
        else:
            _fail_future(job.completion, exc)

    return resolve


def _write_and_commit_batch(batch: list[WriteJob], resolve) -> None:
    """Perform native writes, then atomically publish metadata per LMDB engine.

    Each engine's jobs are committed and their completions resolved
    independently via *resolve* (job, exc_or_None): a PUT going to a quiet
    volume must not wait on an unrelated volume's LMDB commit just because
    both writes landed in the same batching window
    (see docs/milliscale_optimization_plan.md, #1).
    """
    measured = any(job.timings is not None for job in batch)
    started = perf_counter() if measured else 0.0
    if measured:
        for job in batch:
            if job.timings is not None:
                job.timings["write_queue"] = (started - job.submitted_at) * 1000
    write_jobs = [job for job in batch if job.data]
    if write_jobs:
        p2_s3_crypto.write_blocks_shared(
            [(job.handle.fd, job.offset, job.data) for job in write_jobs]
        )
        written = perf_counter() if measured else 0.0

        # One fdatasync per unique volume fd touched by this batch, issued
        # once data is on disk and before any metadata commit references it.
        # Amortizes the durability syscall across the whole batch instead of
        # per write, and keeps the write-ahead ordering (data durable before
        # metadata says it exists) intact for every engine below.
        if getattr(settings, "S3_VOLUME_FDATASYNC", True):
            synced_volumes: set[str] = set()
            for job in write_jobs:
                # Allocations own distinct descriptor leases, even when they
                # target the same volume file. Sync that file only once.
                volume_id = job.handle.uuid_hex
                if volume_id not in synced_volumes:
                    p2_s3_crypto.fdatasync_uring(job.handle.fd)
                    synced_volumes.add(volume_id)
        if measured:
            synced = perf_counter()
            for job in batch:
                if job.timings is not None:
                    job.timings["data_write"] = (written - started) * 1000
                    job.timings["data_sync"] = (synced - written) * 1000

    by_engine: dict[int, tuple[object, list[WriteJob]]] = {}
    for job in batch:
        group = by_engine.setdefault(id(job.engine), (job.engine, []))
        group[1].append(job)

    for engine, jobs in by_engine.values():
        try:
            # Pre-serialize all JSON outside the write transaction to minimize lock time
            serialized_jobs = []
            for job in jobs:
                meta_str = json.dumps(job.metadata_json) if isinstance(job.metadata_json, dict) else job.metadata_json
                serialized_jobs.append((job.lmdb_key.encode("utf-8"), meta_str.encode("utf-8")))

            lock_started = perf_counter() if measured else 0.0
            with engine.env.begin(write=True, db=engine.db) as txn:
                lock_acquired = perf_counter() if measured else 0.0
                for key, val in serialized_jobs:
                    txn.put(key, val)
            if measured:
                committed = perf_counter()
                for job in jobs:
                    if job.timings is not None:
                        job.timings["metadata_lock"] = (lock_acquired - lock_started) * 1000
                        job.timings["metadata_commit"] = (committed - lock_acquired) * 1000
        except Exception as exc:  # noqa: BLE001 - isolate failure to this engine's jobs only
            logger.exception("LMDB commit failed for engine batch of %d objects", len(jobs))
            for job in jobs:
                resolve(job, exc)
        else:
            for job in jobs:
                resolve(job, None)


async def _batch_worker(queue: asyncio.Queue[WriteJob]) -> None:
    max_batch = _batch_size()
    batch_window = _batch_window_seconds()
    loop = asyncio.get_running_loop()
    resolve = _threadsafe_resolver(loop)
    while True:
        first = await queue.get()
        batch = [first]
        try:
            # Drain whatever is already queued immediately — under real
            # concurrency, other PUTs have usually already enqueued by the
            # time this task resumes, so this costs no extra latency.
            while len(batch) < max_batch:
                try:
                    batch.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            # Only pay the coalescing tax when the batch is still small,
            # i.e. genuinely low concurrency where a short wait can still
            # pick up a few more writers without hurting solo-request p50.
            if len(batch) < 4 and batch_window > 0:
                await asyncio.sleep(batch_window)
                while len(batch) < max_batch:
                    try:
                        batch.append(queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

            # Completions are resolved per-engine inside _write_and_commit_batch
            # as soon as that engine's own write + LMDB commit finishes,
            # rather than after the whole batch returns — this avoids
            # coupling unrelated volumes/engines that happened to land in
            # the same batching window.
            await asyncio.to_thread(_write_and_commit_batch, batch, resolve)
        except asyncio.CancelledError:
            for job in batch:
                if not job.completion.done():
                    job.completion.cancel()
            raise
        except Exception as exc:
            # Only reached if _write_and_commit_batch raised before it could
            # isolate the failure to individual engines (e.g. the shared
            # io_uring write call itself failed).
            logger.exception("io_uring batch write failed for %d objects", len(batch))
            for job in batch:
                if not job.completion.done():
                    job.completion.set_exception(exc)
        finally:
            for _ in batch:
                queue.task_done()


async def write_block(
    handle: "VolumeHandle",
    offset: int,
    data: bytes,
    engine: object,
    lmdb_key: str,
    metadata_json: Union[str, Dict[str, Any]],
    md5_hash: bytes | None = None,
    *,
    timings: dict[str, float] | None = None,
) -> bool:
    """Queue a write and wait until its data and metadata are both visible."""
    del md5_hash
    loop = asyncio.get_running_loop()
    queue = await _ensure_batch_worker()
    completion: asyncio.Future[bool] = loop.create_future()
    job = WriteJob(
        handle, offset, data, engine, lmdb_key, metadata_json, completion,
        timings, perf_counter() if timings is not None else 0.0,
    )

    # Awaiting bounded queue capacity applies backpressure rather than growing
    # memory without limit when clients exceed storage service capacity.
    await queue.put(job)
    return await completion


async def shutdown_writer() -> None:
    """Drain accepted writes before the RSGI worker loop closes."""
    if _STATE_LOOP is not asyncio.get_running_loop() or _WORKER is None:
        return
    if _QUEUE is not None and not _WORKER.done():
        await _QUEUE.join()
    _WORKER.cancel()
    await asyncio.gather(_WORKER, return_exceptions=True)


def _direct_write(
    handle: "VolumeHandle",
    offset: int,
    data: bytes,
    engine: object,
    lmdb_key: str,
    metadata_json: Union[str, Dict[str, Any]],
) -> None:
    """Synchronous compatibility path with the same native batch primitive."""
    loop = asyncio.new_event_loop()
    try:
        completion = loop.create_future()
        _write_and_commit_batch(
            [WriteJob(handle, offset, data, engine, lmdb_key, metadata_json, completion)],
            _inline_resolver(),
        )
        if completion.done():
            completion.result()
    finally:
        loop.close()

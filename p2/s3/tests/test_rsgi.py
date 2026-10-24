"""RSGI 1.6 contract, data-plane routing, and backpressure regressions."""
import asyncio
import hashlib
import threading
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest

from p2.core.rsgi_bridge import asgi_scope, call_asgi
from p2.s3 import cache as s3_cache
from p2.s3 import rsgi_handler as handler
from p2.s3.datapath import ByteBudget, await_commit
from p2.s3.read_cache import ReadEntry


class Headers(dict):
    def get_all(self, name):
        return [self[name]]


def scope(method="GET", path="/bucket/key", headers=None, query=""):
    return SimpleNamespace(
        proto="http", method=method, path=path, query_string=query,
        headers=Headers(headers or {"authorization": "AWS4-HMAC-SHA256 test"}),
        authority=None, http_version="1.1", scheme="http",
        server="[::1]:8787", client="127.0.0.1:12345",
    )


class Protocol:
    """Only RSGI 1.6 HTTP methods; deliberately no receive/send/close shim."""

    def __init__(self, body=b""):
        self.body = body
        self.reads = 0
        self.response = None
        self.chunks = []
        self.disconnect_cancelled = False

    async def __call__(self):
        self.reads += 1
        return self.body

    async def __aiter__(self):
        self.reads += 1
        for start in range(0, len(self.body), 2):
            yield self.body[start:start + 2]

    async def client_disconnect(self):
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.disconnect_cancelled = True
            raise

    def response_bytes(self, status, headers, body):
        self.response = status, headers, body

    def response_empty(self, status, headers):
        self.response = status, headers, b""

    def response_stream(self, status, headers):
        self.response = status, headers, None
        return self

    async def send_bytes(self, body):
        self.chunks.append(body)

    def response_file_range(self, status, headers, file, start, end):
        self.response = status, headers, (file, start, end)


@pytest.fixture
def dataplane(settings):
    settings.S3_RSGI_MAX_BODY_BYTES = 1024
    settings.S3_RSGI_INFLIGHT_BYTES = 2048
    settings.S3_BENCHMARK_TIMINGS = True
    settings.S3_ASYNC_EVENT_PUBLISH = False
    volume = SimpleNamespace(uuid=uuid4(), tags={})
    auth = Mock()
    auth.can_handle.return_value = True
    auth.return_value.validate = AsyncMock(return_value=object())
    fallback = AsyncMock()
    with ExitStack() as stack:
        stack.enter_context(patch.object(handler, "AWSV4Authentication", auth))
        stack.enter_context(patch.object(handler, "aget_cached_volume", AsyncMock(return_value=volume)))
        stack.enter_context(patch.object(handler, "require_volume_permission", AsyncMock()))
        yield handler.S3ProxyRSGIApp(fallback), fallback, volume


async def test_bridge_request_body_and_response():
    protocol = Protocol(b"abcdef")

    async def asgi(app_scope, receive, send):
        assert app_scope["path"] == "/bucket/a b%2F"
        data = bytearray()
        while True:
            message = await receive()
            data.extend(message["body"])
            if not message["more_body"]:
                break
        assert data == b"abcdef"
        await send({"type": "http.response.start", "status": 201, "headers": [
            (b"set-cookie", b"a=1"), (b"set-cookie", b"b=2"),
        ]})
        await send({"type": "http.response.body", "body": b"ok"})

    await call_asgi(asgi, scope(path="/bucket/a b%2F"), protocol)
    assert protocol.response == (201, [
        ("set-cookie", "a=1"), ("set-cookie", "b=2"), ("x-p2-datapath", "django"),
    ], b"ok")


async def test_bridge_stream_and_disconnect_watcher_cleanup():
    protocol = Protocol()
    watcher = None

    async def asgi(app_scope, receive, send):
        nonlocal watcher
        await receive()
        watcher = asyncio.create_task(receive())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await send({"type": "http.response.start", "status": 200})
        await send({"type": "http.response.body", "body": b"one", "more_body": True})
        await send({"type": "http.response.body", "body": b"two"})
        assert (await watcher)["type"] == "http.disconnect"

    await call_asgi(asgi, scope(), protocol)
    assert protocol.chunks == [b"one", b"two"]
    assert protocol.disconnect_cancelled


class FutureLikeDisconnect:
    """Mimic Granian's awaitable, recognized as a future but lacking cancelled()."""

    _asyncio_future_blocking = False

    def __init__(self):
        self.inner = asyncio.get_running_loop().create_future()

    def __await__(self):
        return self.inner.__await__()

    def __getattr__(self, name):
        if name == "cancelled":
            raise AttributeError(name)
        return getattr(self.inner, name)


@pytest.mark.parametrize("application_fails", [False, True])
async def test_bridge_wraps_native_future_like_disconnect(application_fails):
    protocol = Protocol()
    disconnect = FutureLikeDisconnect()
    created = asyncio.Event()
    assert asyncio.isfuture(disconnect)
    assert not hasattr(disconnect, "cancelled")

    def watch_disconnect():
        created.set()
        return disconnect

    protocol.client_disconnect = watch_disconnect

    async def asgi(app_scope, receive, send):
        assert not (await receive())["more_body"]
        watcher = asyncio.create_task(receive())
        try:
            await created.wait()
            if application_fails:
                raise ValueError("application failed")
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b"ok"})
            assert (await watcher)["type"] == "http.disconnect"
        finally:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)

    if application_fails:
        with pytest.raises(ValueError, match="application failed"):
            await call_asgi(asgi, scope(), protocol)
    else:
        await call_asgi(asgi, scope(), protocol)
        assert protocol.response == (200, [("x-p2-datapath", "django")], b"ok")
    assert disconnect.inner.cancelled()


def test_bridge_scope_ipv6_http2_authority_and_duplicate_headers():
    class DuplicateHeaders(Headers):
        def get_all(self, name):
            return ["first", "second"]

    request = scope(headers={"x-test": "first"})
    request.headers = DuplicateHeaders(request.headers)
    request.authority = "example.test:8787"
    request.http_version = "2"
    converted = asgi_scope(request)
    assert converted["server"] == ("::1", 8787)
    assert converted["client"] == ("127.0.0.1", 12345)
    assert converted["http_version"] == "2"
    assert converted["headers"] == [
        (b"x-test", b"first"), (b"x-test", b"second"), (b"host", b"example.test:8787"),
    ]


@pytest.mark.parametrize("method,headers,query", [
    ("GET", {"range": "bytes=1-3"}, ""),
    ("GET", {"if-none-match": '"etag"'}, ""),
    ("GET", {}, "versionId=old"),
    ("GET", {}, "response-content-type=text%2Fplain"),
    ("PUT", {}, "uploads"),
    ("PUT", {"x-amz-copy-source": "/source/key"}, ""),
    ("PUT", {"x-amz-server-side-encryption": "AES256"}, ""),
    ("PUT", {"content-encoding": "aws-chunked"}, ""),
    ("PUT", {"x-amz-checksum-crc64nvme": "test"}, ""),
    ("PUT", {"x-amz-trailer": "x-amz-checksum-crc32"}, ""),
    ("PUT", {"content-length": "1025"}, ""),
    ("PUT", {}, ""),
    ("POST", {}, ""),
])
async def test_complex_requests_fall_back_without_consuming_body(dataplane, method, headers, query):
    app, fallback, _ = dataplane
    headers = {"authorization": "AWS4-HMAC-SHA256 test", **headers}
    protocol = Protocol(b"untouched")
    await app(scope(method=method, headers=headers, query=query), protocol)
    fallback.assert_awaited_once()
    assert protocol.reads == 0
    assert protocol.response is None


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
async def test_versioned_mutations_fall_back(dataplane, method):
    app, fallback, volume = dataplane
    volume.tags["versioning"] = "true"
    protocol = Protocol()
    await app(scope(method, headers={
        "authorization": "AWS4-HMAC-SHA256 test", "content-length": "0",
    }), protocol)
    fallback.assert_awaited_once()
    assert protocol.reads == 0


async def test_get_delegates_exact_file_range_to_rust(dataplane):
    app, fallback, _ = dataplane
    size = 64 * 1024 + 1
    metadata = {
        "size": size, "mime": "application/octet-stream", "etag": "abc",
        "blocks": [{"vol_uuid": "volume", "offset": 19, "length": size}],
    }
    with patch.object(handler, "load_read", return_value=ReadEntry(None, 0, metadata)), \
            patch.object(handler.VolumePaths, "get_volume_path", return_value="/test/vol_volume.bin"), \
            patch.object(handler.VolumePool, "get", side_effect=AssertionError("unexpected allocation")):
        protocol = Protocol()
        await app(scope(), protocol)
    assert protocol.response[0] == 200
    assert protocol.response[2] == ("/test/vol_volume.bin", 19, 19 + size)
    assert dict(protocol.response[1])["content-length"] == str(size)
    fallback.assert_not_awaited()


@pytest.mark.parametrize("method,size", [("HEAD", 7), ("GET", 0)])
async def test_head_and_empty_get_need_no_volume_pool(dataplane, method, size):
    app, fallback, _ = dataplane
    metadata = {"size": size, "blocks": [], "mime": "text/plain"}
    with patch.object(handler, "load_read", return_value=ReadEntry(None, 0, metadata)), \
            patch.object(handler.VolumePool, "get", side_effect=AssertionError("unexpected allocation")):
        protocol = Protocol()
        await app(scope(method), protocol)
    assert protocol.response[0] == 200
    assert protocol.response[2] == b""
    fallback.assert_not_awaited()


async def test_multiblock_get_uses_response_stream(dataplane):
    app, _, _ = dataplane
    part_size = 64 * 1024
    metadata = {"size": 2 * part_size, "blocks": [
        {"vol_uuid": "first", "offset": 0, "length": part_size},
        {"vol_uuid": "second", "offset": 5, "length": part_size},
    ]}

    async def chunks(pool, blocks):
        yield b"a" * part_size
        yield b"b" * part_size

    with patch.object(handler, "load_read", return_value=ReadEntry(None, 0, metadata)), \
            patch.object(handler.VolumePool, "get", side_effect=AssertionError("unexpected allocation")), \
            patch.object(handler, "stream_blocks", chunks):
        protocol = Protocol()
        await app(scope(), protocol)
    assert protocol.response[0] == 200
    assert protocol.chunks == [b"a" * part_size, b"b" * part_size]


async def test_small_get_cache_hit_avoids_thread_dispatch_but_rechecks_permissions(dataplane):
    app, _, _ = dataplane
    engine = Mock()
    engine.env.info.return_value = {"last_txnid": 7}
    entry = ReadEntry(engine, 7, {"size": 3, "blocks": [], "etag": "old"}, b"abc")
    permission = handler.require_volume_permission
    with patch.object(handler, "load_read", return_value=entry) as load:
        first, second = Protocol(), Protocol()
        await app(scope(), first)
        with patch.object(asyncio, "to_thread", side_effect=AssertionError("unexpected thread hop")):
            await app(scope(), second)
    assert first.response[2] == second.response[2] == b"abc"
    assert dict(first.response[1])["x-p2-read-cache"] == "miss"
    assert dict(second.response[1])["x-p2-read-cache"] == "hit"
    assert permission.await_count == 2
    load.assert_called_once()


async def test_small_get_cache_invalidates_after_other_worker_commit(dataplane):
    app, _, _ = dataplane
    engine = Mock()
    engine.env.info.return_value = {"last_txnid": 7}
    old = ReadEntry(engine, 7, {"size": 3, "blocks": []}, b"old")
    new = ReadEntry(engine, 8, {"size": 3, "blocks": []}, b"new")
    with patch.object(handler, "load_read", side_effect=[old, new, None]) as load:
        first, second, third = Protocol(), Protocol(), Protocol()
        await app(scope(), first)
        engine.env.info.return_value = {"last_txnid": 8}
        await app(scope(), second)
        engine.env.info.return_value = {"last_txnid": 9}
        await app(scope(), third)
    assert first.response[2] == b"old"
    assert second.response[2] == b"new"
    assert third.response[0] == 404
    assert load.call_count == 3


async def test_cached_response_headers_do_not_reuse_another_requests_origin(dataplane):
    app, _, _ = dataplane
    engine = Mock()
    engine.env.info.return_value = {"last_txnid": 7}
    entry = ReadEntry(engine, 7, {"size": 3, "blocks": []}, b"abc")

    def cors(headers, volume, origin, method):
        headers.append(("access-control-allow-origin", origin))

    with patch.object(handler, "load_read", return_value=entry), \
            patch.object(handler, "_apply_cors", side_effect=cors):
        for origin in ("https://first.example", "https://second.example"):
            protocol = Protocol()
            await app(scope(headers={"authorization": "AWS4-HMAC-SHA256 test", "origin": origin}), protocol)
            assert dict(protocol.response[1])["access-control-allow-origin"] == origin
            assert sum(name == "access-control-allow-origin" for name, _ in protocol.response[1]) == 1
    assert not any(name == "access-control-allow-origin" for name, _ in entry.headers)


async def test_put_calls_sync_stats_normally_and_exposes_timings(dataplane):
    app, _, volume = dataplane
    payload = b"payload"
    engine = Mock()
    handle = SimpleNamespace(uuid_hex="file", fd=9)
    loop_thread = threading.get_ident()

    def read_metadata(*args):
        assert threading.get_ident() != loop_thread
        return engine, {"size": 3, "ctime": "original"}

    with patch.object(handler, "_read_metadata", side_effect=read_metadata), \
            patch.object(handler.VolumePool, "get") as get_pool, \
            patch.object(handler, "write_block", AsyncMock()) as write, \
            patch.object(handler, "update_volume_stats_for_put") as stats:
        get_pool.return_value.allocate_block.return_value = (handle, 17)
        protocol = Protocol(payload)
        await app(scope("PUT", headers={
            "authorization": "AWS4-HMAC-SHA256 test",
            "content-length": str(len(payload)),
        }), protocol)
    assert protocol.response[0] == 200
    stats.assert_called_once_with(volume, True, 3, len(payload))
    write.assert_awaited_once()
    assert write.call_args.args[5]["ctime"] == "original"
    assert write.call_args.args[2] is payload
    assert "hash_integrity;dur=" in dict(protocol.response[1])["server-timing"]


async def test_bad_checksum_never_publishes_metadata(dataplane):
    app, _, _ = dataplane
    with patch.object(handler, "_read_metadata") as read:
        protocol = Protocol(b"payload")
        await app(scope("PUT", headers={
            "authorization": "AWS4-HMAC-SHA256 test", "content-length": "7",
            "x-amz-content-sha256": hashlib.sha256(b"wrong").hexdigest(),
        }), protocol)
    assert protocol.response[0] == 403
    assert b"XAmzContentSHA256Mismatch" in protocol.response[2]
    read.assert_not_called()


async def test_incomplete_body_never_reaches_storage(dataplane):
    app, _, _ = dataplane
    with patch.object(handler, "_put", AsyncMock()) as put:
        protocol = Protocol(b"x")
        await app(scope("PUT", headers={
            "authorization": "AWS4-HMAC-SHA256 test", "content-length": "7",
        }), protocol)
    assert protocol.response[0] == 400
    put.assert_not_awaited()


@pytest.mark.parametrize("signed", [False, True])
async def test_framed_put_reserves_encoded_and_decoded_buffer_space(dataplane, signed):
    _, fallback, _ = dataplane
    from p2.s3.tests.test_put_body import framed_put
    raw, headers = framed_put()
    if signed:
        from botocore.credentials import Credentials
        from p2.s3.tests.streaming_signer import signed_put
        raw, signed_headers = signed_put("http://example.com", "/bucket/key", Credentials("test", "test"), b"abcdef")
        headers = {name.lower(): value for name, value in signed_headers.items()}
    budget = ByteBudget(2048)

    async def commit(*args):
        assert budget.used == len(raw) * 2
        return {"etag": "test"}

    with patch.object(handler, "ByteBudget", return_value=budget), \
            patch.object(handler, "_put", side_effect=commit):
        app = handler.S3ProxyRSGIApp(fallback)
        protocol = Protocol(raw)
        await app(scope("PUT", headers={
            "authorization": "AWS4-HMAC-SHA256 test", "content-length": str(len(raw)), **headers,
        }), protocol)
    assert protocol.response[0] == 200
    assert budget.used == 0
    fallback.assert_not_awaited()


async def test_oversize_metadata_fails_before_storage_allocation(dataplane):
    app, _, _ = dataplane
    with patch.object(handler, "_read_metadata") as read:
        protocol = Protocol(b"body")
        await app(scope("PUT", headers={
            "authorization": "AWS4-HMAC-SHA256 test", "content-length": "4",
            "x-amz-meta-too-big": "x" * 2048,
        }), protocol)
    assert protocol.response[0] == 400
    read.assert_not_called()

async def test_byte_budget_blocks_and_recovers_from_waiter_cancellation():
    budget = ByteBudget(10)
    entered = asyncio.Event()

    async def waiter():
        async with budget.reserve(5):
            entered.set()

    async with budget.reserve(8):
        task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        assert not entered.is_set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert budget.used == 8
    assert budget.used == 0
    await waiter()
    assert entered.is_set()


async def test_cancelled_http_task_keeps_budget_until_commit_finishes():
    budget = ByteBudget(10)
    started, finish = asyncio.Event(), asyncio.Event()

    async def commit():
        started.set()
        await finish.wait()

    async def request():
        async with budget.reserve(10):
            await await_commit(commit())

    task = asyncio.create_task(request())
    await started.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert budget.used == 10
    assert not task.done()
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert budget.used == 0


async def test_async_generation_checks_are_singleflight_and_nonblocking(settings):
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    s3_cache.clear_all_caches()
    started, finish = asyncio.Event(), asyncio.Event()

    async def check(key):
        started.set()
        await finish.wait()
        return 3

    with patch("django.core.cache.cache.aget", side_effect=check) as read:
        first = asyncio.create_task(s3_cache.aget_cached_volume("bucket"))
        second = asyncio.create_task(s3_cache.aget_cached_volume("bucket"))
        await started.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert not second.done()
        finish.set()
        assert await second is None
        await s3_cache.aget_cached_volume("bucket")
        assert read.call_count == 1
    s3_cache.clear_all_caches()


async def test_async_generation_change_evicts_revoked_key(settings):
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
    s3_cache.clear_all_caches()
    with patch("django.core.cache.cache.aget", AsyncMock(return_value=1)):
        await s3_cache.aset_cached_apikey("key", "test-only", 1, "user", False)
    s3_cache._apikey_gen_cache["key"] = (1, 0)
    with patch("django.core.cache.cache.aget", AsyncMock(return_value=2)):
        assert await s3_cache.aget_cached_apikey("key") is None
    s3_cache.clear_all_caches()

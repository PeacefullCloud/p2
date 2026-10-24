"""Experimental S3 fast path using only the RSGI 1.6 HTTP interface.

Ordinary single-object operations stay outside Django. Complex S3 semantics
fall back before the request body is consumed. LMDB misses and allocation run
off-loop; single-block GETs let Granian read the exact volume-file range.
"""
import asyncio
import datetime as dt
import hashlib
import json
import logging
import os
from urllib.parse import parse_qsl

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.http import QueryDict
from granian.rsgi import ProtocolClosed

from p2.core.events import STREAM_BLOB_POST_SAVE, make_event, publish_event
from p2.core.models import Volume
from p2.lib.config import CONFIG
from p2.s3.auth.aws_v4 import AWSV4Authentication
from p2.s3.cache import aget_cached_volume, aset_cached_volume, invalidate_metadata
from p2.s3.datapath import ByteBudget, RequestTimings, await_commit
from p2.s3.engine import get_engine
from p2.s3.errors import AWSError, AWSIncompleteBody
from p2.s3.fastpath import (
    put_user_metadata, require_volume_permission, update_volume_stats_for_put,
    user_metadata_headers, validate_fast_put_integrity,
)
from p2.s3.put_body import CHECKSUM_HEADERS, decode_chunked_put, supports_chunked_put
from p2.s3.read_cache import ReadCache, VolumePaths, load_read
from p2.s3.volume_pool import BlockCoord, VolumePool
from p2.s3.volume_reader import stream_blocks
from p2.s3.volume_writer import write_block

LOGGER = logging.getLogger(__name__)
_BG_TASKS = set()
_AUTH_QUERY_KEYS = frozenset({
    "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
    "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token",
    "X-Amz-Content-Sha256",
})


class S3Request:
    __slots__ = ("method", "path", "META", "hdrs", "body", "_query", "_get")

    def __init__(self, scope, headers):
        self.method = scope.method
        self.path = scope.path
        self.hdrs = headers
        self.body = b""
        self._query = scope.query_string
        self._get = None
        self.META = {
            "REQUEST_METHOD": self.method,
            "PATH_INFO": self.path,
            "QUERY_STRING": self._query,
        }
        for name in ("authorization", "x-amz-date", "x-amz-content-sha256"):
            if name in headers:
                self.META["HTTP_" + name.upper().replace("-", "_")] = headers[name]

    @property
    def GET(self):
        if self._get is None:
            self._get = QueryDict(self._query)
        return self._get


def _spawn_bg(coroutine):
    task = asyncio.create_task(coroutine)
    _BG_TASKS.add(task)
    task.add_done_callback(_background_done)


def _background_done(task):
    _BG_TASKS.discard(task)
    if not task.cancelled() and task.exception() is not None:
        LOGGER.error("S3 event publication failed: %s", type(task.exception()).__name__)


def _apply_cors(headers, volume, origin, method):
    if not origin or volume is None:
        return
    from p2.s3.cors import find_matching_rule, get_cors_rules
    rule = find_matching_rule(get_cors_rules(volume), origin, method)
    if not rule:
        return
    headers.extend([
        ("access-control-allow-origin", origin),
        ("access-control-allow-methods", ", ".join(rule.get("AllowedMethods", []))),
        ("vary", "Origin"),
    ])
    for field, header in (
        ("AllowedHeaders", "access-control-allow-headers"),
        ("ExposeHeaders", "access-control-expose-headers"),
    ):
        if rule.get(field):
            headers.append((header, ", ".join(rule[field])))
    if rule.get("MaxAgeSeconds") is not None:
        headers.append(("access-control-max-age", str(rule["MaxAgeSeconds"])))


def _error(protocol, status, code, volume=None, origin="", method="GET"):
    body = f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{code}</Code></Error>'.encode()
    headers = [("content-type", "application/xml"), ("content-length", str(len(body)))]
    _apply_cors(headers, volume, origin, method)
    if method == "HEAD":
        protocol.response_empty(status, headers)
    else:
        protocol.response_bytes(status, headers, body)


def _needs_fallback(scope, headers):
    if scope.method not in ("GET", "HEAD", "PUT", "DELETE"):
        return True
    if any(name not in _AUTH_QUERY_KEYS for name, _ in parse_qsl(scope.query_string, keep_blank_values=True)):
        return True
    if any(name == "range" or name.startswith("if-") for name in headers):
        return True
    if scope.method == "PUT":
        chunked = supports_chunked_put(headers)
        for name in headers:
            if name.startswith((
                "x-amz-copy-", "x-amz-server-side-encryption",
                "x-amz-grant-", "x-amz-object-lock-",
            )) or name in (
                "x-amz-acl", "x-amz-tagging", "x-amz-storage-class",
            ):
                return True
            if name in ("x-amz-trailer", "x-amz-decoded-content-length") and not chunked:
                return True
            if name == "x-amz-checksum-type" and headers[name] == "FULL_OBJECT":
                continue
            if name.startswith("x-amz-checksum-") and name not in CHECKSUM_HEADERS:
                return True
        if not chunked and (
            headers.get("content-encoding") or headers.get("x-amz-content-sha256", "").startswith("STREAMING-")
        ):
            return True
    return False


def _read_metadata(volume, key):
    engine = get_engine(volume)
    raw = engine.get(key)
    return engine, json.loads(raw) if raw is not None else None


def _read_headers(metadata, key):
    from p2.s3.views.objects import (
        _ACTIVE_CONTENT_TYPES, _fmt_http_date, _meta_etag, _meta_mime, _meta_mtime, _meta_size,
    )
    headers = [
        ("content-type", _meta_mime(metadata, key)), ("content-length", str(_meta_size(metadata))),
        ("accept-ranges", "bytes"), ("x-p2-datapath", "rsgi"),
        ("x-content-type-options", "nosniff"),
    ]
    if headers[0][1].split(";")[0].strip().lower() in _ACTIVE_CONTENT_TYPES:
        headers.append(("content-security-policy", "sandbox"))
    etag = _meta_etag(metadata)
    if etag:
        headers.append(("etag", f'"{etag}"'))
    modified = _fmt_http_date(_meta_mtime(metadata))
    if modified:
        headers.append(("last-modified", modified))
    headers.extend(user_metadata_headers(metadata))
    return tuple(headers)


def _prepare_put(volume, key, headers, body, timings, streaming_auth=None):
    from time import perf_counter
    started = perf_counter() if timings is not None else 0
    if supports_chunked_put(headers):
        body, headers = decode_chunked_put(body, headers, streaming_auth)
        if timings is not None:
            now = perf_counter()
            timings["body_decode"] = (now - started) * 1000
            started = now
    user_metadata = put_user_metadata(headers)
    md5 = hashlib.md5(body).hexdigest()
    sha256 = hashlib.sha256(body).hexdigest()
    validate_fast_put_integrity(headers, body, md5, sha256)
    if timings is not None:
        timings["hash_integrity"] = (perf_counter() - started) * 1000
    engine, existing = _read_metadata(volume, key)
    handle, offset = VolumePool.get().allocate_block(len(body)) if body else (None, 0)
    blocks = [BlockCoord(handle.uuid_hex, offset, len(body)).to_dict()] if handle else []
    now = dt.datetime.now(dt.UTC).isoformat()
    metadata = {
        "size": len(body), "mime": headers.get("content-type", "application/octet-stream"),
        "blocks": blocks, "etag": md5, "sha256": sha256, "mtime": now,
        "ctime": (existing or {}).get("ctime", now), "is_folder": False,
    }
    if user_metadata:
        metadata["user_metadata"] = user_metadata
    return engine, handle, offset, metadata, existing, body


async def _put(volume, key, headers, body, timings, streaming_auth=None):
    values = timings.values if timings is not None else None
    engine, handle, offset, metadata, existing, body = await asyncio.to_thread(
        _prepare_put, volume, key, headers, body, values, streaming_auth,
    )
    if timings:
        timings.mark("prepare")
    if handle is not None:
        await write_block(handle, offset, body, engine, key, metadata, timings=values)
    else:
        await asyncio.to_thread(engine.put, key, json.dumps(metadata))
    if timings:
        timings.mark("write_metadata")
    invalidate_metadata(volume.uuid.hex, key)
    counted = existing is not None and not existing.get("is_folder", existing.get("blob.p2.io/is_folder", False))
    old_size = int((existing or {}).get("size", (existing or {}).get("blob.p2.io/size/bytes", 0)) or 0)
    update_volume_stats_for_put(volume, counted, old_size, len(body))
    if settings.S3_ASYNC_EVENT_PUBLISH:
        event = make_event(
            blob_uuid=os.urandom(8).hex(), volume_uuid=volume.uuid.hex, event_type="blob_post_save",
        )
        event.update({"blob_path": key, "mime": metadata["mime"], "blocks": metadata["blocks"]})
        _spawn_bg(publish_event(STREAM_BLOB_POST_SAVE, event))
    return metadata


def S3ProxyRSGIApp(django_fallback):
    base_domain = CONFIG.y("s3.base_domain", "s3.example.com")
    max_body = min(settings.S3_RSGI_MAX_BODY_BYTES, settings.VOLUME_SIZE_BYTES)
    budget = ByteBudget(settings.S3_RSGI_INFLIGHT_BYTES)
    paths = VolumePaths(settings.STORAGE_ROOT)
    small_limit = max(0, settings.S3_RSGI_SMALL_READ_BYTES)
    reads = ReadCache(settings.S3_RSGI_READ_CACHE_ENTRIES, settings.S3_RSGI_READ_CACHE_BYTES)
    if max_body <= 0 or max_body > budget.capacity:
        raise ValueError("RSGI max body must be positive and no larger than its byte budget")

    async def app(scope, protocol):
        if scope.proto != "http":
            return await django_fallback(scope, protocol)
        if scope.path.startswith(("/_/", "/api/", "/.well-known/")) or scope.path == "/favicon.ico":
            return await django_fallback(scope, protocol)

        # RSGI headers are already lower-case and Rust-backed.
        headers = scope.headers
        if "host" not in headers and scope.authority:
            headers = dict(headers.items())
            headers["host"] = scope.authority
        host = headers.get("host", "").split(":", 1)[0]
        is_s3 = (
            headers.get("authorization", "").startswith("AWS")
            or "x-amz-date" in headers or "X-Amz-Signature=" in scope.query_string
            or host.endswith("." + base_domain)
        )
        if not is_s3 or _needs_fallback(scope, headers):
            return await django_fallback(scope, protocol)
        if host.endswith("." + base_domain):
            bucket, key = host[:-(len(base_domain) + 1)], scope.path.lstrip("/")
        else:
            parts = scope.path.lstrip("/").split("/", 1)
            bucket, key = parts[0], parts[1] if len(parts) == 2 else ""
        if not bucket or not key:
            return await django_fallback(scope, protocol)

        content_length = 0
        if scope.method == "PUT":
            try:
                content_length = int(headers.get("content-length", "-1"))
            except ValueError:
                return _error(protocol, 400, "InvalidRequest", method="PUT")
            if content_length == -1 or content_length > max_body:
                return await django_fallback(scope, protocol)
            if content_length < 0:
                return _error(protocol, 400, "InvalidRequest", method="PUT")
            # Framed PUTs retain encoded and decoded buffers through commit.
            admission_bytes = content_length * (2 if supports_chunked_put(headers) else 1)
            if admission_bytes > budget.capacity:
                return await django_fallback(scope, protocol)

        timings = RequestTimings() if settings.S3_BENCHMARK_TIMINGS else None
        origin = headers.get("origin", "")
        volume = None
        try:
            request = S3Request(scope, headers)
            if not AWSV4Authentication.can_handle(request):
                return await django_fallback(scope, protocol)
            authenticator = AWSV4Authentication(request)
            user = await authenticator.validate()
            if user is None:
                return _error(protocol, 403, "AccessDenied", method=scope.method)
            if timings:
                timings.mark("auth")
            volume = await aget_cached_volume(bucket)
            if volume is None:
                volume = await Volume.objects.aget(name=bucket)
                await aset_cached_volume(bucket, volume)
            if timings:
                timings.mark("volume")
            if scope.method in ("PUT", "DELETE") and (volume.tags or {}).get("versioning") == "true":
                return await django_fallback(scope, protocol)
            permission = {"GET": "read", "HEAD": "read", "PUT": "write", "DELETE": "delete"}[scope.method]
            await require_volume_permission(user, volume, permission, bucket, key)
            if timings:
                timings.mark("permission")

            if scope.method in ("GET", "HEAD"):
                cache_key = (volume.uuid.hex, key)
                entry = reads.get(cache_key, scope.method == "GET", small_limit)
                cache_hit = entry is not None
                if entry is None:
                    entry = await asyncio.to_thread(
                        load_read, volume, key, paths, small_limit, scope.method == "GET",
                    )
                    if entry is not None:
                        reads.put(cache_key, entry)
                if timings:
                    timings.mark("metadata_read")
                if entry is None:
                    return _error(protocol, 404, "NoSuchKey", volume, origin, scope.method)
                metadata = entry.metadata
                if "blocks" not in metadata or metadata.get("sse_algorithm") or metadata.get("compressed"):
                    return await django_fallback(scope, protocol)
                from p2.s3.views.objects import _meta_size
                size = _meta_size(metadata)
                if entry.headers is None:
                    entry.headers = _read_headers(metadata, key)
                # Only snapshot-derived headers are cached. CORS and timings
                # must be rebuilt for this request, after authorization.
                response_headers = list(entry.headers)
                _apply_cors(response_headers, volume, origin, scope.method)
                if timings:
                    response_headers.append(timings.header())
                    response_headers.append(("x-p2-read-cache", "hit" if cache_hit else "miss"))
                if scope.method == "HEAD" or size == 0:
                    return protocol.response_empty(200, response_headers)
                if entry.body is not None:
                    return protocol.response_bytes(200, response_headers, entry.body)
                blocks = [BlockCoord.from_dict(item) for item in metadata["blocks"]]
                if sum(block.length for block in blocks) != size:
                    return _error(protocol, 500, "InternalError", volume, origin, scope.method)
                if len(blocks) == 1:
                    block = blocks[0]
                    return protocol.response_file_range(
                        200, response_headers, paths.get_volume_path(block.vol_uuid),
                        block.offset, block.offset + block.length,
                    )
                transport = protocol.response_stream(200, response_headers)
                async for chunk in stream_blocks(paths, blocks):
                    await transport.send_bytes(chunk)
                return

            if scope.method == "PUT":
                async with budget.reserve(admission_bytes):
                    if timings:
                        timings.mark("admission")
                    body = await protocol()
                    if len(body) != content_length:
                        raise AWSIncompleteBody
                    if timings:
                        timings.mark("body_receive")
                    metadata = await await_commit(_put(
                        volume, key, headers, body, timings, getattr(authenticator, "streaming_auth", None),
                    ))
                response_headers = [
                    ("etag", f'"{metadata["etag"]}"'), ("content-length", "0"),
                    ("x-p2-put-fastpath", "1"), ("x-p2-datapath", "rsgi"),
                ]
                _apply_cors(response_headers, volume, origin, "PUT")
                if timings:
                    response_headers.append(timings.header())
                return protocol.response_empty(200, response_headers)

            engine = await asyncio.to_thread(get_engine, volume)
            await asyncio.to_thread(engine.delete, key)
            invalidate_metadata(volume.uuid.hex, key)
            response_headers = [("content-length", "0"), ("x-p2-datapath", "rsgi")]
            _apply_cors(response_headers, volume, origin, "DELETE")
            if timings:
                timings.mark("metadata_delete")
                response_headers.append(timings.header())
            protocol.response_empty(204, response_headers)
        except ObjectDoesNotExist:
            _error(protocol, 404, "NoSuchBucket", method=scope.method)
        except AWSError as exc:
            _error(protocol, exc.status, exc.code, volume, origin, scope.method)
        except ProtocolClosed:
            return

    return app

"""Raw ASGI Application Proxy for S3 Datapath Performance

Intercepts S3 GET/PUT single-object requests before Django middleware.
All header parsing is done once per request and shared across detection,
routing, auth, and the handler itself.
"""
import asyncio
import datetime as _dt
import json
import logging
import os
import time
import urllib.parse
import uuid
from email.utils import format_datetime

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.http import QueryDict

from p2.core.models import Volume
from p2.s3.auth.aws_v4 import AWSV4Authentication
from p2.s3.cache import (
    get_cached_metadata, set_cached_metadata, invalidate_metadata,
    get_cached_volume, set_cached_volume,
)
from p2.s3.engine import get_engine
from p2.s3.errors import AWSError
from p2.s3.fastpath import (
    existing_object_state,
    hash_put_body,
    put_user_metadata,
    require_volume_permission,
    update_volume_stats_for_put,
    user_metadata_headers,
    validate_fast_put_integrity,
)
from p2.s3.volume_pool import BlockCoord, VolumePool
from p2.s3.volume_writer import write_block
from p2.s3.volume_reader import read_object, stream_blocks
from p2.core.events import STREAM_BLOB_POST_SAVE, make_event, publish_event


LOGGER = logging.getLogger(__name__)

# Strong references to fire-and-forget background tasks. asyncio only holds a
# weak reference to tasks, so without this they can be GC'd before completion.
_BG_TASKS: set = set()


def _spawn_bg(coro) -> None:
    task = asyncio.create_task(coro)
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)


ATTR_BLOB_MIME = "blob.p2.io/mime"
ATTR_BLOB_SIZE_BYTES = "blob.p2.io/size/bytes"
ATTR_BLOB_IS_FOLDER = "blob.p2.io/is_folder"
ATTR_BLOB_STAT_MTIME = "blob.p2.io/stat/mtime"
ATTR_BLOB_STAT_CTIME = "blob.p2.io/stat/ctime"

# Cache the S3 base domain at module level — never changes at runtime.
_S3_BASE_DOMAIN: str | None = None

from django.utils.dateparse import parse_datetime
import datetime as _dt

def _parse_stored_timestamp(ts_str: str):
    """Parse a stored mtime/ctime value, handling both ISO 8601 (current)
    and legacy Unix epoch floats from objects written before the timestamp fix."""
    dt = parse_datetime(ts_str)
    if dt is None:
        try:
            dt = _dt.datetime.fromtimestamp(float(ts_str), tz=_dt.UTC)
        except (ValueError, OverflowError):
            return None
    return dt

def _get_s3_base_domain() -> str:
    global _S3_BASE_DOMAIN
    if _S3_BASE_DOMAIN is None:
        from p2.lib.config import CONFIG
        _S3_BASE_DOMAIN = CONFIG.y('s3.base_domain', 's3.example.com')
    return _S3_BASE_DOMAIN


# Pre-compute the empty SHA256 hash for GET/HEAD/OPTIONS auth verification.
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Reusable response templates — avoids dict construction per request.
_PUT_RESPONSE_START_TYPE = 'http.response.start'
_PUT_RESPONSE_BODY_TYPE = 'http.response.body'
_EMPTY_BODY = b''


class _S3Request:
    """Minimal request shim for the SigV4 authenticator.

    ``AWSV4Authentication`` only needs ``method``, ``META``, ``hdrs``, ``body``
    and ``GET``, so the fast path hands it this instead of building a real
    Django ``HttpRequest``.

    This used to be a ``class`` statement *inside* the request handler, which
    meant every single request executed a class definition — building a fresh
    namespace, type object and mappingproxy — just to hang five attributes off
    it. It showed up at ~3% of per-request CPU work in profiles. Instantiating a
    ``__slots__`` class is far cheaper.

    ``GET`` is built on first access. ``can_handle`` only looks at it when the
    request has no ``Authorization`` header, so header-authenticated clients
    (the boto3/warp default) never pay for parsing the query string; only
    presigned-URL requests do.
    """

    __slots__ = ('method', 'path', 'META', 'hdrs', 'body', '_qs', '_get')

    def __init__(self, method, path, meta, hdrs, qs, body=_EMPTY_BODY):
        self.method = method
        self.path = path
        self.META = meta
        self.hdrs = hdrs
        self.body = body
        self._qs = qs
        self._get = None

    @property
    def GET(self):
        get = self._get
        if get is None:
            get = self._get = QueryDict(self._qs)
        return get


def _apply_asgi_cors(resp_headers: list, volume, origin: str, method: str) -> None:
    if not origin or not volume:
        return
    try:
        from p2.s3.cors import get_cors_rules, find_matching_rule
        rules = get_cors_rules(volume)
        rule = find_matching_rule(rules, origin, method)
        if rule:
            resp_headers.append((b'access-control-allow-origin', origin.encode('utf-8')))
            resp_headers.append((b'access-control-allow-methods', ', '.join(rule.get('AllowedMethods', [])).encode('utf-8')))
            allowed_headers = rule.get('AllowedHeaders', [])
            if allowed_headers:
                resp_headers.append((b'access-control-allow-headers', ', '.join(allowed_headers).encode('utf-8')))
            expose_headers = rule.get('ExposeHeaders', [])
            if expose_headers:
                resp_headers.append((b'access-control-expose-headers', ', '.join(expose_headers).encode('utf-8')))
            max_age = rule.get('MaxAgeSeconds')
            if max_age:
                resp_headers.append((b'access-control-max-age', str(max_age).encode('utf-8')))
            resp_headers.append((b'vary', b'Origin'))
    except Exception as e:
        LOGGER.error("S3 ASGI CORS error: %s", e)


async def _s3_error(send, status, code, volume=None, origin=''):
    xml = f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{code}</Code></Error>'.encode('utf-8')
    resp_headers = [
        (b'content-type', b'application/xml'),
        (b'content-length', str(len(xml)).encode('ascii'))
    ]
    if volume and origin:
        _apply_asgi_cors(resp_headers, volume, origin, 'GET')
    await send({
        'type': _PUT_RESPONSE_START_TYPE,
        'status': status,
        'headers': resp_headers
    })
    await send({'type': _PUT_RESPONSE_BODY_TYPE, 'body': xml})


def S3ProxyASGIApp(django_app):
    """ASGI wrapper: intercepts S3 GET/PUT, falls back to Django for everything else."""

    # Cache S3_ASYNC_EVENT_PUBLISH at startup.
    async_events = getattr(settings, 'S3_ASYNC_EVENT_PUBLISH', False)
    benchmark_timings = getattr(settings, 'S3_BENCHMARK_TIMINGS', False)
    s3_base = _get_s3_base_domain()

    async def app(scope, receive, send):
        if scope['type'] != 'http':
            return await django_app(scope, receive, send)

        path = scope['path']
        method = scope['method']

        # Fast reject non-S3 paths without parsing headers.
        if path.startswith('/_/') or path.startswith('/api/') or path == '/favicon.ico' or path.startswith('/.well-known/'):
            return await django_app(scope, receive, send)

        # ── Parse headers ONCE ────────────────────────────────────────────
        # Build both the lowercase dict (for routing/PUT) and the META dict
        # (for auth) in a single pass over the raw ASGI headers.
        hdrs = {}          # lowercase str -> str
        for raw_name, raw_value in scope.get('headers', []):
            k = raw_name.decode('ascii').lower()
            v = raw_value.decode('latin1')
            hdrs[k] = v
            
        qs_bytes = scope.get('query_string', b'')
        qs = qs_bytes.decode('ascii')

        # The Django-style META dict is built further down, just before auth.
        # Everything between here and there can still hand the request off to
        # Django, and none of it reads META — so building it now would waste an
        # unquote() and a dict on every SPA asset, API call and favicon request.

        # ── S3 detection ──────────────────────────────────────────────────
        is_s3 = (
            'x-amz-date' in hdrs
            or hdrs.get('authorization', '').startswith('AWS')
            or 'X-Amz-Signature' in qs
            or 'X-P2-Signature' in qs
        )
        if not is_s3:
            host = hdrs.get('host', '').split(':')[0]
            if host.endswith('.' + s3_base):
                is_s3 = True

        if not is_s3:
            return await django_app(scope, receive, send)

        # ── Routing ───────────────────────────────────────────────────────
        if b'uploadId' in qs_bytes or b'tagging' in qs_bytes or b'acl' in qs_bytes:
            return await django_app(scope, receive, send)

        # Extract bucket + key
        host = hdrs.get('host', '').split(':')[0]
        if host.endswith('.' + s3_base):
            bucket = host[:-(len(s3_base) + 1)]
            key = urllib.parse.unquote(path.lstrip('/'))
        else:
            parts = path.lstrip('/').split('/', 1)
            if not parts or not parts[0]:
                return await django_app(scope, receive, send)
            bucket = parts[0]
            key = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ''

        if not bucket or not key:
            return await django_app(scope, receive, send)

        if method not in ('GET', 'PUT', 'DELETE'):
            return await django_app(scope, receive, send)

        timings = {} if benchmark_timings and method == 'PUT' else None
        stage_started = time.perf_counter() if timings is not None else 0.0
        put_started = stage_started

        # ── Auth ──────────────────────────────────────────────────────────
        # Django-style META dict, built only now that the request is known to be
        # S3 traffic we handle. Only the keys the SigV4 authenticator reads are
        # copied; a full WSGI-style META would mean touching every header.
        meta = {
            'REQUEST_METHOD': method,
            'PATH_INFO': urllib.parse.unquote(path),
            'QUERY_STRING': qs,
        }
        if 'content-type' in hdrs:
            meta['CONTENT_TYPE'] = hdrs['content-type']
        if 'content-length' in hdrs:
            meta['CONTENT_LENGTH'] = hdrs['content-length']
        if 'authorization' in hdrs:
            meta['HTTP_AUTHORIZATION'] = hdrs['authorization']
        if 'x-amz-date' in hdrs:
            meta['HTTP_X_AMZ_DATE'] = hdrs['x-amz-date']
        if 'x-amz-content-sha256' in hdrs:
            meta['HTTP_X_AMZ_CONTENT_SHA256'] = hdrs['x-amz-content-sha256']

        s3_request = _S3Request(method, path, meta, hdrs, qs)

        try:
            if not AWSV4Authentication.can_handle(s3_request):
                return await django_app(scope, receive, send)
            user = await AWSV4Authentication(s3_request).validate()
            if not user:
                return await _s3_error(send, 403, 'AccessDenied')
        except AWSError as e:
            return await _s3_error(send, e.status, e.code)
        except Exception as e:
            LOGGER.error("S3 proxy auth error: %s", e)
            return await _s3_error(send, 500, 'InternalError')

        # ── Volume lookup ─────────────────────────────────────────────────
        if timings is not None:
            timings['auth'] = (time.perf_counter() - stage_started) * 1000
            stage_started = time.perf_counter()
        try:
            volume = get_cached_volume(bucket)
            if not volume:
                volume = await Volume.objects.aget(name=bucket)
                set_cached_volume(bucket, volume)
        except ObjectDoesNotExist:
            return await _s3_error(send, 404, 'NoSuchBucket')

        vol_hex = volume.uuid.hex
        origin = hdrs.get('origin', '')
        if timings is not None:
            timings['volume'] = (time.perf_counter() - stage_started) * 1000
            stage_started = time.perf_counter()


        # ── GET ───────────────────────────────────────────────────────────
        if method == 'GET':
            try:
                await require_volume_permission(user, volume, 'read', bucket, key)
            except AWSError as e:
                return await _s3_error(send, e.status, e.code, volume=volume, origin=origin)

            attributes = get_cached_metadata(vol_hex, key)
            if attributes is None:
                engine = get_engine(volume)
                # LMDB get is a lock-free read over an mmap (~1-5us). Dispatching
                # it to a thread costs more (~30-100us) than the read itself, so
                # run it inline in the event loop.
                raw = engine.get(key)
                if not raw:
                    return await _s3_error(send, 404, 'NoSuchKey', volume=volume, origin=origin)
                attributes = json.loads(raw)
                set_cached_metadata(vol_hex, key, attributes)

            blocks_raw = attributes.get('blocks', [])
            if not blocks_raw:
                # Legacy object with internal_path — fall back to Django
                return await django_app(scope, receive, send)

            ct = attributes.get('mime', attributes.get('blob.p2.io/mime', 'application/octet-stream'))
            size = int(attributes.get('size', attributes.get('blob.p2.io/size/bytes', 0)) or 0)
            etag = attributes.get('etag', attributes.get('blob.p2.io/hash/md5', ''))

            lm = b''
            lm_str = attributes.get('mtime', attributes.get('blob.p2.io/stat/mtime', ''))
            if lm_str:
                dt = _parse_stored_timestamp(lm_str)
                if dt:
                    lm = format_datetime(dt, usegmt=True).encode('ascii')

            blocks = [BlockCoord.from_dict(b) for b in blocks_raw]
            pool = VolumePool.get()

            resp_h = [
                (b'content-type', ct.encode('utf-8')),
                (b'content-length', str(size).encode('ascii')),
                (b'accept-ranges', b'bytes'),
            ]
            if etag:
                resp_h.append((b'etag', f'"{etag}"'.encode('utf-8')))
            if lm:
                resp_h.append((b'last-modified', lm))
            _apply_asgi_cors(resp_h, volume, origin, method)
            resp_h.extend(
                (name.encode("ascii"), value.encode("latin1"))
                for name, value in user_metadata_headers(attributes)
            )

            await send({'type': _PUT_RESPONSE_START_TYPE, 'status': 200, 'headers': resp_h})
            if size <= 4 * 1024 * 1024:
                data = await read_object(pool, blocks)
                await send({'type': _PUT_RESPONSE_BODY_TYPE, 'body': data, 'more_body': False})
            else:
                async for chunk in stream_blocks(pool, blocks):
                    await send({'type': _PUT_RESPONSE_BODY_TYPE, 'body': chunk, 'more_body': True})
                await send({'type': _PUT_RESPONSE_BODY_TYPE, 'body': _EMPTY_BODY, 'more_body': False})
            return

        # ── PUT ───────────────────────────────────────────────────────────
        if method == 'PUT':
            is_versioned = (volume.tags or {}).get('versioning') == 'true'
            if is_versioned:
                return await django_app(scope, receive, send)

            try:
                await require_volume_permission(user, volume, 'write', bucket, key)
            except AWSError as e:
                return await _s3_error(send, e.status, e.code, volume=volume, origin=origin)
            if timings is not None:
                timings['permission'] = (time.perf_counter() - stage_started) * 1000
                stage_started = time.perf_counter()

            client_ct = hdrs.get('content-type', 'application/octet-stream')
            try:
                content_length = int(hdrs.get('content-length', '-1'))
            except ValueError:
                return await _s3_error(send, 400, 'InvalidRequest', volume=volume, origin=origin)
            is_aws_chunked = (
                'aws-chunked' in hdrs.get('content-encoding', '')
                or 'x-amz-decoded-content-length' in hdrs
            )

            if content_length > 67108864 or content_length == -1:
                return await django_app(scope, receive, send)

            pool = VolumePool.get()
            chunks_body = []

            try:
                while True:
                    message = await receive()
                    mtype = message['type']
                    if mtype == 'http.request':
                        chunk = message.get('body', _EMPTY_BODY)
                        if chunk:
                            if is_aws_chunked:
                                from p2.s3.utils import decode_aws_chunked
                                chunk = decode_aws_chunked(chunk)
                            chunks_body.append(chunk)
                        if not message.get('more_body', False):
                            break
                    elif mtype == 'http.disconnect':
                        return
            except Exception:
                return await _s3_error(send, 500, 'InternalError')

            body = b''.join(chunks_body)
            blob_size = len(body)
            md5_hash_bytes, final_sha256 = await hash_put_body(body)
            final_md5 = md5_hash_bytes.hex()
            if timings is not None:
                timings['body'] = (time.perf_counter() - stage_started) * 1000
                stage_started = time.perf_counter()

            try:
                validate_fast_put_integrity(hdrs, body, final_md5, final_sha256, blob_size=blob_size)
                user_metadata = put_user_metadata(hdrs)
            except AWSError as e:
                return await _s3_error(send, e.status, e.code, volume=volume, origin=origin)

            now_iso = _dt.datetime.now(_dt.UTC).isoformat()
            engine = get_engine(volume)

            # Skip LMDB read for non-versioned buckets — no need to check
            # if the object already exists (saves 1 LMDB transaction per PUT).
            if is_versioned:
                existing_json, existing_size, existing_counted = await existing_object_state(engine, key)
            else:
                existing_json, existing_size, existing_counted = None, 0, False

            if blob_size > 0:
                handle, offset = pool.allocate_block(blob_size)
                block = BlockCoord(vol_uuid=handle.uuid_hex, offset=offset, length=blob_size)
                blocks = [block]
            else:
                handle = None
                offset = 0
                blocks = []
            if timings is not None:
                timings['prepare_allocate'] = (time.perf_counter() - stage_started) * 1000
                stage_started = time.perf_counter()

            blob_uuid = uuid.uuid4().hex
            internal_path = f"/internal-storage/volumes/{vol_hex}/{blob_uuid[0:2]}/{blob_uuid[2:4]}/{blob_uuid}"

            meta_payload = {
                'size': blob_size,
                'mime': client_ct,
                'blocks': [b.to_dict() for b in blocks],
                'etag': final_md5,
                'sha256': final_sha256,
                'mtime': now_iso,
                'ctime': now_iso,
                'is_folder': False,
                'internal_path': internal_path,
            }
            if user_metadata:
                meta_payload["user_metadata"] = user_metadata

            if handle is not None:
                await write_block(handle, offset, body, engine, key, meta_payload, md5_hash_bytes)
            else:
                await asyncio.to_thread(engine.put, key, json.dumps(meta_payload))
            if timings is not None:
                timings['write_metadata'] = (time.perf_counter() - stage_started) * 1000
                stage_started = time.perf_counter()

            invalidate_metadata(vol_hex, key)
            if existing_json:
                from p2.s3.cache import invalidate_volume_global
                invalidate_volume_global(bucket)
            # Stats are approximate and are coalesced in-process before one
            # Redis pipeline per short batch. Do not create one task per PUT.
            update_volume_stats_for_put(volume, existing_counted, existing_size, blob_size)

            if async_events:
                event = make_event(blob_uuid=os.urandom(8).hex(), volume_uuid=vol_hex, event_type='blob_post_save')
                event['blob_path'] = key
                event['mime'] = client_ct
                event['blocks'] = [b.to_dict() for b in blocks]
                _spawn_bg(publish_event(STREAM_BLOB_POST_SAVE, event))

            resp_h = [
                (b'etag', f'"{final_md5}"'.encode('utf-8')),
                (b'content-length', b'0'),
                (b'x-p2-put-fastpath', b'1'),
            ]
            if timings is not None:
                timings['post'] = (time.perf_counter() - stage_started) * 1000
                timings['total'] = (time.perf_counter() - put_started) * 1000
                resp_h.append((
                    b'server-timing',
                    ', '.join(
                        f"{name};dur={duration:.3f}" for name, duration in timings.items()
                    ).encode('ascii'),
                ))
            _apply_asgi_cors(resp_h, volume, origin, method)
            await send({'type': _PUT_RESPONSE_START_TYPE, 'status': 200, 'headers': resp_h})
            await send({'type': _PUT_RESPONSE_BODY_TYPE, 'body': _EMPTY_BODY})
            return

        # ── DELETE ─────────────────────────────────────────────────────────
        if method == 'DELETE':
            try:
                await require_volume_permission(user, volume, 'delete', bucket, key)
            except AWSError as e:
                return await _s3_error(send, e.status, e.code, volume=volume, origin=origin)

            engine = get_engine(volume)
            await asyncio.to_thread(engine.delete, key)
            invalidate_metadata(vol_hex, key)

            resp_h = [
                (b'content-length', b'0'),
            ]
            _apply_asgi_cors(resp_h, volume, origin, method)
            await send({'type': _PUT_RESPONSE_START_TYPE, 'status': 204, 'headers': resp_h})
            await send({'type': _PUT_RESPONSE_BODY_TYPE, 'body': _EMPTY_BODY})
            return

    return app

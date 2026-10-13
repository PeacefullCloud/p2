"""p2 S3 Object views — Volume Pool architecture.

Metadata schema stored in LMDB per key:
{
  "size": <int>,
  "mime": <str>,
  "blocks": [{"vol_uuid": "...", "offset": <int>, "length": <int>}, ...],
  "etag": "<md5hex>",
  "sha256": "<sha256hex>",
  "mtime": "<iso8601>",
  "ctime": "<iso8601>",
  "version_id": "<str>",          # optional
  "is_folder": false,
  "sse_algorithm": "AES256",      # optional
  "tags": {},                     # optional user tags
  "acl": "private"                # optional
}

DELETE is logical: removes the LMDB key only — physical bytes stay in the
volume until the compaction worker reclaims them.
"""
from __future__ import annotations

import asyncio
import binascii
import json
import logging
import mimetypes
import os
import uuid
from email.utils import format_datetime
from typing import Any
from xml.etree import ElementTree

from django.conf import settings
from django.http import StreamingHttpResponse
from django.http.response import HttpResponse
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now

from p2.core.constants import ATTR_BLOB_IS_FOLDER, ATTR_BLOB_MIME, ATTR_BLOB_SIZE_BYTES, ATTR_BLOB_STAT_MTIME, ATTR_BLOB_STAT_CTIME
from p2.s3.constants import TAG_S3_ACL, TAG_S3_USER_TAG_PREFIX, XML_NAMESPACE
from p2.s3.cors import apply_cors_headers, cors_preflight_response, find_matching_rule, get_cors_rules
from p2.s3.errors import AWSAccessDenied, AWSBadDigest, AWSNoSuchKey
from p2.s3.http import XMLResponse
from p2.s3.presign import validate_presigned_token
from p2.s3.views.common import S3View
from p2.s3.views.multipart import MultipartUploadView
from p2.s3.utils import decode_aws_chunked, iter_request_body
from p2.s3.cache import (
    get_cached_metadata, set_cached_metadata, invalidate_metadata, invalidate_volume_global,
)
from p2.s3.fastpath import hash_put_body
from p2.s3.volume_pool import BlockCoord, VolumePool
from p2.s3.volume_reader import (
    read_object, read_range, slice_blocks, stream_blocks, stream_sliced_blocks, total_size,
)
from p2.s3.volume_writer import write_block

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_conditional_headers(request, blob) -> HttpResponse | None:
    """Check If-Match/If-None-Match/If-Modified-Since/If-Unmodified-Since.
    Returns an error HttpResponse if condition fails, None if OK."""
    if blob is None:
        if request.META.get('HTTP_IF_NONE_MATCH') == '*':
            return None
        if request.META.get('HTTP_IF_MATCH'):
            return HttpResponse(status=412)
        return None

    if hasattr(blob, 'attributes'):
        attrs = blob.attributes
    elif isinstance(blob, dict):
        attrs = blob
    else:
        attrs = {}

    etag = attrs.get('blob.p2.io/hash/md5', '') or attrs.get('etag', '')
    if_match = request.META.get('HTTP_IF_MATCH')
    if if_match:
        tags = [t.strip().strip('"') for t in if_match.split(',')]
        if etag.strip('"') not in tags and '*' not in tags:
            return HttpResponse(status=412)
    if_none_match = request.META.get('HTTP_IF_NONE_MATCH')
    if if_none_match:
        if if_none_match == '*':
            return HttpResponse(status=412)
        tags = [t.strip().strip('"') for t in if_none_match.split(',')]
        if etag.strip('"') in tags:
            return HttpResponse(status=412)
    if_unmod = request.META.get('HTTP_IF_UNMODIFIED_SINCE')
    if if_unmod:
        from email.utils import parsedate_to_datetime
        try:
            threshold = parsedate_to_datetime(if_unmod)
            mtime = attrs.get(ATTR_BLOB_STAT_MTIME, '') or attrs.get('mtime', '')
            if mtime:
                from django.utils.dateparse import parse_datetime
                blob_dt = parse_datetime(str(mtime))
                if blob_dt and blob_dt > threshold:
                    return HttpResponse(status=412)
        except (ValueError, TypeError):
            pass
    return None


def _fmt_http_date(mtime_str: str) -> str | None:
    if not mtime_str:
        return None
    dt = parse_datetime(mtime_str)
    if dt is None:
        import datetime as _dt
        try:
            dt = _dt.datetime.fromtimestamp(float(mtime_str), tz=_dt.UTC)
        except (ValueError, OverflowError):
            return None
    return format_datetime(dt, usegmt=True) if dt else None


def _blocks_from_meta(meta: dict) -> list[BlockCoord]:
    return [BlockCoord.from_dict(b) for b in meta.get("blocks", [])]


# Types a browser executes in the page's origin. Presigned URLs share the UI
# origin, so these must not be able to run script against it.
_ACTIVE_CONTENT_TYPES = frozenset({
    "text/html", "application/xhtml+xml", "image/svg+xml", "text/xml", "application/xml",
})
_GENERIC_MIME_TYPES = frozenset({"", "application/octet-stream", "binary/octet-stream"})


def _meta_size(meta: dict) -> int:
    """Object size from either the block schema or the legacy UI-upload schema."""
    return int(meta.get("size", meta.get(ATTR_BLOB_SIZE_BYTES, 0)) or 0)


def _meta_etag(meta: dict) -> str:
    return meta.get("etag", meta.get("blob.p2.io/hash/md5", "")) or ""


def _meta_mtime(meta: dict) -> str:
    return str(meta.get("mtime", meta.get(ATTR_BLOB_STAT_MTIME, "")) or "")


def _meta_mime(meta: dict, key: str) -> str:
    """Content-Type for an object.

    Uploads that arrive without a real type (browsers and curl fall back to
    application/octet-stream) are stored as such, which makes browsers download
    instead of render. Infer the type from the key's extension in that case.
    """
    mime = meta.get("mime") or meta.get(ATTR_BLOB_MIME) or ""
    if mime.split(";")[0].strip().lower() in _GENERIC_MIME_TYPES:
        guessed, _ = mimetypes.guess_type(key)
        mime = guessed or mime or "application/octet-stream"
    if mime.startswith("text/") and "charset" not in mime.lower():
        mime = f"{mime}; charset=utf-8"
    return mime


def _legacy_fs_path(meta: dict) -> str | None:
    """Filesystem path of a legacy per-file object, or None for block objects."""
    if meta.get("blocks"):
        return None
    internal_path = meta.get("internal_path")
    if not internal_path:
        return None
    from p2.core.storage_path import internal_to_fs
    return internal_to_fs(internal_path)


def _read_file_range(fs_path: str, start: int, end: int) -> bytes:
    with open(fs_path, "rb") as fh:
        fh.seek(start)
        return fh.read(end - start + 1)


async def _stream_file_range(fs_path: str, start: int, end: int, chunk_size: int = 1024 * 1024):
    remaining = end - start + 1
    fh = await asyncio.to_thread(open, fs_path, "rb")
    try:
        await asyncio.to_thread(fh.seek, start)
        while remaining > 0:
            chunk = await asyncio.to_thread(fh.read, min(chunk_size, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk
    finally:
        await asyncio.to_thread(fh.close)


def _harden_inline_response(response: HttpResponse, content_type: str) -> None:
    response["X-Content-Type-Options"] = "nosniff"
    if content_type.split(";")[0].strip().lower() in _ACTIVE_CONTENT_TYPES:
        response["Content-Security-Policy"] = "sandbox"


def _parse_tagging_xml(body: bytes) -> dict:
    root = ElementTree.fromstring(body)
    tags = {}
    for tag_el in root.iter("Tag"):
        key_el = tag_el.find("Key") or tag_el.find(f"{{{XML_NAMESPACE}}}Key")
        val_el = tag_el.find("Value") or tag_el.find(f"{{{XML_NAMESPACE}}}Value")
        if key_el is not None and key_el.text:
            tags[key_el.text] = val_el.text if val_el is not None else ""
    return tags


def _build_tagging_xml(tags: dict) -> ElementTree.Element:
    root = ElementTree.Element(f"{{{XML_NAMESPACE}}}Tagging")
    tag_set = ElementTree.SubElement(root, "TagSet")
    for k, v in tags.items():
        t = ElementTree.SubElement(tag_set, "Tag")
        ElementTree.SubElement(t, "Key").text = k
        ElementTree.SubElement(t, "Value").text = str(v)
    return root


# ---------------------------------------------------------------------------
# ObjectView
# ---------------------------------------------------------------------------

class ObjectView(S3View):
    """S3 Object CRUD — all handlers async, uses Volume Pool block model."""

    # ── CORS / presign helpers ────────────────────────────────────────────

    async def _check_presigned(self, request, bucket, path):
        token = request.GET.get("X-P2-Signature")
        if not token:
            return
        max_age = int(request.GET.get("X-Amz-Expires", 3600))
        validate_presigned_token(token, bucket, path.lstrip("/"), request.method, max_age=max_age)
        request._presigned_validated = True

    async def _apply_cors(self, request, response, volume):
        requested_vid = request.GET.get("versionId")
        if requested_vid:
            response["x-amz-version-id"] = requested_vid
        origin = request.META.get("HTTP_ORIGIN", "")
        if not origin:
            return response
        rule = find_matching_rule(get_cors_rules(volume), origin, request.method)
        if rule:
            apply_cors_headers(response, rule, origin)
        return response

    # ── OPTIONS ───────────────────────────────────────────────────────────

    async def options(self, request, bucket, path):
        origin = request.META.get("HTTP_ORIGIN", "")
        req_method = request.META.get("HTTP_ACCESS_CONTROL_REQUEST_METHOD", "GET")
        try:
            from p2.core.models import Volume
            from p2.s3.cache import get_cached_volume, set_cached_volume
            volume = get_cached_volume(bucket)
            if not volume:
                volume = await Volume.objects.aget(name=bucket)
                set_cached_volume(bucket, volume)
        except Exception:
            return HttpResponse(status=403)
        rule = find_matching_rule(get_cors_rules(volume), origin, req_method)
        if not rule:
            return HttpResponse(status=403)
        return cors_preflight_response(rule, origin)

    # ── HEAD ──────────────────────────────────────────────────────────────

    async def head(self, request, bucket, path):
        await self._check_presigned(request, bucket, path)
        volume = await self.get_volume(request.user, bucket, "read", object_key=path)

        requested_vid = request.GET.get("versionId")
        if requested_vid:
            from p2.s3.versioning import _version_lmdb_key
            engine = await self.get_engine(volume)
            version_key = _version_lmdb_key(path, requested_vid)
            raw = await asyncio.to_thread(engine.get_raw, version_key)
            if not raw:
                return HttpResponse(status=404)
            meta = json.loads(raw)
            if meta.get("blob.p2.io/delete_marker", False) or meta.get("delete_marker", False):
                response = HttpResponse(status=404)
                response["x-amz-delete-marker"] = "true"
                response["x-amz-version-id"] = requested_vid
                return await self._apply_cors(request, response, volume)
        else:
            meta = get_cached_metadata(volume.uuid.hex, path)
            if meta is None:
                engine = await self.get_engine(volume)
                raw = await asyncio.to_thread(engine.get, path)
                if not raw:
                    return HttpResponse(status=404)
                meta = json.loads(raw)
                set_cached_metadata(volume.uuid.hex, path, meta)

        response = HttpResponse(status=200)
        response["Content-Length"] = _meta_size(meta)
        response["Content-Type"] = _meta_mime(meta, path)
        lm = _fmt_http_date(_meta_mtime(meta))
        if lm:
            response["Last-Modified"] = lm
        etag = _meta_etag(meta)
        if etag:
            response["ETag"] = f'"{etag}"'
        response["Accept-Ranges"] = "bytes"
        return await self._apply_cors(request, response, volume)

    # ── GET ───────────────────────────────────────────────────────────────

    async def get(self, request, bucket, path):
        await self._check_presigned(request, bucket, path)

        if "tagging" in request.GET:
            return await self._get_tagging(request, bucket, path)
        if "acl" in request.GET:
            return await self._get_acl(request, bucket, path)
        if "uploadId" in request.GET:
            return await MultipartUploadView().dispatch(request, bucket, path)

        volume = await self.get_volume(request.user, bucket, "read", object_key=path)
        pool = VolumePool.get()

        requested_vid = request.GET.get("versionId")
        if requested_vid:
            from p2.s3.versioning import _version_lmdb_key
            engine = await self.get_engine(volume)
            version_key = _version_lmdb_key(path, requested_vid)
            raw = await asyncio.to_thread(engine.get_raw, version_key)
            if not raw:
                return HttpResponse(status=404)
            meta = json.loads(raw)
            if meta.get("blob.p2.io/delete_marker", False) or meta.get("delete_marker", False):
                response = HttpResponse(status=404)
                response["x-amz-delete-marker"] = "true"
                response["x-amz-version-id"] = requested_vid
                return await self._apply_cors(request, response, volume)
        else:
            meta = get_cached_metadata(volume.uuid.hex, path)
            if meta is None:
                engine = await self.get_engine(volume)
                raw = await asyncio.to_thread(engine.get, path)
                if not raw:
                    LOGGER.warning("GET 404: bucket=%s path=%r", bucket, path)
                    return HttpResponse(status=404)
                meta = json.loads(raw)
                set_cached_metadata(volume.uuid.hex, path, meta)

        blocks = _blocks_from_meta(meta)
        legacy_path = _legacy_fs_path(meta)
        obj_size = _meta_size(meta)
        content_type = _meta_mime(meta, path)
        etag = _meta_etag(meta)

        if legacy_path and obj_size > 0 and not await asyncio.to_thread(os.path.exists, legacy_path):
            LOGGER.error("GET: backing file missing for bucket=%s path=%r", bucket, path)
            return HttpResponse(status=404)

        # 304 Not Modified
        if_none_match = request.META.get("HTTP_IF_NONE_MATCH")
        if if_none_match and etag:
            tags = [t.strip().strip('"') for t in if_none_match.split(",")]
            if etag.strip('"') in tags:
                resp = HttpResponse(status=304)
                resp["ETag"] = etag
                return await self._apply_cors(request, resp, volume)

        range_header = request.META.get("HTTP_RANGE")
        if range_header and obj_size > 0:
            return await self._range_response(request, pool, blocks, content_type, obj_size, etag, meta, range_header, volume, legacy_path)

        # Full object streaming
        lm = _fmt_http_date(_meta_mtime(meta))
        if legacy_path:
            if obj_size <= 4 * 1024 * 1024:
                data = await asyncio.to_thread(_read_file_range, legacy_path, 0, obj_size - 1) if obj_size else b""
                response = HttpResponse(data, content_type=content_type, status=200)
            else:
                response = StreamingHttpResponse(
                    _stream_file_range(legacy_path, 0, obj_size - 1), content_type=content_type, status=200)
        elif obj_size <= 4 * 1024 * 1024:
            data = await read_object(pool, blocks)
            response = HttpResponse(data, content_type=content_type, status=200)
        else:
            async def _gen():
                async for chunk in stream_blocks(pool, blocks):
                    yield chunk
            response = StreamingHttpResponse(_gen(), content_type=content_type, status=200)

        response["Content-Length"] = obj_size
        if lm:
            response["Last-Modified"] = lm
        response["ETag"] = f'"{etag}"' if etag else ""
        response["Accept-Ranges"] = "bytes"
        if "response-content-type" in request.GET:
            response["Content-Type"] = request.GET["response-content-type"]
        if "response-content-disposition" in request.GET:
            response["Content-Disposition"] = request.GET["response-content-disposition"]
        _harden_inline_response(response, response["Content-Type"])
        return await self._apply_cors(request, response, volume)

    async def _range_response(self, request, pool, blocks, content_type, obj_size, etag, meta, range_header, volume, legacy_path=None):
        try:
            unit, ranges = range_header.split("=", 1)
            if unit.strip() != "bytes":
                raise ValueError
            start_str, end_str = ranges.strip().split("-", 1)
            start = int(start_str) if start_str else None
            end = int(end_str) if end_str else None
        except (ValueError, AttributeError):
            return HttpResponse(status=416)

        if start is None:
            start = max(0, obj_size - end)
            end = obj_size - 1
        if end is None or end >= obj_size:
            end = obj_size - 1
        if start > end or start >= obj_size:
            resp = HttpResponse(status=416)
            resp["Content-Range"] = f"bytes */{obj_size}"
            return resp

        length = end - start + 1
        if legacy_path:
            if length <= 4 * 1024 * 1024:
                data = await asyncio.to_thread(_read_file_range, legacy_path, start, end)
                response = HttpResponse(data, content_type=content_type, status=206)
            else:
                response = StreamingHttpResponse(
                    _stream_file_range(legacy_path, start, end), content_type=content_type, status=206)
        elif length <= 4 * 1024 * 1024:
            data = await read_range(pool, blocks, start, end)
            response = HttpResponse(data, content_type=content_type, status=206)
        else:
            slices = slice_blocks(blocks, start, end)

            async def _gen():
                async for chunk in stream_sliced_blocks(pool, slices):
                    yield chunk
            response = StreamingHttpResponse(_gen(), content_type=content_type, status=206)

        response["Content-Length"] = length
        response["Content-Range"] = f"bytes {start}-{end}/{obj_size}"
        response["Accept-Ranges"] = "bytes"
        if etag:
            response["ETag"] = f'"{etag}"'
        lm = _fmt_http_date(_meta_mtime(meta))
        if lm:
            response["Last-Modified"] = lm
        _harden_inline_response(response, content_type)
        return await self._apply_cors(request, response, volume)

    # ── POST ──────────────────────────────────────────────────────────────

    async def post(self, request, bucket, path):
        return await MultipartUploadView().dispatch(request, bucket, path)

    # ── PUT ───────────────────────────────────────────────────────────────

    async def put(self, request, bucket, path):
        await self._check_presigned(request, bucket, path)

        if "uploadId" in request.GET:
            return await MultipartUploadView().dispatch(request, bucket, path)
        if "tagging" in request.GET:
            return await self._put_tagging(request, bucket, path)
        if "acl" in request.GET:
            return await self._put_acl(request, bucket, path)
        if request.META.get("HTTP_X_AMZ_COPY_SOURCE"):
            return await self._copy_object(request, bucket, path, request.META["HTTP_X_AMZ_COPY_SOURCE"])

        volume = await self.get_volume(request.user, bucket, "write")
        engine = await self.get_engine(volume)
        pool = VolumePool.get()

        client_ct = request.META.get("CONTENT_TYPE", "application/octet-stream")
        content_encoding = request.META.get("HTTP_CONTENT_ENCODING", "")
        decoded_length = request.META.get("HTTP_X_AMZ_DECODED_CONTENT_LENGTH")
        is_aws_chunked = "aws-chunked" in content_encoding or decoded_length

        # ── Read body ────────────────────────────────────────────────────
        chunks: list[bytes] = []

        if is_aws_chunked:
            raw = await asyncio.to_thread(request.read)
            body = decode_aws_chunked(raw)
            chunks = [body]
        else:
            async for chunk in iter_request_body(request, 4 * 1024 * 1024):
                chunks.append(chunk)

        data = b"".join(chunks)
        blob_size = len(data)
        # Hashing pins the event loop for the duration of the call (hashlib
        # releases the GIL internally, but this coroutine still can't yield to
        # any other request on this worker until it returns), so large bodies
        # are dispatched to a thread — see hash_put_body().
        md5_digest, final_sha256 = await hash_put_body(data)
        final_md5 = md5_digest.hex()

        # ── Integrity checks ─────────────────────────────────────────────
        expected_md5 = request.META.get("HTTP_CONTENT_MD5")
        if expected_md5:
            import base64
            computed = base64.b64encode(md5_digest).decode("ascii")
            if computed != expected_md5:
                raise AWSBadDigest

        # ── Allocate block in volume pool ─────────────────────────────────
        if blob_size > 0:
            handle, offset = await asyncio.to_thread(pool.allocate_block, blob_size)
            block = BlockCoord(vol_uuid=handle.uuid_hex, offset=offset, length=blob_size)
            blocks = [block]
        else:
            # Zero-byte object: no block allocated
            handle = None
            offset = 0
            blocks = []

        # ── Versioning ────────────────────────────────────────────────────
        existing_raw = await asyncio.to_thread(engine.get, path)
        existing_size = 0
        existing_counted = False
        if existing_raw:
            ex = json.loads(existing_raw)
            if not ex.get("is_folder", False):
                existing_size = int(ex.get("size", 0) or 0)
                existing_counted = True

        bucket_versioning = (volume.tags or {}).get("versioning") == "true"
        new_version_id = None
        if bucket_versioning:
            from p2.s3.versioning import archive_version, new_version_id as _new_vid
            if existing_raw and not json.loads(existing_raw).get("is_folder", False):
                await archive_version(engine, path, existing_raw)
            new_version_id = _new_vid()

        # ── Build metadata ────────────────────────────────────────────────
        now_ts = str(now())
        import uuid
        blob_uuid = uuid.uuid4().hex
        internal_path = f"/internal-storage/volumes/{volume.uuid.hex}/{blob_uuid[0:2]}/{blob_uuid[2:4]}/{blob_uuid}"

        metadata_payload: dict[str, Any] = {
            "size": blob_size,
            "mime": client_ct,
            "blocks": [b.to_dict() for b in blocks],
            "etag": final_md5,
            "sha256": final_sha256,
            "mtime": now_ts,
            "ctime": now_ts,
            "is_folder": False,
            "internal_path": internal_path,
        }
        if new_version_id:
            metadata_payload["version_id"] = new_version_id
        metadata_json = json.dumps(metadata_payload)

        # ── Group-commit: write data + metadata atomically ────────────────
        if handle is not None:
            await write_block(handle, offset, data, engine, path, metadata_json, md5_digest)
        else:
            await asyncio.to_thread(engine.put, path, metadata_json)

        if new_version_id:
            from p2.s3.versioning import _version_lmdb_key
            lmdb_key = _version_lmdb_key(path, new_version_id)
            await asyncio.to_thread(engine.put_raw, lmdb_key, metadata_json.encode("utf-8"))

        # ── Cache invalidation + stats ────────────────────────────────────
        invalidate_metadata(volume.uuid.hex, path)
        if existing_raw:
            invalidate_volume_global(volume.name)

        from p2.core.volume_stats import adjust_volume_stats
        await adjust_volume_stats(
            volume,
            object_delta=0 if existing_counted else 1,
            bytes_delta=blob_size - existing_size,
        )

        # ── Publish event ─────────────────────────────────────────────────
        try:
            from p2.core.events import STREAM_BLOB_POST_SAVE, make_event, publish_event
            event = make_event(
                blob_uuid=uuid.uuid4().hex,
                volume_uuid=volume.uuid.hex,
                event_type="blob_post_save",
            )
            event["blob_path"] = path
            event["mime"] = client_ct
            event["blocks"] = [b.to_dict() for b in blocks]
            if getattr(settings, "S3_ASYNC_EVENT_PUBLISH", False):
                task = asyncio.create_task(publish_event(STREAM_BLOB_POST_SAVE, event))
                task.add_done_callback(lambda t: t.exception() if t.exception() else None)
            else:
                await publish_event(STREAM_BLOB_POST_SAVE, event)
        except Exception as e:
            LOGGER.warning("Failed to publish blob event: %s", e)

        response = HttpResponse(status=200)
        response["ETag"] = f'"{final_md5}"'
        if new_version_id:
            response["x-amz-version-id"] = new_version_id
        return await self._apply_cors(request, response, volume)

    # ── DELETE ────────────────────────────────────────────────────────────

    async def delete(self, request, bucket, path):
        await self._check_presigned(request, bucket, path)
        volume = await self.get_volume(request.user, bucket, "delete")
        engine = await self.get_engine(volume)

        # Versioning
        bucket_versioning = (volume.tags or {}).get("versioning") == "true"
        requested_vid = request.GET.get("versionId")
        if bucket_versioning and requested_vid:
            from p2.s3.versioning import delete_specific_version
            found = await delete_specific_version(engine, path, requested_vid)
            resp = HttpResponse(status=204)
            if found:
                resp["x-amz-version-id"] = requested_vid
            return resp
        if bucket_versioning and not requested_vid:
            from p2.s3.versioning import write_delete_marker
            marker_vid = await write_delete_marker(engine, path, str(now()))
            invalidate_metadata(volume.uuid.hex, path)
            invalidate_volume_global(volume.name)
            resp = HttpResponse(status=204)
            resp["x-amz-version-id"] = marker_vid
            resp["x-amz-delete-marker"] = "true"
            return resp

        # Logical delete: remove LMDB key only — physical bytes reclaimed by compaction
        raw = await asyncio.to_thread(engine.get, path)
        bytes_delta = 0
        object_delta = 0
        if raw:
            meta = json.loads(raw)
            if not meta.get("is_folder", False):
                bytes_delta = -int(meta.get("size", 0) or 0)
                object_delta = -1
            await asyncio.to_thread(engine.delete, path)
            invalidate_metadata(volume.uuid.hex, path)
            invalidate_volume_global(volume.name)
            from p2.core.volume_stats import adjust_volume_stats
            await adjust_volume_stats(volume, object_delta=object_delta, bytes_delta=bytes_delta)

        return HttpResponse(status=204)

    # ── Copy object ───────────────────────────────────────────────────────

    async def _copy_object(self, request, dest_bucket, dest_path, copy_source):
        import urllib.parse
        try:
            copy_source = urllib.parse.unquote(copy_source).lstrip("/")
            parts = copy_source.split("/", 1)
            if len(parts) != 2:
                return HttpResponse(status=400)
            src_bucket, src_path = parts

            src_volume = await self.get_volume(request.user, src_bucket, "read")
            dest_volume = await self.get_volume(request.user, dest_bucket, "write")
            src_engine = await self.get_engine(src_volume)
            dest_engine = await self.get_engine(dest_volume)

            src_raw = await asyncio.to_thread(src_engine.get, src_path)
            if not src_raw:
                return HttpResponse(status=404)
            src_meta = json.loads(src_raw)

            # Copy: reuse the exact same block coords (zero physical copy)
            dest_meta = dict(src_meta)
            dest_meta["mtime"] = str(now())
            dest_meta["ctime"] = str(now())

            existing_raw = await asyncio.to_thread(dest_engine.get, dest_path)
            existing_size = 0
            existing_counted = False
            if existing_raw:
                ex = json.loads(existing_raw)
                if not ex.get("is_folder", False):
                    existing_size = int(ex.get("size", 0) or 0)
                    existing_counted = True

            dest_versioning = (dest_volume.tags or {}).get("versioning") == "true"
            new_vid = None
            if dest_versioning:
                from p2.s3.versioning import archive_version, new_version_id as _new_vid
                if existing_raw:
                    await archive_version(dest_engine, dest_path, existing_raw)
                new_vid = _new_vid()
                dest_meta["version_id"] = new_vid
            else:
                dest_meta.pop("version_id", None)

            dest_json = json.dumps(dest_meta)
            await asyncio.to_thread(dest_engine.put, dest_path, dest_json)
            if new_vid:
                from p2.s3.versioning import _version_lmdb_key
                lk = _version_lmdb_key(dest_path, new_vid)
                await asyncio.to_thread(dest_engine.put_raw, lk, dest_json.encode("utf-8"))

            from p2.core.volume_stats import adjust_volume_stats
            await adjust_volume_stats(
                dest_volume,
                object_delta=0 if existing_counted else 1,
                bytes_delta=int(dest_meta.get("size", 0) or 0) - existing_size,
            )
            invalidate_metadata(dest_volume.uuid.hex, dest_path)
            if existing_raw:
                invalidate_volume_global(dest_volume.name)

            root = ElementTree.Element(f"{{{XML_NAMESPACE}}}CopyObjectResult")
            ElementTree.SubElement(root, "LastModified").text = dest_meta["mtime"]
            etag = dest_meta.get("etag", "")
            if etag:
                ElementTree.SubElement(root, "ETag").text = f'"{etag}"'
            resp = XMLResponse(root)
            if new_vid:
                resp["x-amz-version-id"] = new_vid
            return resp
        except Exception:
            LOGGER.exception("_copy_object failed")
            return HttpResponse(status=500)

    # ── Tagging ───────────────────────────────────────────────────────────

    async def _get_tagging(self, request, bucket, path):
        volume = await self.get_volume(request.user, bucket, "read")
        engine = await self.get_engine(volume)
        raw = await asyncio.to_thread(engine.get, path)
        if not raw:
            return HttpResponse(status=404)
        meta = json.loads(raw)
        tags = meta.get("tags", {})
        return XMLResponse(_build_tagging_xml(tags))

    async def _put_tagging(self, request, bucket, path):
        volume = await self.get_volume(request.user, bucket, "write")
        engine = await self.get_engine(volume)
        raw = await asyncio.to_thread(engine.get, path)
        if not raw:
            return HttpResponse(status=404)
        meta = json.loads(raw)
        meta["tags"] = _parse_tagging_xml(request.body)
        await asyncio.to_thread(engine.put, path, json.dumps(meta))
        invalidate_metadata(volume.uuid.hex, path)
        return HttpResponse(status=200)

    async def _get_acl(self, request, bucket, path):
        volume = await self.get_volume(request.user, bucket, "read")
        engine = await self.get_engine(volume)
        raw = await asyncio.to_thread(engine.get, path)
        if not raw:
            return HttpResponse(status=404)
        meta = json.loads(raw)
        acl = meta.get("acl", "private")
        owner_id = str(volume.owner.pk) if volume.owner else "0"
        owner_name = volume.owner.username if volume.owner else "System"
        root = ElementTree.Element(f"{{{XML_NAMESPACE}}}AccessControlPolicy")
        owner_el = ElementTree.SubElement(root, "Owner")
        ElementTree.SubElement(owner_el, "ID").text = owner_id
        ElementTree.SubElement(owner_el, "DisplayName").text = owner_name
        acl_list = ElementTree.SubElement(root, "AccessControlList")
        grant = ElementTree.SubElement(acl_list, "Grant")
        grantee = ElementTree.SubElement(grant, "Grantee")
        grantee.set("{http://www.w3.org/2001/XMLSchema-instance}type", "CanonicalUser")
        ElementTree.SubElement(grantee, "ID").text = owner_id
        ElementTree.SubElement(grant, "Permission").text = "FULL_CONTROL"
        return XMLResponse(root)

    async def _put_acl(self, request, bucket, path):
        volume = await self.get_volume(request.user, bucket, "write")
        engine = await self.get_engine(volume)
        raw = await asyncio.to_thread(engine.get, path)
        if not raw:
            return HttpResponse(status=404)
        acl_header = request.META.get("HTTP_X_AMZ_ACL")
        if acl_header:
            meta = json.loads(raw)
            meta["acl"] = acl_header
            await asyncio.to_thread(engine.put, path, json.dumps(meta))
            invalidate_metadata(volume.uuid.hex, path)
        return HttpResponse(status=200)

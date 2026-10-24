"""Core API Ninja Endpoints"""
import hashlib
import json
import logging
import mimetypes
import os
import uuid
from typing import List, Optional

from asgiref.sync import async_to_sync
from django.contrib.auth.models import Group
from django.db.models import Q
from django.utils.timezone import now
from django.http import FileResponse, Http404, HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404
from ninja import Router, File
from ninja.files import UploadedFile

from p2.core.acl import VolumeACL, has_volume_permission
from p2.core.api.schemas import (
    StorageSchema, VolumeSchema, VolumeCreateSchema, VolumeUpdateSchema,
    UploadResponseSchema, BlobSchema, BlobListResponse,
    FolderCreateSchema,
)
from p2.core.constants import (ATTR_BLOB_IS_FOLDER, ATTR_BLOB_MIME,
                                ATTR_BLOB_SIZE_BYTES, ATTR_BLOB_STAT_CTIME,
                                ATTR_BLOB_STAT_MTIME)
from p2.core.models import Storage, Volume
from p2.core.volume_stats import adjust_volume_stats_sync
from p2.s3.engine import get_engine as _get_engine

LOGGER = logging.getLogger(__name__)

router_volume = Router(tags=["core-volume"])
router_storage = Router(tags=["core-storage"])

def _check_permission(user, volume, permission):
    return async_to_sync(has_volume_permission)(user, volume, permission)


ALL_VOLUME_PERMISSIONS = ('read', 'write', 'delete', 'list', 'admin')


def _permission_map(user, volumes):
    """Map volume pk -> set of permissions held by *user*.

    Batched so listing many buckets doesn't issue one ACL query per bucket.
    """
    result = {str(v.pk): set() for v in volumes}
    if getattr(user, 'is_superuser', False):
        for pk in result:
            result[pk] = set(ALL_VOLUME_PERMISSIONS)
        return result
    if getattr(user, 'is_authenticated', False):
        group_ids = list(
            Group.objects.filter(user=user).values_list('pk', flat=True)
        )
        acls = VolumeACL.objects.filter(volume__in=volumes).filter(
            Q(user=user) | Q(group_id__in=group_ids)
        )
        for acl in acls:
            perms = acl.permissions if isinstance(acl.permissions, list) else []
            result[str(acl.volume_id)].update(perms)
    for v in volumes:
        if v.public_read:
            result[str(v.pk)].update({'read', 'list'})
    return result


def _ordered_permissions(perms) -> list:
    return [p for p in ALL_VOLUME_PERMISSIONS if p in perms]


def _visible_volumes(user):
    """Volumes the caller is allowed to see.

    Superusers see everything; everyone else only sees volumes they hold an
    ACL entry for (directly or via a group) plus publicly readable volumes.
    Without this filter any authenticated user can enumerate every bucket.
    """
    if not getattr(user, 'is_authenticated', False):
        return Volume.objects.filter(public_read=True)
    if getattr(user, 'is_superuser', False):
        return Volume.objects.all()
    group_ids = list(
        Group.objects.filter(user=user).values_list('pk', flat=True)
    )
    return Volume.objects.filter(
        Q(public_read=True) | Q(acls__user=user) | Q(acls__group_id__in=group_ids)
    ).distinct()


@router_volume.get("/", response=List[VolumeSchema])
def list_volumes(request):
    volumes = list(_visible_volumes(request.user))
    perms = _permission_map(request.user, volumes)
    for vol in volumes:
        vol._p2_permissions = _ordered_permissions(perms[str(vol.pk)])
    return volumes

@router_volume.get("/{volume_uuid}/", response=VolumeSchema)
def get_volume(request, volume_uuid: str):
    vol = get_object_or_404(_visible_volumes(request.user), uuid=volume_uuid)
    stats = _get_volume_stats(vol)
    perms = _permission_map(request.user, [vol])[str(vol.pk)]
    # Present live stats and the caller's permissions without another query.
    vol.object_count = stats["object_count"]
    vol.space_used_bytes = stats["space_used_bytes"]
    vol._p2_permissions = _ordered_permissions(perms)
    return vol

@router_volume.post("/", response=VolumeSchema)
def create_volume(request, payload: VolumeCreateSchema):
    # Only administrators may create buckets. Everyone else is limited to the
    # buckets explicitly shared with them.
    if not getattr(request.user, 'is_superuser', False):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("Only administrators can create buckets")
    storage = None
    if payload.storage_uuid:
        storage = get_object_or_404(Storage, uuid=payload.storage_uuid)
    else:
        from p2.core.tests.utils import get_test_storage
        storage = get_test_storage()
    tags = payload.tags or {}
    public_read = tags.get('access_policy') in ('public-read', 'public-read-write')
    vol = Volume.objects.create(name=payload.name, storage=storage, tags=tags, public_read=public_read)
    VolumeACL.objects.create(volume=vol, user=request.user,
                             permissions=['read', 'write', 'delete', 'list', 'admin'])
    vol._p2_permissions = list(ALL_VOLUME_PERMISSIONS)
    return vol

@router_volume.delete("/{volume_uuid}/")
def delete_volume(request, volume_uuid: str):
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'admin'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No admin permission on this volume")
    vol.delete()
    from p2.s3.engine import close_engine
    close_engine(volume_uuid)
    return {"success": True}

@router_volume.put("/{volume_uuid}/", response=VolumeSchema)
def update_volume(request, volume_uuid: str, payload: VolumeUpdateSchema):
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'admin'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No admin permission on this volume")
    
    tags = vol.tags or {}
    if payload.access_policy is not None:
        tags['access_policy'] = payload.access_policy
        vol.public_read = payload.access_policy in ('public-read', 'public-read-write')
    if payload.versioning is not None:
        # Store as 'true'/'false' string to match S3 view convention
        tags['versioning'] = 'true' if payload.versioning else 'false'
    if payload.encryption is not None:
        tags['encryption'] = payload.encryption
    if payload.cors_rules is not None:
        from p2.s3.constants import TAG_S3_CORS_RULES
        valid_methods = {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}
        normalized_rules = []
        for r in payload.cors_rules:
            origins = [o.strip() for o in r.AllowedOrigins if o and o.strip()]
            methods = [m.strip().upper() for m in r.AllowedMethods if m and m.strip().upper() in valid_methods]
            if not origins or not methods:
                continue
            rule_dict = {
                'AllowedOrigins': origins,
                'AllowedMethods': methods,
                'AllowedHeaders': [h.strip() for h in (r.AllowedHeaders or []) if h and h.strip()],
                'ExposeHeaders': [h.strip() for h in (r.ExposeHeaders or []) if h and h.strip()],
            }
            if r.MaxAgeSeconds is not None and r.MaxAgeSeconds >= 0:
                rule_dict['MaxAgeSeconds'] = int(r.MaxAgeSeconds)
            normalized_rules.append(rule_dict)
        if normalized_rules:
            tags[TAG_S3_CORS_RULES] = normalized_rules
        else:
            tags.pop(TAG_S3_CORS_RULES, None)

    vol.tags = tags
    vol.save(update_fields=['tags', 'public_read'])

    # Invalidate S3 volume cache across ALL workers via Redis generation counter.
    from p2.s3.cache import invalidate_volume_global, invalidate_acl
    invalidate_volume_global(vol.name)
    invalidate_acl(str(vol.pk))

    return VolumeSchema.from_orm(vol)

@router_volume.get("/{volume_uuid}/blobs/", response=BlobListResponse)
def list_blobs(request, volume_uuid: str, prefix: str = "", max_keys: int = 100, start_after: str = "", search: str = ""):
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'list'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No list permission on this volume")
    engine = _get_engine(vol)
    # When searching, scan the entire bucket (ignore prefix) and filter by search term
    search_lower = search.lower() if search else ""
    if not search_lower:
        objects_entries, folders_entries = engine.list_dir(
            prefix=prefix,
            start_after=start_after or None,
            max_keys=max_keys
        )
        direct_objects = []
        for key, meta_json in objects_entries:
            try:
                meta = json.loads(meta_json)
            except (json.JSONDecodeError, TypeError):
                continue
            direct_objects.append(BlobSchema(
                key=key,
                size=int(meta.get(ATTR_BLOB_SIZE_BYTES, 0) or 0),
                last_modified=meta.get(ATTR_BLOB_STAT_MTIME, ''),
                mime=meta.get(ATTR_BLOB_MIME, 'application/octet-stream'),
                etag=meta.get('blob.p2.io/hash/md5', ''),
            ))
        folders = set(folders_entries)
        has_more = (len(direct_objects) + len(folders)) >= max_keys
    else:
        entries = engine.list("", start_after=start_after or None, max_keys=2000)
        all_objects = []
        folders = set()
        plen = len(prefix)

        for key, meta_json in entries:
            try:
                meta = json.loads(meta_json)
            except (json.JSONDecodeError, TypeError):
                continue

            # Explicit folder markers
            if meta.get(ATTR_BLOB_IS_FOLDER, False):
                folders.add(key)
                continue

            all_objects.append(BlobSchema(
                key=key,
                size=int(meta.get(ATTR_BLOB_SIZE_BYTES, 0) or 0),
                last_modified=meta.get(ATTR_BLOB_STAT_MTIME, ''),
                mime=meta.get(ATTR_BLOB_MIME, 'application/octet-stream'),
                etag=meta.get('blob.p2.io/hash/md5', ''),
            ))

        # Separate: direct children belong in `objects`, nested keys derive folders.
        direct_objects = []
        for obj in all_objects:
            remainder = obj.key[plen:] if prefix and obj.key.startswith(prefix) else obj.key
            if '/' in remainder:
                dirname = remainder[:remainder.index('/') + 1]
                folders.add((prefix + dirname) if prefix else dirname)
            else:
                direct_objects.append(obj)

        # Apply search filter across the bucket if search term provided
        # When searching, include ALL matching objects across nesting levels,
        # not just direct children. Also include matching folders.
        direct_objects = [obj for obj in all_objects
                          if search_lower in obj.key.lower()]
        folders = {f for f in folders if search_lower in f.lower()}
        has_more = len(entries) >= 2000

    # Compute pagination token: last key among returned items
    all_returned_keys = [obj.key for obj in direct_objects] + list(folders)
    next_start_after_val = ""
    if has_more and all_returned_keys:
        next_start_after_val = sorted(all_returned_keys)[-1]

    # Calculate count and size of files inside each folder prefix using cache
    from django.core.cache import cache
    folder_details = []
    for folder_prefix in sorted(folders):
        cache_key = f"folder_stats:{vol.uuid.hex}:{folder_prefix}"
        stats = cache.get(cache_key)
        if stats is None:
            folder_size = 0
            folder_count = 0
            for key, meta_json in engine.list(folder_prefix, max_keys=None):
                try:
                    meta = json.loads(meta_json)
                except (json.JSONDecodeError, TypeError):
                    continue
                if meta.get(ATTR_BLOB_IS_FOLDER, False):
                    continue
                folder_count += 1
                folder_size += int(meta.get(ATTR_BLOB_SIZE_BYTES, 0) or 0)
            stats = {
                "size": folder_size,
                "object_count": folder_count,
            }
            # Cache for 10 minutes (600 seconds) since we invalidate on writes
            cache.set(cache_key, stats, timeout=600)
            
        folder_details.append({
            "name": folder_prefix.rstrip('/').split('/')[-1],
            "prefix": folder_prefix,
            "size": stats["size"],
            "object_count": stats["object_count"],
        })

    return BlobListResponse(
        objects=direct_objects,
        folders=folder_details,
        total_count=len(direct_objects),
        prefix=prefix,
        next_start_after=next_start_after_val,
        has_more=has_more,
    )

@router_volume.get("/{volume_uuid}/blobs/detail/", response=dict)
def blob_detail(request, volume_uuid: str, key: str = ""):
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'read'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No read permission on this volume")
    engine = _get_engine(vol)
    meta_json = engine.get(key)
    if not meta_json:
        return {"error": "Not found", "key": key}
    try:
        return json.loads(meta_json)
    except json.JSONDecodeError:
        return {"error": "Invalid metadata", "key": key}

@router_volume.delete("/{volume_uuid}/blobs/")
def delete_blob(request, volume_uuid: str, key: str = ""):
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'delete'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No delete permission on this volume")
    engine = _get_engine(vol)
    meta_json = engine.get(key)
    if not meta_json:
        return {"error": "Not found"}
    try:
        meta = json.loads(meta_json)
    except json.JSONDecodeError:
        meta = {}
    # Delete the file from disk
    internal_path = meta.get('internal_path', '')
    if internal_path:
        from p2.core.storage_path import internal_to_fs
        fs_path = internal_to_fs(internal_path)
        try:
            os.remove(fs_path)
        except OSError:
            pass
    bytes_delta = 0
    if not meta.get(ATTR_BLOB_IS_FOLDER, False):
        bytes_delta = -int(meta.get(ATTR_BLOB_SIZE_BYTES, 0) or 0)
    engine.delete(key)
    adjust_volume_stats_sync(vol, object_delta=-1, bytes_delta=bytes_delta)
    return {"success": True}

@router_volume.delete("/{volume_uuid}/folder/")
def delete_folder(request, volume_uuid: str, prefix: str = ""):
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'delete'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No delete permission on this volume")
    if not prefix.endswith('/'):
        prefix += '/'
    engine = _get_engine(vol)
    entries = engine.list(prefix, start_after=None, max_keys=10000)
    deleted = 0
    bytes_delta = 0
    for key, meta_json in entries:
        try:
            meta = json.loads(meta_json)
        except (json.JSONDecodeError, TypeError):
            continue
        internal_path = meta.get('internal_path', '')
        if internal_path:
            from p2.core.storage_path import internal_to_fs
            try:
                os.remove(internal_to_fs(internal_path))
            except OSError:
                pass
        if not meta.get(ATTR_BLOB_IS_FOLDER, False):
            bytes_delta -= int(meta.get(ATTR_BLOB_SIZE_BYTES, 0) or 0)
        engine.delete(key)
        deleted += 1
    adjust_volume_stats_sync(vol, object_delta=-deleted, bytes_delta=bytes_delta)
    return {"success": True, "deleted": deleted}


@router_volume.post("/{volume_uuid}/folder/")
def create_folder(request, volume_uuid: str, payload: FolderCreateSchema):
    """Create a folder marker in a volume at the given prefix.

    Folders are implicit in p2 (derived from blob key prefixes),
    but explicit folder markers make empty folders visible in listings.
    """
    prefix = payload.prefix
    folder_name = payload.folder_name
    if not folder_name:
        return {"error": "folder_name is required"}

    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'write'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No write permission on this volume")

    # Build the folder key
    folder_name = folder_name.strip().rstrip('/')
    key = f"{prefix.rstrip('/')}/{folder_name}/" if prefix and prefix != '/' else f"{folder_name}/"
    key = key.lstrip('/')

    engine = _get_engine(vol)

    # Don't overwrite if already exists
    existing = engine.get(key)
    if existing:
        try:
            existing_attr = json.loads(existing)
            if existing_attr.get(ATTR_BLOB_IS_FOLDER, False):
                return {"success": True, "key": key, "existed": True}
        except (json.JSONDecodeError, TypeError):
            pass

    now_ts = str(now())
    attrs = {
        ATTR_BLOB_MIME: 'application/x-directory',
        ATTR_BLOB_SIZE_BYTES: '0',
        ATTR_BLOB_IS_FOLDER: True,
        ATTR_BLOB_STAT_MTIME: now_ts,
        ATTR_BLOB_STAT_CTIME: now_ts,
    }
    engine.put(key, json.dumps(attrs))

    return {"success": True, "key": key}


@router_volume.get("/{volume_uuid}/blobs/download/", response=None)
def blob_download(request, volume_uuid: str, key: str = "", download: bool = False):
    """Serve blob content for preview or download.

    Serves the file directly via FileResponse. Set ?download=1 to force
    Content-Disposition: attachment.
    """
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'read'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No read permission on this volume")

    engine = _get_engine(vol)
    meta_json = engine.get(key)
    if not meta_json:
        raise Http404(f"Blob not found: {key}")

    try:
        attributes = json.loads(meta_json)
    except (json.JSONDecodeError, TypeError):
        raise Http404(f"Invalid metadata for: {key}")

    internal_path = attributes.get('internal_path', '')
    if not internal_path:
        raise Http404(f"No internal_path for: {key}")

    from p2.core.storage_path import internal_to_fs
    fs_path = internal_to_fs(internal_path)

    mime = attributes.get(ATTR_BLOB_MIME, 'application/octet-stream')
    file_size = int(attributes.get(ATTR_BLOB_SIZE_BYTES, 0) or 0)
    filename = key.rsplit('/', 1)[-1] if '/' in key else key
    etag = attributes.get('blob.p2.io/hash/md5', '')

    import os as _os
    if not _os.path.exists(fs_path):
        raise Http404(f"File not found on disk: {key}")

    try:
        response = FileResponse(open(fs_path, 'rb'), content_type=mime)
        response['Content-Length'] = file_size
        if etag:
            response['ETag'] = f'"{etag}"'
        if download:
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
        else:
            disposition = 'inline'
            if mime.startswith('image/') or mime.startswith('video/') or mime.startswith('audio/') or mime == 'application/pdf':
                disposition = 'inline'
            else:
                disposition = f'inline; filename="{filename}"'
            response['Content-Disposition'] = disposition
        response['Accept-Ranges'] = 'bytes'
        return response
    except Exception:
        raise Http404(f"Cannot read file: {key}")


# ── Folder download (ZIP streaming) ─────────────────────────────────────

@router_volume.get("/{volume_uuid}/folder/download/", response=None)
def folder_download(request, volume_uuid: str, prefix: str = ""):
    """Stream a folder as a ZIP file."""
    vol = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, vol, 'read'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No read permission on this volume")

    engine = _get_engine(vol)
    prefix = prefix.strip('/') + '/' if prefix else ''

    try:
        items = list(engine.list(prefix, max_keys=10000))
    except Exception as e:
        LOGGER.error("Failed to list for ZIP: %s", e)
        items = []

    import zipfile, queue, threading
    from p2.core.storage_path import internal_to_fs

    CHUNK = 65536

    blobs = []
    for key, json_val in items:
        if not key.startswith(prefix):
            continue
        try:
            attr = json.loads(json_val) if isinstance(json_val, str) else json_val
            if not attr.get(ATTR_BLOB_IS_FOLDER, False):
                internal_path = attr.get('internal_path', '')
                fs_path = internal_to_fs(internal_path) if internal_path else ''
                if fs_path and os.path.exists(fs_path):
                    blobs.append((key, fs_path))
        except Exception:
            pass

    def _zip_generator():
        q = queue.Queue(maxsize=16)
        SENTINEL = object()

        class _StreamIO:
            def __init__(self):
                self._pos = 0
            def write(self, data):
                if data:
                    q.put(bytes(data))
                self._pos += len(data)
                return len(data)
            def flush(self): pass
            def tell(self): return self._pos

        def _worker():
            try:
                stream = _StreamIO()
                with zipfile.ZipFile(stream, mode='w', allowZip64=True) as zf:
                    for key, fs_path in blobs:
                        arcname = key[len(prefix):]
                        zi = zipfile.ZipInfo(arcname)
                        zi.compress_type = zipfile.ZIP_DEFLATED
                        try:
                            with zf.open(zi, 'w', force_zip64=True) as dest:
                                with open(fs_path, 'rb') as src:
                                    while True:
                                        chunk = src.read(CHUNK)
                                        if not chunk:
                                            break
                                        dest.write(chunk)
                        except Exception as e:
                            LOGGER.warning("Skipping %s in ZIP: %s", key, e)
            except Exception as e:
                LOGGER.error("ZIP error: %s", e)
            finally:
                q.put(SENTINEL)

        threading.Thread(target=_worker, daemon=True).start()
        while True:
            item = q.get()
            if item is SENTINEL:
                break
            yield item

    folder_name = prefix.strip('/').split('/')[-1] or vol.name if prefix else vol.name
    response = StreamingHttpResponse(_zip_generator(), content_type='application/zip')
    response['Content-Disposition'] = f'attachment; filename="{folder_name}.zip"'
    return response


def _get_volume_stats(vol) -> dict:
    """Return object_count and space_used_bytes for a volume via LMDB scan."""
    engine = _get_engine(vol)
    entries = engine.list("", start_after=None, max_keys=100000)
    count = 0
    total_bytes = 0
    for _, meta_json in entries:
        try:
            meta = json.loads(meta_json)
        except (json.JSONDecodeError, TypeError):
            continue
        if not meta.get(ATTR_BLOB_IS_FOLDER, False):
            count += 1
            total_bytes += int(meta.get(ATTR_BLOB_SIZE_BYTES, 0) or 0)
    return {"object_count": count, "space_used_bytes": total_bytes}

@router_volume.post("/{volume_uuid}/upload/", response=UploadResponseSchema)
def upload_files(request, volume_uuid: str, prefix: str = "", file: List[UploadedFile] = File(...)):
    volume = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, volume, 'write'):
        # Just return 403 standard, ninja handles exceptions if configured, or we can return custom.
        # But for now, we just raise standard exception which ninja catches.
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No write permission on this volume")

    prefix = prefix.strip('/')
    uploaded_files = []

    for uploaded_file in file:
        # Django Ninja doesn't naturally parse 'relativePath' POST form field alongside multiple files easily
        # without Form models, but we can fall back to request.POST logic.
        rel_path = request.POST.get('relativePath', uploaded_file.name)
        key = f"{prefix}/{rel_path.lstrip('/')}" if prefix else rel_path.lstrip('/')

        blob_uuid = uuid.uuid4().hex
        from p2.core.storage_path import storage_path
        dir_path = storage_path("volumes", volume.uuid.hex, blob_uuid[0:2], blob_uuid[2:4])
        os.makedirs(dir_path, exist_ok=True)
        fs_path = os.path.join(dir_path, blob_uuid)
        internal_path = (
            f"/internal-storage/volumes/{volume.uuid.hex}"
            f"/{blob_uuid[0:2]}/{blob_uuid[2:4]}/{blob_uuid}"
        )

        md5_hash = hashlib.md5()
        blob_size = 0
        with open(fs_path, 'wb') as f:
            for chunk in uploaded_file.chunks(chunk_size=1 << 20):
                f.write(chunk)
                md5_hash.update(chunk)
                blob_size += len(chunk)

        final_md5 = md5_hash.hexdigest()
        engine = _get_engine(volume)
        existing_json = engine.get(key)
        existing_size = 0
        existing_counted = False
        if existing_json:
            existing_attr = json.loads(existing_json)
            if not existing_attr.get(ATTR_BLOB_IS_FOLDER, False):
                existing_size = int(existing_attr.get(ATTR_BLOB_SIZE_BYTES, 0) or 0)
                existing_counted = True
        attrs = json.loads(existing_json) if existing_json else {}
        upload_mime = uploaded_file.content_type
        if not upload_mime or upload_mime == 'application/octet-stream':
            upload_mime = mimetypes.guess_type(key)[0] or 'application/octet-stream'
        attrs.update({
            ATTR_BLOB_MIME: upload_mime,
            ATTR_BLOB_SIZE_BYTES: str(blob_size),
            ATTR_BLOB_IS_FOLDER: False,
            ATTR_BLOB_STAT_MTIME: str(now()),
            'blob.p2.io/hash/md5': final_md5,
            'internal_path': internal_path,
        })
        if not existing_json:
            attrs[ATTR_BLOB_STAT_CTIME] = str(now())
        engine.put(key, json.dumps(attrs))
        adjust_volume_stats_sync(
            volume,
            object_delta=0 if existing_counted else 1,
            bytes_delta=blob_size - existing_size,
        )

        try:
            from p2.core.events import STREAM_BLOB_POST_SAVE, make_event, publish_event
            event = make_event(
                blob_uuid=blob_uuid,
                volume_uuid=volume.uuid.hex,
                event_type="blob_post_save",
            )
            event['blob_path'] = key
            event['mime'] = upload_mime
            async_to_sync(publish_event)(STREAM_BLOB_POST_SAVE, event)
        except Exception as exc:
            LOGGER.warning("Failed to publish blob event: %s", exc)

        uploaded_files.append({'path': key, 'size': blob_size, 'etag': final_md5})

    return {"uploaded": uploaded_files}


@router_volume.post("/{volume_uuid}/re-index/")
def re_index(request, volume_uuid: str):
    volume = get_object_or_404(Volume, uuid=volume_uuid)
    if not _check_permission(request.user, volume, 'write'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("No write permission on this volume")
    return 0



@router_storage.get("/", response=List[StorageSchema])
def list_storages(request):
    return Storage.objects.all()

@router_storage.get("/{storage_uuid}/", response=StorageSchema)
def get_storage(request, storage_uuid: str):
    return get_object_or_404(Storage, uuid=storage_uuid)

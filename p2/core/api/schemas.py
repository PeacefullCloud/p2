"""p2 core api schemas (Django Ninja)"""
from ninja import ModelSchema, Schema
from p2.core.models import Storage, Volume
from typing import Dict, Any, Optional, List

class VolumeSchema(ModelSchema):
    object_count: int = 0
    space_used_bytes: int = 0
    # Permissions the *requesting* user holds on this volume. Lets the UI show
    # management controls only where the user actually has 'admin' access.
    # Populated by the endpoint via the `_p2_permissions` attribute.
    permissions: List[str] = []

    class Meta:
        model = Volume
        fields = ['uuid', 'name', 'storage', 'tags', 'object_count', 'space_used_bytes']

    @staticmethod
    def resolve_permissions(obj):
        return getattr(obj, '_p2_permissions', [])

class VolumeCreateSchema(Schema):
    name: str
    storage_uuid: Optional[str] = None
    tags: Optional[dict] = None

class CorsRuleSchema(Schema):
    AllowedOrigins: List[str]
    AllowedMethods: List[str]
    AllowedHeaders: List[str] = []
    ExposeHeaders: List[str] = []
    MaxAgeSeconds: Optional[int] = None

class VolumeUpdateSchema(Schema):
    access_policy: Optional[str] = None
    versioning: Optional[bool] = None
    encryption: Optional[str] = None
    cors_rules: Optional[List[CorsRuleSchema]] = None

class FolderCreateSchema(Schema):
    prefix: str = ""
    folder_name: str

class StorageSchema(ModelSchema):
    predefined_keys: dict = {}
    provider: str = ""

    class Meta:
        model = Storage
        fields = ['uuid', 'name', 'controller_path', 'tags']

class UploadResponseSchema(Schema):
    uploaded: list[dict]

class BlobSchema(Schema):
    key: str
    size: int
    last_modified: Optional[str] = None
    mime: Optional[str] = "application/octet-stream"
    etag: Optional[str] = None
    is_folder: bool = False

class FolderSchema(Schema):
    name: str
    prefix: str
    size: int = 0
    object_count: int = 0

class BlobListResponse(Schema):
    objects: List[BlobSchema]
    folders: List[FolderSchema]
    total_count: int
    prefix: str = ""
    next_start_after: str = ""
    has_more: bool = False

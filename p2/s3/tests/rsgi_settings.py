"""Isolated settings for real-Granian integration tests, never a user database."""
from p2.core.settings import *  # noqa: F403

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
VOLUME_SIZE_BYTES = 16 * 1024 * 1024
VOLUME_ACTIVE_POOL_SIZE = 2
S3_ASYNC_EVENT_PUBLISH = False
S3_BENCHMARK_TIMINGS = True
S3_METADATA_LMDB_SYNC = True
S3_METADATA_LMDB_METASYNC = True
S3_VOLUME_FDATASYNC = True

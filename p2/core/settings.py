"""
Django settings for p2 project (Django 5.x / async-first).

Replaces p2/root/settings.py with modernized configuration:
- Django 5.x native JSONField (no postgres-specific import)
- ASGI / uvicorn entrypoint
- psycopg 3.x async-capable database engine
- Django built-in Redis cache backend (replaces django-redis)
- ARQ task queue settings (replaces Celery)
- OpenTelemetry configuration
- djangorestframework-simplejwt (replaces djangorestframework-jwt)
- drf-spectacular (replaces drf-yasg)
- authlib OIDC (replaces mozilla-django-oidc)
- VolumeACL permission model (replaces django-guardian)
"""

import os
import sys
from datetime import timedelta

from p2 import __version__
from p2.lib.config import CONFIG
from django.core.exceptions import ImproperlyConfigured

# Compat shim removed since we are no longer using django.contrib.postgres.

# ---------------------------------------------------------------------------
# Base paths
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

SECRET_KEY = CONFIG.y('secret_key', '')
if not SECRET_KEY:
    raise ImproperlyConfigured(
        "SECRET_KEY is not set. Add SECRET_KEY=<random-string> to your .env file. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
    )

# Fernet key for reversible encryption of API key secrets (used in AWS v4 HMAC auth).
# Must be a URL-safe base64-encoded 32-byte key. Generate with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FERNET_KEY = CONFIG.y('fernet_key', '')

# ── Ninja JWT Configuration ────────────────────────────────────────────────
# ninja-jwt is used for the REST API (/api/v1/*) authentication.
# Without this, JWTAuth() cannot validate tokens and returns 401.
NINJA_JWT = {
    'SIGNING_KEY': SECRET_KEY,
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

DEBUG = CONFIG.y_bool('debug')
TEST = any('test' in arg for arg in sys.argv)

# Validate FERNET_KEY early (before DEBUG/TEST are used elsewhere).
# Skip validation during tests since fixtures may not set this.
if (not TEST) and (not FERNET_KEY or str(FERNET_KEY).lower().startswith('change-me')):
    raise ImproperlyConfigured(
        "FERNET_KEY is not set. Add P2_FERNET_KEY=<fernet-key> to your .env file. "
        "Generate one with: python -c \"from cryptography.fernet import Fernet; "
        "print(Fernet.generate_key().decode())\""
    )

CORS_ORIGIN_ALLOW_ALL = DEBUG
SECURE_SSL_REDIRECT = CONFIG.y_bool('security.ssl_redirect', default=not DEBUG and not TEST)
X_FRAME_OPTIONS = "SAMEORIGIN"

# Publish S3 post-save events without blocking PUT response.
S3_ASYNC_EVENT_PUBLISH = CONFIG.y_bool("s3.async_event_publish", default=False)
# Optional bounded queue for Redis Stream publishing (experimental, off by default).
S3_EVENT_QUEUE_ENABLED = CONFIG.y_bool("s3.event_queue.enabled", default=False)
S3_EVENT_QUEUE_MAX_SIZE = int(CONFIG.y("s3.event_queue.max_size", default=8192))
S3_EVENT_QUEUE_BATCH_SIZE = int(CONFIG.y("s3.event_queue.batch_size", default=64))
S3_EVENT_QUEUE_FLUSH_MS = int(CONFIG.y("s3.event_queue.flush_ms", default=5))
S3_EVENT_QUEUE_WAIT_FOR_ACK = CONFIG.y_bool("s3.event_queue.wait_for_ack", default=False)
S3_BLOB_SHARD_DEPTH = max(1, min(2, int(CONFIG.y("s3.blob.shard_depth", default=2))))
# LMDB metadata durability knobs.
# Defaults retain the existing throughput-oriented configuration. Syncing the
# volume file does not make LMDB object keys/metadata durable. Enable metadata
# sync for durability testing; scanning raw volume bytes cannot recover keys.
S3_METADATA_LMDB_SYNC = CONFIG.y_bool("s3.metadata.lmdb.sync", default=False)
S3_METADATA_LMDB_METASYNC = CONFIG.y_bool("s3.metadata.lmdb.metasync", default=False)
# Whether the group committer issues fdatasync on the volume file after each
# batch. This syncs object bytes only; metadata and new-file directory durability
# are separate concerns. Set False only when data durability is not required.
S3_VOLUME_FDATASYNC = CONFIG.y_bool("s3.volume.fdatasync", default=True)
# Optional bounded queue for async metadata writes (reduces PUT tail latency under concurrency).
S3_METADATA_WRITE_QUEUE_ENABLED = CONFIG.y_bool("s3.metadata.write_queue.enabled", default=True)
S3_METADATA_WRITE_QUEUE_MAX_SIZE = int(CONFIG.y("s3.metadata.write_queue.max_size", default=8192))
S3_METADATA_WRITE_BATCH_SIZE = int(CONFIG.y("s3.metadata.write_queue.batch_size", default=128))
# Straggler wait before flushing a batch of 1. Default 0: the drain loop already
# coalesces all queued requests; a non-zero wait only adds latency at the low
# per-worker concurrency real deployments see (measured 7.3ms vs 1.3ms/op).
S3_METADATA_WRITE_BATCH_WINDOW_MS = float(CONFIG.y("s3.metadata.write_queue.batch_window_ms", default=0.0))
S3_BENCHMARK_TIMINGS = CONFIG.y_bool("s3.benchmark_timings", default=False)
# Experimental RSGI PUT admission, per worker. Reserve before receiving bodies.
S3_RSGI_MAX_BODY_BYTES = int(CONFIG.y("s3.rsgi.max_body_bytes", default=64 * 1024 * 1024))
S3_RSGI_INFLIGHT_BYTES = int(CONFIG.y("s3.rsgi.inflight_bytes", default=256 * 1024 * 1024))
# Warm small-object reads avoid thread hops and file-response setup. Cache
# snapshots are invalidated by LMDB transaction IDs, not a stale-data TTL.
S3_RSGI_SMALL_READ_BYTES = int(CONFIG.y("s3.rsgi.small_read_bytes", default=64 * 1024))
S3_RSGI_READ_CACHE_BYTES = int(CONFIG.y("s3.rsgi.read_cache_bytes", default=64 * 1024 * 1024))
S3_RSGI_READ_CACHE_ENTRIES = int(CONFIG.y("s3.rsgi.read_cache_entries", default=10000))
# In-process hot-path cache TTLs (seconds) for S3 auth/ACL checks.
S3_CACHE_APIKEY_TTL_SECONDS = float(CONFIG.y("s3.cache.apikey_ttl_seconds", default=600))
S3_CACHE_VOLUME_TTL_SECONDS = float(CONFIG.y("s3.cache.volume_ttl_seconds", default=600))
S3_CACHE_ACL_TTL_SECONDS = float(CONFIG.y("s3.cache.acl_ttl_seconds", default=600))
S3_CACHE_VOLUME_PERMISSION_TTL_SECONDS = float(CONFIG.y("s3.cache.volume_permission_ttl_seconds", default=600))
S3_CACHE_METADATA_TTL_SECONDS = float(CONFIG.y("s3.cache.metadata_ttl_seconds", default=60))
S3_CACHE_PREFIX_TTL_SECONDS = float(CONFIG.y("s3.cache.prefix_ttl_seconds", default=30))
# Compression settings for large objects (disabled by default, enable for storage savings).
S3_COMPRESSION_ENABLED = CONFIG.y_bool("s3.compression.enabled", default=False)
S3_COMPRESSION_MIN_SIZE = int(CONFIG.y("s3.compression.min_size", default=1024 * 1024))  # 1MB
S3_COMPRESSION_LEVEL = int(CONFIG.y("s3.compression.level", default=6))  # zlib level 1-9
# Base directory for LMDB volume data. Override with P2_STORAGE__ROOT for local dev.
STORAGE_ROOT = CONFIG.y("storage.root", default="/storage")

# ---------------------------------------------------------------------------
# Volume Pool (Fixed-Size Preallocated .bin files)
# ---------------------------------------------------------------------------
# Max size of a single volume file before it is sealed (default 10 GiB).
VOLUME_SIZE_BYTES = int(CONFIG.y("storage.volume_size_bytes", default=10 * 1024 * 1024 * 1024))
# Number of concurrently active write volumes per process.
VOLUME_ACTIVE_POOL_SIZE = max(1, int(CONFIG.y("storage.volume_active_pool_size", default=4)))
# Sealed volume live-byte ratio below which compaction triggers (0.0–1.0).
VOLUME_COMPACT_THRESHOLD = float(CONFIG.y("storage.volume_compact_threshold", default=0.30))
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

_allowed_hosts = CONFIG.y('allowed_hosts', 'localhost,127.0.0.1,[::1]')
ALLOWED_HOSTS = ['*'] if DEBUG else [host.strip() for host in str(_allowed_hosts).split(',') if host.strip()]
INTERNAL_IPS = ['127.0.0.1']

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    # Third-party
    'ninja',
    'ninja_jwt',
    'ninja_jwt.token_blacklist',  # lets us revoke refresh tokens (see p2/auth/mfa_api.py)
    'django_filters',
    'crispy_forms',
    'crispy_bootstrap4',
    # django-allauth — social/SSO login (any provider). Credentials for each
    # provider are configured as SocialApp rows via /_/admin/socialaccount/socialapp/,
    # no code changes needed to add a new provider once its provider app is listed here.
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.microsoft',
    'allauth.socialaccount.providers.github',
    # allauth.mfa — TOTP two-factor auth. We only use its Authenticator model
    # and TOTP/RecoveryCodes helpers (allauth.mfa.totp / .recovery_codes);
    # its own session/HTML views are not mounted — p2's JWT login flow calls
    # into those helpers directly from p2/auth/mfa_api.py instead. See
    # docs/sso-and-2fa-setup.md for the enrollment/verification flow.
    'allauth.mfa',
    # p2 - Core Components
    'p2.core.apps.P2CoreConfig',
    'p2.api.apps.P2APIConfig',
    'p2.s3.apps.P2S3Config',
    'p2.serve.apps.P2ServeConfig',
    'p2.log.apps.P2LogConfig',
    'p2.ui.apps.P2UIConfig',
    # p2 - Components
    'p2.components.quota.apps.P2QuotaComponentConfig',
    'p2.components.image.apps.P2ImageComponentConfig',
    'p2.components.public_access.apps.P2PublicAccessComponentConfig',
    'p2.components.replication.apps.P2ReplicationComponentConfig',
    'p2.components.expire.apps.P2ExpireComponentConfig',
    # p2 - Storage
    'p2.storage.local.apps.P2LocalStorageConfig',
    'p2.storage.s3.apps.P2S3StorageConfig',
]

MIDDLEWARE = [
    'p2.s3.middleware.S3RoutingMiddleware',  # MUST be first - handles S3 auth + routing
    'p2.core.middleware.HealthCheckMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'p2.core.middleware.S3AuthPreserveMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.http.ConditionalGetMiddleware',
    'p2.api.middleware.ApiCSRFExemptMiddleware',  # skip CSRF for JWT-based API paths
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

ROOT_URLCONF = 'p2.root.urls'
APPEND_SLASH = False

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

ASGI_APPLICATION = 'p2.core.asgi.application'

DATA_UPLOAD_MAX_MEMORY_SIZE = 536870912

# ---------------------------------------------------------------------------
# Database — Turso (libSQL) async-capable engine
# ---------------------------------------------------------------------------

_libsql_sync_url = CONFIG.y('libsql.sync_url', '')
_db_path = CONFIG.y('libsql.file', os.path.join(BASE_DIR, 'p2-control.db'))

if _libsql_sync_url:
    # Turso / embedded replica mode — needs file:// URI
    DATABASES = {
        'default': {
            'ENGINE': 'libsql.db.backends.sqlite3',
            'NAME': f'file:{_db_path}',
            'OPTIONS': {
                'sync_url': _libsql_sync_url,
                'auth_token': CONFIG.y('libsql.auth_token', ''),
            },
        }
    }
else:
    # Local dev — plain SQLite (no Turso connection needed)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': _db_path,
        }
    }

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ---------------------------------------------------------------------------
# Cache — Django 5.x built-in Redis backend (replaces django-redis)
# ---------------------------------------------------------------------------

_redis_password = CONFIG.y('redis.password', '')
_redis_auth = f':{_redis_password}@' if _redis_password else ''
REDIS_URL = CONFIG.y(
    'redis.url',
    f"redis://{_redis_auth}{CONFIG.y('redis.host', 'localhost')}:6379"
    f"/{CONFIG.y('redis.cache_db', '0')}"
)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': REDIS_URL,
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_SAVE_EVERY_REQUEST = False  # Only save when session data actually changes
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = CONFIG.y_bool('security.session_cookie_secure', default=not DEBUG and not TEST)
CSRF_COOKIE_SECURE = CONFIG.y_bool('security.csrf_cookie_secure', default=not DEBUG and not TEST)

CSRF_TRUSTED_ORIGINS = CONFIG.y('csrf_trusted_origins', 'http://localhost,http://127.0.0.1').split(',')

# ---------------------------------------------------------------------------
# ARQ task queue (replaces Celery)
# ---------------------------------------------------------------------------

ARQ_REDIS_URL = CONFIG.y(
    'redis.arq_url',
    f"redis://{_redis_auth}{CONFIG.y('redis.host', 'localhost')}:6379"
    f"/{CONFIG.y('redis.message_queue_db', '1')}"
)

ARQ_WORKER_SETTINGS = {
    'max_jobs': 50,
    'job_timeout': 300,
    'max_tries': 5,
}

# ---------------------------------------------------------------------------
# OpenTelemetry
# ---------------------------------------------------------------------------

OTEL_ENDPOINT = CONFIG.y('otel.endpoint', os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://localhost:4317'))
OTEL_SERVICE_NAME = CONFIG.y('otel.service_name', os.getenv('OTEL_SERVICE_NAME', 'p2'))

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

LOGIN_URL = 'auth_login'
LOGIN_REDIRECT_URL = '/'

# ---------------------------------------------------------------------------
# django-allauth — social/SSO login (Google, Microsoft, GitHub, and any
# other provider from allauth.socialaccount.providers.*).
# ---------------------------------------------------------------------------
# We only use allauth for the social login handshake, not for local
# registration/password management — p2 already has its own login view
# (P2LoginView) and its own JWT issuance (ninja-jwt) for the SPA. Keep
# allauth's own account views disabled/unused; the "auth" for a normal user
# is JWT, minted by our SocialAccountAdapter after allauth completes the
# provider OAuth dance (see p2/auth/adapters.py).
SITE_ID = 1
SOCIALACCOUNT_ADAPTER = 'p2.auth.adapters.P2SocialAccountAdapter'
SOCIALACCOUNT_LOGIN_ON_GET = True  # skip the intermediate "confirm" page, redirect straight to provider
SOCIALACCOUNT_STORE_TOKENS = False  # we don't need to keep provider access tokens around
# Local (non-social) allauth account features are not used — p2 has its own
# login/password views — but the account app must stay installed since
# socialaccount depends on it.
ACCOUNT_LOGIN_METHODS = {'username', 'email'}
ACCOUNT_EMAIL_VERIFICATION = 'none'
ACCOUNT_ADAPTER = 'p2.auth.adapters.P2AccountAdapter'

# Per-provider scopes. Client id/secret are NOT set here — they are configured
# per-deployment as SocialApp rows via /_/admin/socialaccount/socialapp/,
# so enabling a new provider for a given deployment is a config-only change
# (add credentials in the admin), not a code change.
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'},
        'OAUTH_PKCE_ENABLED': True,
    },
    'microsoft': {
        'TENANT': CONFIG.y('sso.microsoft.tenant', 'common'),
    },
    'github': {
        'SCOPE': ['user:email'],
    },
}

# ---------------------------------------------------------------------------
# allauth.mfa — TOTP two-factor auth (alternative to SSO; a user can enable
# 2FA on their own local/password account instead of using a social login).
# ---------------------------------------------------------------------------
MFA_TOTP_ISSUER = CONFIG.y('mfa.totp_issuer', 'p2 Storage')
# Allow ±1 time step (±30 seconds) clock skew for authenticator apps (RFC 6238).
# Each extra step adds another valid code at any instant, which widens the
# window for online guessing.
MFA_TOTP_TOLERANCE = int(CONFIG.y('mfa.totp_tolerance', default=1))
# A short-lived, single-use "MFA challenge" token is minted after password
# auth succeeds for a user with 2FA enabled, and must be exchanged (together
# with a valid TOTP/recovery code) for the real ninja-jwt pair within this
# window. See p2/auth/mfa_api.py: _issue_mfa_challenge / _consume_mfa_challenge.
MFA_CHALLENGE_TTL_SECONDS = int(CONFIG.y('mfa.challenge_ttl_seconds', default=300))
# Never set MFA_TOTP_INSECURE_BYPASS_CODE outside of local development —
# allauth itself refuses to honor it unless DEBUG=True.

# authlib OIDC configuration (legacy — superseded by allauth above, kept
# for the single-provider deployments already configured via oidc.* env vars)
OIDC_ENABLED = CONFIG.y_bool('oidc.enabled')
AUTHLIB_OAUTH_CLIENTS = {
    'oidc': {
        'client_id': CONFIG.y('oidc.client_id', ''),
        'client_secret': CONFIG.y('oidc.client_secret', ''),
        # OIDC Discovery endpoint — authlib resolves all endpoints automatically
        'server_metadata_url': CONFIG.y('oidc.discovery_url', ''),
        'client_kwargs': {
            'scope': 'openid email profile',
            'code_challenge_method': 'S256',  # PKCE
        },
    }
}

# ---------------------------------------------------------------------------
# REST Framework (Removed - Using Django Ninja)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------

STATIC_URL = '/_/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

CRISPY_TEMPLATE_PACK = 'bootstrap4'
CRISPY_ALLOWED_TEMPLATE_PACKS = 'bootstrap4'

VERSION = __version__

# ---------------------------------------------------------------------------
# Logging (stdlib — OTel LoggingInstrumentor will correlate with traces)
# ---------------------------------------------------------------------------

import warnings
warnings.filterwarnings("ignore", message="StreamingHttpResponse must consume synchronous iterators")

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'p2.s3.middleware': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
        'p2.s3.views.objects': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
        'p2.s3.engine': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
        'p2': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
        'django': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
        'django.contrib.sessions': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
        'arq': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
        'grpc': {'handlers': ['console'], 'level': 'WARNING', 'propagate': False},
    },
}

# ---------------------------------------------------------------------------
# Test overrides
# ---------------------------------------------------------------------------

if TEST:
    VOLUME_SIZE_BYTES = 10 * 1024 * 1024  # 10 MiB for tests (prevents huge allocations via posix_fallocate)
    VOLUME_ACTIVE_POOL_SIZE = 2           # 2 active volumes for tests

# ---------------------------------------------------------------------------
# Debug toolbar (dev only)
# ---------------------------------------------------------------------------

if DEBUG:
    INTERNAL_IPS = ['127.0.0.1', '::1']
    try:
        import debug_toolbar  # noqa: F401
        import django_extensions  # noqa: F401
        INSTALLED_APPS += ['debug_toolbar', 'django_extensions']
        MIDDLEWARE.append('debug_toolbar.middleware.DebugToolbarMiddleware')
    except ImportError:
        pass

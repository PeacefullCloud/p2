"""Root NinjaAPI instance for p2 control plane."""
from ninja import NinjaAPI

from ninja_jwt.authentication import JWTAuth
from ninja.security import django_auth

from p2.api.endpoints import router_user, router_key, router_config
from p2.auth.mfa_api import router_login, router_mfa
from p2.core.api.endpoints import router_volume, router_storage
from p2.serve.api.endpoints import router_serve
from p2.core.api.auth_policy_api import router_auth_policy
from p2.core.api.sso_api import router_sso
from p2.core.api.acl_api import router_acl

from ninja_extra.router import Router as _ExtraRouter
from ninja_jwt.routers.verify import verify_router
from ninja_jwt.schema_control import SchemaControl
from ninja_jwt.settings import api_settings as _jwt_settings

_jwt_schema = SchemaControl(_jwt_settings)

# Refresh only. ninja-jwt's stock obtain_pair_router also exposes /pair, a
# public password-only token mint that skips the 2FA challenge and the auth
# policy checks in /auth/login. Do not mount it.
token_refresh_router = _ExtraRouter()


@token_refresh_router.post(
    "/refresh",
    response=_jwt_schema.obtain_pair_refresh_schema.get_response_schema(),
    url_name="token_refresh",
    operation_id="token_refresh",
    auth=None,
)
def refresh_token(request, refresh_token: _jwt_schema.obtain_pair_refresh_schema):
    return refresh_token.to_response_schema()


# Require JWT auth by default for all API endpoints, or session-based for the UI.
api = NinjaAPI(
    title="p2 API",
    version="1.0.0",
    description="p2 S3 Control Plane API",
    auth=[JWTAuth(), django_auth],
)

# Authentication Endpoints (Simple JWT)
api.add_router("/auth/token", token_refresh_router)
api.add_router("/auth/token/verify", verify_router)
# Password login + optional TOTP 2FA gate. The SPA should call /auth/login
# (there is intentionally no /auth/token/pair), since only this endpoint knows to
# hold back the JWT pair and issue an MFA challenge when the user has 2FA
# enabled. Enrollment/verification endpoints (setup/confirm/status/disable/
# verify) live under /auth/mfa/*. See p2/auth/mfa_api.py.
api.add_router("/auth", router_login)
api.add_router("/auth/mfa", router_mfa)

# Register all subsystem routers
api.add_router("/system/user", router_user)
api.add_router("/system/key", router_key)
api.add_router("/system/config", router_config)
api.add_router("/core/volume", router_volume)
api.add_router("/core/storage", router_storage)
api.add_router("/tier0/policy", router_serve)
api.add_router("/system/auth-policy", router_auth_policy)
api.add_router("/system/sso-providers", router_sso)
api.add_router("/core", router_acl)

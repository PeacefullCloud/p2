"""SSO Provider Management API (Ninja).

Allows superadmins to configure and manage SocialApp entries
for OAuth2/OIDC providers directly from the Settings UI.
"""
import logging
from typing import List, Optional

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount import providers
from django.conf import settings
from django.contrib.sites.models import Site
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from ninja import Router, Schema
from ninja.errors import HttpError

from p2.core.auth_policy import SSOSettings

LOGGER = logging.getLogger(__name__)

router_sso = Router(tags=["system-sso-providers"])


class SocialAppSchema(Schema):
    id: int
    provider: str
    name: str
    client_id: str
    callback_url: str


class SocialAppCreateSchema(Schema):
    provider: str
    name: str
    client_id: str
    client_secret: str


class SocialAppUpdateSchema(Schema):
    name: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class AvailableProviderSchema(Schema):
    id: str
    name: str
    callback_path: str


class PublicProviderSchema(Schema):
    id: str
    name: str
    login_url: str


class SSOSettingsSchema(Schema):
    allowed_email_domains: str = ""
    allow_jit_signup: bool = False


def _normalize_domains(raw: str) -> str:
    seen = []
    for part in (raw or "").replace("\n", ",").split(","):
        domain = part.strip().lower().lstrip("@")
        if not domain:
            continue
        if "." not in domain or " " in domain or "/" in domain or "@" in domain:
            raise HttpError(400, f"'{part.strip()}' is not a valid email domain.")
        if domain not in seen:
            seen.append(domain)
    return ", ".join(seen)


def _require_superuser(request):
    if not getattr(request.user, "is_authenticated", False) or not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Superuser privileges required.")


def _callback_url_for(request, provider_id: str) -> str:
    host = request.get_host()
    proto = "https" if request.is_secure() else "http"
    return f"{proto}://{host}/_/accounts/{provider_id}/login/callback/"


@router_sso.get("/public/", response=List[PublicProviderSchema], auth=None)
def public_providers(request):
    """Configured SSO providers for the login page (no auth required).

    Only providers that a superadmin has actually created a SocialApp for
    are returned, so the login page never shows a dead provider button.
    """
    apps = SocialApp.objects.all().order_by("name")
    return [
        PublicProviderSchema(
            id=app.provider,
            name=app.name,
            login_url=f"/_/accounts/{app.provider}/login/",
        )
        for app in apps
    ]


@router_sso.get("/settings/", response=SSOSettingsSchema)
def get_sso_settings(request):
    _require_superuser(request)
    cfg = SSOSettings.load()
    return SSOSettingsSchema(
        allowed_email_domains=cfg.allowed_email_domains,
        allow_jit_signup=cfg.allow_jit_signup,
    )


@router_sso.put("/settings/", response=SSOSettingsSchema)
def update_sso_settings(request, payload: SSOSettingsSchema):
    _require_superuser(request)
    cfg = SSOSettings.load()
    cfg.allowed_email_domains = _normalize_domains(payload.allowed_email_domains)
    cfg.allow_jit_signup = payload.allow_jit_signup
    cfg.save()
    LOGGER.info("SSO settings updated by %s: domains=%r jit=%s",
                request.user.get_username(), cfg.allowed_email_domains, cfg.allow_jit_signup)
    return SSOSettingsSchema(
        allowed_email_domains=cfg.allowed_email_domains,
        allow_jit_signup=cfg.allow_jit_signup,
    )


@router_sso.get("/", response=List[SocialAppSchema])
def list_providers(request):
    _require_superuser(request)
    apps = SocialApp.objects.all().order_by("name")
    result = []
    for app in apps:
        result.append(
            SocialAppSchema(
                id=app.id,
                provider=app.provider,
                name=app.name,
                client_id=app.client_id,
                callback_url=_callback_url_for(request, app.provider),
            )
        )
    return result


@router_sso.get("/available/", response=List[AvailableProviderSchema])
def available_providers(request):
    """List OAuth providers available in the running environment."""
    _require_superuser(request)
    provider_classes = providers.registry.get_class_list()
    return [
        AvailableProviderSchema(
            id=p.id,
            name=p.name,
            callback_path=f"/_/accounts/{p.id}/login/callback/",
        )
        for p in provider_classes
    ]


@router_sso.post("/", response=SocialAppSchema)
def create_provider(request, payload: SocialAppCreateSchema):
    _require_superuser(request)
    if SocialApp.objects.filter(provider=payload.provider).exists():
        raise HttpError(400, f"Provider '{payload.provider}' is already configured.")

    app = SocialApp.objects.create(
        provider=payload.provider,
        name=payload.name,
        client_id=payload.client_id,
        secret=payload.client_secret,
    )
    site_id = getattr(settings, "SITE_ID", 1)
    site = Site.objects.filter(id=site_id).first() or Site.objects.first()
    if site:
        app.sites.add(site)

    return SocialAppSchema(
        id=app.id,
        provider=app.provider,
        name=app.name,
        client_id=app.client_id,
        callback_url=_callback_url_for(request, app.provider),
    )


@router_sso.put("/{app_id}/", response=SocialAppSchema)
def update_provider(request, app_id: int, payload: SocialAppUpdateSchema):
    _require_superuser(request)
    app = get_object_or_404(SocialApp, id=app_id)
    if payload.name is not None:
        app.name = payload.name
    if payload.client_id is not None:
        app.client_id = payload.client_id
    if payload.client_secret is not None and payload.client_secret.strip():
        app.secret = payload.client_secret
    app.save()

    return SocialAppSchema(
        id=app.id,
        provider=app.provider,
        name=app.name,
        client_id=app.client_id,
        callback_url=_callback_url_for(request, app.provider),
    )


@router_sso.delete("/{app_id}/")
def delete_provider(request, app_id: int):
    _require_superuser(request)
    app = get_object_or_404(SocialApp, id=app_id)
    app.delete()
    return {"ok": True}

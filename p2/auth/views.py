"""p2 authentication views — async-native login + OIDC."""
import logging

from asgiref.sync import sync_to_async
from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.auth.forms import AuthenticationForm
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View

from p2.auth.adapters import SPA_LOGIN_PATH

LOGGER = logging.getLogger(__name__)

oauth = OAuth()
oauth.register(
    name='oidc',
    server_metadata_url=settings.AUTHLIB_OAUTH_CLIENTS['oidc']['server_metadata_url'],
    client_id=settings.AUTHLIB_OAUTH_CLIENTS['oidc']['client_id'],
    client_secret=settings.AUTHLIB_OAUTH_CLIENTS['oidc']['client_secret'],
    client_kwargs=settings.AUTHLIB_OAUTH_CLIENTS['oidc']['client_kwargs'],
)

User = get_user_model()


def _session_login_blocked(user) -> bool:
    """True if *user* must not get a password-only Django session.

    A session is accepted by the API (django_auth) and the admin, so handing
    one out here would bypass the TOTP challenge and auth policy that
    /api/v1/auth/login enforces. Those users must sign in through the SPA.
    """
    from p2.auth.mfa_api import _totp_authenticator
    from p2.core.auth_policy import AuthPolicy, password_change_required, resolve_policy

    if password_change_required(user):
        return True
    if _totp_authenticator(user) is not None:
        return True
    if user.is_superuser:
        return False
    return resolve_policy(user) != AuthPolicy.Requirement.NONE


def _safe_next(request: HttpRequest, candidate: str) -> str:
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure(),
    ):
        return candidate
    return settings.LOGIN_REDIRECT_URL


class P2LoginView(View):
    """Async-native login view — correctly sets the session cookie under ASGI/uvicorn.

    Django's built-in LoginView is sync-only. Under ASGI it runs in a thread pool
    via async_to_sync, which causes SessionMiddleware to lose the Set-Cookie header
    on the response. This view is fully async so the session save and cookie are
    handled in the same async context as the middleware.
    """

    async def get(self, request: HttpRequest) -> HttpResponse:
        # The HTML form template was never shipped; the SPA owns the sign-in UI.
        return redirect(SPA_LOGIN_PATH)

    async def post(self, request: HttpRequest) -> HttpResponse:
        form = AuthenticationForm(request, data=request.POST)
        next_url = _safe_next(request, request.POST.get('next') or request.GET.get('next') or '')

        if not await sync_to_async(form.is_valid)():
            return redirect(SPA_LOGIN_PATH)

        user = form.get_user()
        if await sync_to_async(_session_login_blocked)(user):
            return HttpResponse(
                'This account requires a password change, two-factor or SSO sign-in. Please use the main login page.',
                status=403, content_type='text/plain',
            )
        await sync_to_async(login)(request, user)
        return redirect(next_url)


def oidc_login(request: HttpRequest) -> HttpResponse:
    """Redirect to OIDC provider with PKCE code challenge."""
    if not settings.OIDC_ENABLED:
        raise Http404
    redirect_uri = request.build_absolute_uri(reverse('p2_auth:oidc_callback'))
    return oauth.oidc.authorize_redirect(request, redirect_uri)


def oidc_callback(request: HttpRequest) -> HttpResponse:
    """Handle OIDC callback: exchange code, create/update user, mint a JWT.

    Ends in the same auth-policy gate as allauth social login
    (p2.auth.adapters._build_jwt_redirect) rather than a Django session, so
    forced MFA enrollment applies and no session bypasses 2FA.
    """
    if not settings.OIDC_ENABLED:
        raise Http404
    try:
        token = oauth.oidc.authorize_access_token(request)
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.warning("OIDC callback failed: %s", exc)
        return redirect(settings.LOGIN_URL)

    userinfo = token.get('userinfo') or oauth.oidc.userinfo(token=token)
    if not userinfo:
        LOGGER.warning("OIDC callback: no userinfo returned")
        return redirect(settings.LOGIN_URL)

    email = userinfo.get('email', '')
    sub = userinfo.get('sub', '')

    if not email and not sub:
        LOGGER.warning("OIDC callback: userinfo missing email and sub")
        return redirect(settings.LOGIN_URL)

    # An unverified email is attacker-controlled on many IdPs; never use it as
    # an identity.
    if email and userinfo.get('email_verified') is not True:
        LOGGER.warning("OIDC callback: rejected unverified email")
        return redirect(settings.LOGIN_URL)

    username = email or sub
    existing = User.objects.filter(username=username).first()
    if existing is not None and (existing.is_staff or existing.is_superuser):
        # Matching on username alone must not hand a privileged local account
        # to whoever controls that email at the IdP.
        LOGGER.warning("OIDC callback: refusing to link privileged account %s", username)
        return redirect(settings.LOGIN_URL)
    if existing is not None and not existing.is_active:
        return redirect(settings.LOGIN_URL)

    user, created = User.objects.get_or_create(
        username=username,
        defaults={
            'email': email,
            'first_name': userinfo.get('given_name', ''),
            'last_name': userinfo.get('family_name', ''),
        },
    )
    if created:
        user.set_unusable_password()
        user.save(update_fields=['password'])
    else:
        updated = False
        if email and user.email != email:
            user.email = email
            updated = True
        first_name = userinfo.get('given_name', '')
        last_name = userinfo.get('family_name', '')
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            updated = True
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            updated = True
        if updated:
            user.save(update_fields=['email', 'first_name', 'last_name'])

    LOGGER.debug("OIDC login: user=%s created=%s", username, created)

    from p2.auth.adapters import _build_jwt_redirect
    return redirect(_build_jwt_redirect(user))

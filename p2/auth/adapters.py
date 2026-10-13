"""django-allauth adapters that bridge social login into p2's JWT auth.

p2's SPA (ui/) is JWT-based (ninja-jwt access/refresh tokens in localStorage),
not session-based. django-allauth authenticates the user into a Django
*session* by default. P2AccountAdapter overrides the point where allauth
decides "where does the browser go after login" (get_login_redirect_url) and
sends it back to the SPA's login page with a one-time code that LoginPage.vue
exchanges for a JWT pair over POST, so social login and password login both
end up in the same authenticated SPA state.

Adding a new provider requires no changes to this file — only:
  1. Add 'allauth.socialaccount.providers.<provider>' to INSTALLED_APPS.
  2. Create a SocialApp row for it via /_/admin/socialaccount/socialapp/.
"""
import logging
from urllib.parse import urlencode

from allauth.account.adapter import DefaultAccountAdapter
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import HttpRequest, HttpResponseRedirect

from p2.core.auth_policy import SSOSettings

LOGGER = logging.getLogger(__name__)

# Where the SPA's login page lives. After SSO it reads `sso_code` (exchanged for
# tokens over POST) or `sso_error` (a reason code to show) from the query.
SPA_LOGIN_PATH = '/login'


def _build_jwt_redirect(user) -> str:
    """Return the SPA URL to send the browser to after a successful SSO login.

    No token ever appears in the URL: it carries only an opaque, single-use
    ``sso_code`` that the SPA exchanges over POST (/api/v1/auth/sso/exchange).
    Policy enforcement happens at exchange time too, so the code is bound to
    the user, not to an outcome.
    """
    from p2.auth.mfa_api import _issue_sso_code
    try:
        code = _issue_sso_code(user)
    except Exception:
        LOGGER.exception("Could not issue SSO exchange code; denying")
        return f'{SPA_LOGIN_PATH}?{urlencode({"sso_error": "login_failed"})}'
    LOGGER.debug("SSO login: issued exchange code for user=%s", user.get_username())
    return f'{SPA_LOGIN_PATH}?{urlencode({"sso_code": code})}'


def _sso_deny(code: str):
    """Abort the allauth flow and send the browser to the SPA login page with a
    reason code, instead of one of allauth's own HTML error pages."""
    LOGGER.warning("SSO sign-in denied: %s", code)
    raise ImmediateHttpResponse(HttpResponseRedirect(f'{SPA_LOGIN_PATH}?{urlencode({"sso_error": code})}'))


def _verified_emails(sociallogin) -> list[str]:
    """Emails the provider itself vouches for. Unverified ones are ignored:
    some providers (e.g. Microsoft multi-tenant) let the account holder set
    any address, so they must never identify or link a local user."""
    out = []
    for addr in getattr(sociallogin, 'email_addresses', None) or []:
        email = (getattr(addr, 'email', '') or '').strip().lower()
        if email and '@' in email and getattr(addr, 'verified', False) and email not in out:
            out.append(email)
    return out


class P2AccountAdapter(DefaultAccountAdapter):
    """Redirect post-login/signup to the SPA with a minted JWT pair instead
    of leaving the user on a bare Django session.
    """

    def get_login_redirect_url(self, request: HttpRequest) -> str:
        return _build_jwt_redirect(request.user)

    def get_signup_redirect_url(self, request: HttpRequest) -> str:
        return _build_jwt_redirect(request.user)


class P2SocialAccountAdapter(DefaultSocialAccountAdapter):
    """SSO sign-in rules.

    * An already-linked provider account signs in (identity = provider + its
      stable account id; email changes do not matter).
    * Otherwise the provider's *verified* email may link exactly one existing
      local user, once. After that the link is used, not the email.
    * With no matching user, a new one is created only if an admin turned on
      "create users on first SSO login" (off by default).
    * Every refusal goes back to /login?sso_error=<code>.
    """

    def pre_social_login(self, request: HttpRequest, sociallogin) -> None:
        if sociallogin.state.get('process') == 'connect':
            return
        if sociallogin.is_existing:
            if not sociallogin.user.is_active:
                _sso_deny('account_disabled')
            return

        cfg = SSOSettings.load()
        emails = _verified_emails(sociallogin)
        if not emails:
            _sso_deny('email_unverified')

        domains = cfg.domains()
        if domains and not any(e.rsplit('@', 1)[1] in domains for e in emails):
            _sso_deny('domain_not_allowed')

        query = Q()
        for email in emails:
            query |= Q(email__iexact=email)
        matches = list(get_user_model().objects.filter(query).distinct()[:2])
        if len(matches) > 1:
            _sso_deny('ambiguous_account')
        if matches:
            user = matches[0]
            if not user.is_active:
                _sso_deny('account_disabled')
            sociallogin.user = user
            sociallogin.save(request, connect=True)
            LOGGER.info("SSO: linked %s account to existing user %s",
                        sociallogin.account.provider, user.get_username())
            return

        if not cfg.allow_jit_signup:
            _sso_deny('no_account')

    def is_auto_signup_allowed(self, request: HttpRequest, sociallogin) -> bool:
        # pre_social_login has already enforced the domain list and verified
        # email; this only reflects the admin's create-on-first-login switch.
        return SSOSettings.load().allow_jit_signup

    def on_authentication_error(self, request, provider, error=None, exception=None, extra_context=None):
        LOGGER.warning("SSO provider error: provider=%s error=%s", getattr(provider, 'id', provider), error)
        _sso_deny('cancelled' if str(error) == 'cancelled' else 'provider_error')

    def get_connect_redirect_url(self, request: HttpRequest, socialaccount) -> str:
        return _build_jwt_redirect(socialaccount.user)

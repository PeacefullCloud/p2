from types import SimpleNamespace
from unittest import mock

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from p2.auth import mfa_api

User = get_user_model()
JSON = 'application/json'


class AuthHardeningTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('alice', email='a@example.com', password='pw-12345-x')

    def _enroll_totp(self, user):
        Authenticator.objects.create(user=user, type=Authenticator.Type.TOTP, data={'secret': 'x'})

    # ── session login must not bypass 2FA ───────────────────────────────
    def test_session_login_blocked_for_totp_user(self):
        self._enroll_totp(self.user)
        resp = self.client.post('/_/auth/login/', {'username': 'alice', 'password': 'pw-12345-x'})
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_session_login_allowed_without_2fa_or_policy(self):
        resp = self.client.post('/_/auth/login/', {'username': 'alice', 'password': 'pw-12345-x'})
        self.assertEqual(resp.status_code, 302)

    def test_session_login_ignores_offsite_next(self):
        resp = self.client.post(
            '/_/auth/login/',
            {'username': 'alice', 'password': 'pw-12345-x', 'next': 'https://evil.example/'})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp['Location'], '/')

    # ── legacy OIDC routes are off unless enabled ───────────────────────
    def test_oidc_routes_404_when_disabled(self):
        self.assertEqual(self.client.get('/_/oidc/login/').status_code, 404)
        self.assertEqual(self.client.get('/_/oidc/callback/').status_code, 404)

    # ── SSO exchange code ───────────────────────────────────────────────
    def test_sso_code_is_single_use_and_not_a_token(self):
        code = mfa_api._issue_sso_code(self.user)
        first = self.client.post('/api/v1/auth/sso/exchange', {'code': code}, content_type=JSON)
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()['access'])
        again = self.client.post('/api/v1/auth/sso/exchange', {'code': code}, content_type=JSON)
        self.assertEqual(again.status_code, 401)

    def test_sso_exchange_rejects_unknown_code(self):
        resp = self.client.post('/api/v1/auth/sso/exchange', {'code': 'nope'}, content_type=JSON)
        self.assertEqual(resp.status_code, 401)

    def test_sso_redirect_url_carries_no_tokens(self):
        from p2.auth.adapters import _build_jwt_redirect
        url = _build_jwt_redirect(self.user)
        self.assertIn('sso_code=', url)
        self.assertNotIn('access=', url)
        self.assertNotIn('refresh=', url)

    def test_sso_exchange_challenges_enrolled_user_under_mfa_policy(self):
        from p2.core.auth_policy import AuthPolicy
        AuthPolicy.objects.create(group=None, requirement=AuthPolicy.Requirement.MFA_REQUIRED)
        self._enroll_totp(self.user)
        code = mfa_api._issue_sso_code(self.user)
        data = self.client.post('/api/v1/auth/sso/exchange', {'code': code}, content_type=JSON).json()
        self.assertTrue(data['mfa_required'])
        self.assertFalse(data.get('access'))

    def test_sso_exchange_fails_closed_when_policy_errors(self):
        code = mfa_api._issue_sso_code(self.user)
        with mock.patch('p2.core.auth_policy.resolve_policy', side_effect=RuntimeError('boom')):
            resp = self.client.post('/api/v1/auth/sso/exchange', {'code': code}, content_type=JSON)
        self.assertEqual(resp.status_code, 503)

    # ── throttling ──────────────────────────────────────────────────────
    def test_login_is_throttled_after_repeated_failures(self):
        body = {'username': 'alice', 'password': 'wrong'}
        for _ in range(mfa_api._LOGIN_FAILS_PER_ACCOUNT_IP):
            self.assertEqual(self.client.post('/api/v1/auth/login', body, content_type=JSON).status_code, 401)
        self.assertEqual(self.client.post('/api/v1/auth/login', body, content_type=JSON).status_code, 429)
        good = {'username': 'alice', 'password': 'pw-12345-x'}
        self.assertEqual(self.client.post('/api/v1/auth/login', good, content_type=JSON).status_code, 429)

    def test_mfa_challenge_is_consumed_atomically(self):
        token = mfa_api._issue_mfa_challenge(self.user)
        self.assertTrue(mfa_api._delete_mfa_challenge(token))
        self.assertFalse(mfa_api._delete_mfa_challenge(token))

    # ── CSRF ────────────────────────────────────────────────────────────
    def test_session_authenticated_api_post_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        resp = client.post('/api/v1/auth/mfa/disable', {'password': 'pw-12345-x'}, content_type=JSON)
        self.assertEqual(resp.status_code, 403)

    def test_unauthenticated_login_endpoint_needs_no_csrf(self):
        client = Client(enforce_csrf_checks=True)
        resp = client.post('/api/v1/auth/login', {'username': 'alice', 'password': 'pw-12345-x'}, content_type=JSON)
        self.assertEqual(resp.status_code, 200)

    # ── revocation ──────────────────────────────────────────────────────
    def test_disabling_2fa_revokes_refresh_tokens(self):
        from ninja_jwt.token_blacklist.models import BlacklistedToken
        self._enroll_totp(self.user)
        pair = mfa_api._mint_jwt_pair(self.user)
        resp = self.client.post(
            '/api/v1/auth/mfa/disable', {'password': 'pw-12345-x'}, content_type=JSON,
            HTTP_AUTHORIZATION=f"Bearer {pair['access']}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(BlacklistedToken.objects.exists())
        refreshed = self.client.post('/api/v1/auth/token/refresh', {'refresh': pair['refresh']}, content_type=JSON)
        self.assertEqual(refreshed.status_code, 401)


class SocialLoginRuleTests(TestCase):
    """P2SocialAccountAdapter: link by verified email, create only if allowed,
    and send every refusal to /login?sso_error=<code>."""

    def setUp(self):
        from allauth.core.exceptions import ImmediateHttpResponse
        from p2.auth.adapters import P2SocialAccountAdapter
        from p2.core.auth_policy import SSOSettings
        self.Denied = ImmediateHttpResponse
        self.adapter = P2SocialAccountAdapter()
        self.cfg = SSOSettings.load()
        self.admin = User.objects.create_user(
            'admin2', email='Suleman@Inklik.com', password='pw-12345-x', is_superuser=True)

    def _login(self, *emails, existing_user=None, process='login'):
        """emails: (address, verified) tuples."""
        saved = mock.Mock()
        return SimpleNamespace(
            state={'process': process},
            is_existing=existing_user is not None,
            user=existing_user or SimpleNamespace(pk=None),
            email_addresses=[SimpleNamespace(email=e, verified=v) for e, v in emails],
            account=SimpleNamespace(provider='google'),
            save=saved,
        )

    def _denied_code(self, sociallogin):
        with self.assertRaises(self.Denied) as ctx:
            self.adapter.pre_social_login(mock.Mock(), sociallogin)
        loc = ctx.exception.response['Location']
        self.assertTrue(loc.startswith('/login?sso_error='), loc)
        return loc.split('sso_error=')[1]

    def test_verified_email_links_existing_admin_case_insensitively(self):
        login = self._login(('suleman@inklik.com', True))
        self.adapter.pre_social_login(mock.Mock(), login)
        self.assertEqual(login.user, self.admin)
        login.save.assert_called_once()
        self.assertTrue(login.save.call_args.kwargs['connect'])

    def test_unverified_email_never_links(self):
        self.assertEqual(self._denied_code(self._login(('suleman@inklik.com', False))), 'email_unverified')

    def test_domain_allowlist_blocks_other_domains(self):
        self.cfg.allowed_email_domains = 'inklik.com'
        self.cfg.save()
        self.assertEqual(self._denied_code(self._login(('x@evil.com', True))), 'domain_not_allowed')
        self.adapter.pre_social_login(mock.Mock(), self._login(('suleman@inklik.com', True)))

    def test_two_users_with_same_email_is_refused(self):
        User.objects.create_user('dup', email='suleman@inklik.com', password='pw-12345-x')
        self.assertEqual(self._denied_code(self._login(('suleman@inklik.com', True))), 'ambiguous_account')

    def test_disabled_user_is_refused(self):
        self.admin.is_active = False
        self.admin.save()
        self.assertEqual(self._denied_code(self._login(('suleman@inklik.com', True))), 'account_disabled')

    def test_unknown_email_denied_unless_jit_enabled(self):
        self.assertEqual(self._denied_code(self._login(('new@inklik.com', True))), 'no_account')
        self.assertFalse(self.adapter.is_auto_signup_allowed(mock.Mock(), None))
        self.cfg.allow_jit_signup = True
        self.cfg.save()
        self.adapter.pre_social_login(mock.Mock(), self._login(('new@inklik.com', True)))
        self.assertTrue(self.adapter.is_auto_signup_allowed(mock.Mock(), None))

    def test_already_linked_account_signs_in_regardless_of_email(self):
        login = self._login(('changed@elsewhere.com', True), existing_user=self.admin)
        self.adapter.pre_social_login(mock.Mock(), login)
        login.save.assert_not_called()

    def test_provider_error_redirects_to_login(self):
        with self.assertRaises(self.Denied) as ctx:
            self.adapter.on_authentication_error(mock.Mock(), SimpleNamespace(id='google'), error='cancelled')
        self.assertEqual(ctx.exception.response['Location'], '/login?sso_error=cancelled')


class SSOSettingsApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_user('root1', password='pw-12345-x', is_superuser=True)
        self.plain = User.objects.create_user('plain1', password='pw-12345-x')

    def _auth(self, user):
        return {'HTTP_AUTHORIZATION': f"Bearer {mfa_api._mint_jwt_pair(user)['access']}"}

    def test_superuser_can_read_and_update(self):
        url = '/api/v1/system/sso-providers/settings/'
        resp = self.client.put(
            url, {'allowed_email_domains': ' @Inklik.com, inklik.com ,x.org', 'allow_jit_signup': True},
            content_type=JSON, **self._auth(self.admin))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['allowed_email_domains'], 'inklik.com, x.org')
        got = self.client.get(url, **self._auth(self.admin)).json()
        self.assertTrue(got['allow_jit_signup'])

    def test_invalid_domain_rejected(self):
        resp = self.client.put(
            '/api/v1/system/sso-providers/settings/', {'allowed_email_domains': 'not a domain', 'allow_jit_signup': False},
            content_type=JSON, **self._auth(self.admin))
        self.assertEqual(resp.status_code, 400)

    def test_non_superuser_forbidden(self):
        resp = self.client.get('/api/v1/system/sso-providers/settings/', **self._auth(self.plain))
        self.assertEqual(resp.status_code, 403)


class GoogleFlowThroughAllauthTests(TestCase):
    """Drive allauth's real complete_social_login with a Google-shaped profile."""

    def setUp(self):
        from allauth.socialaccount.models import SocialApp
        from django.contrib.sites.models import Site
        self.app = SocialApp.objects.create(provider='google', name='Sign in with Google', client_id='x', secret='y')
        self.app.sites.add(Site.objects.get_current())
        self.admin = User.objects.create_user(
            'admin3', email='suleman@inklik.com', password='pw-12345-x', is_superuser=True, is_staff=True)
        # Migration 0002 seeds a default admin, so count relative to now.
        self.base_users = User.objects.count()

    def _complete(self, email, verified=True, uid='g-123'):
        from allauth.socialaccount.helpers import complete_social_login
        from allauth.socialaccount.providers import registry
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        request = RequestFactory().get('/_/accounts/google/login/callback/')
        request.META['SERVER_NAME'] = 'localhost'
        SessionMiddleware(lambda r: None).process_request(request)
        request.session.save()
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        request.user = AnonymousUser()
        setattr(request, '_messages', FallbackStorage(request))

        provider = registry.get_class('google')(request, app=self.app)
        data = {'sub': uid, 'email': email, 'email_verified': verified, 'name': 'S', 'given_name': 'S'}
        sociallogin = provider.sociallogin_from_response(request, data)
        sociallogin.state = {'process': 'login'}
        from allauth.core import context
        with context.request_context(request):
            return complete_social_login(request, sociallogin), request

    def test_admin_email_signs_in_as_existing_admin_without_signup_page(self):
        resp, _ = self._complete('Suleman@inklik.com')
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp['Location'].startswith('/login?sso_code='), resp['Location'])
        self.assertEqual(User.objects.count(), self.base_users)
        from allauth.socialaccount.models import SocialAccount
        link = SocialAccount.objects.get()
        self.assertEqual((link.user, link.uid), (self.admin, 'g-123'))

    def test_second_login_uses_the_link_even_if_email_changed(self):
        self._complete('suleman@inklik.com')
        self.admin.email = 'renamed@inklik.com'
        self.admin.save()
        resp, _ = self._complete('suleman@inklik.com')
        self.assertTrue(resp['Location'].startswith('/login?sso_code='))
        self.assertEqual(User.objects.count(), self.base_users)

    def test_unknown_email_goes_to_login_with_reason_not_signup_form(self):
        resp, _ = self._complete('stranger@inklik.com', uid='g-999')
        self.assertEqual(resp['Location'], '/login?sso_error=no_account')
        self.assertEqual(User.objects.count(), self.base_users)

    def test_jit_creates_user_when_enabled(self):
        from p2.core.auth_policy import SSOSettings
        cfg = SSOSettings.load()
        cfg.allow_jit_signup = True
        cfg.save()
        resp, _ = self._complete('newbie@inklik.com', uid='g-777')
        self.assertTrue(resp['Location'].startswith('/login?sso_code='), resp['Location'])
        newbie = User.objects.get(email='newbie@inklik.com')
        self.assertFalse(newbie.is_superuser)
        self.assertFalse(newbie.has_usable_password())

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from p2.auth import mfa_api
from p2.core.auth_policy import PasswordChangeRequired, password_change_required

User = get_user_model()
JSON = 'application/json'
NEW_PW = 'a-Much-Better-Pass-93!'


class ForcedPasswordChangeTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.get(username='admin')
        self.admin.set_password('admin')
        self.admin.save()
        PasswordChangeRequired.objects.get_or_create(user=self.admin)

    def _login(self, password='admin'):
        return self.client.post(
            '/api/v1/auth/login', {'username': 'admin', 'password': password}, content_type=JSON)

    def _change(self, token, new_password=NEW_PW):
        return self.client.post(
            '/api/v1/auth/password-change',
            {'password_change_token': token, 'new_password': new_password}, content_type=JSON)

    def test_migration_seeded_admin_is_flagged(self):
        # The data migration flags the seeded admin/admin account.
        self.assertTrue(password_change_required(self.admin))

    def test_password_login_issues_no_tokens_while_flagged(self):
        body = self._login().json()
        self.assertTrue(body['password_change_required'])
        self.assertTrue(body['password_change_token'])
        self.assertIsNone(body['access'])
        self.assertIsNone(body['refresh'])

    def test_change_clears_flag_and_signs_in(self):
        token = self._login().json()['password_change_token']
        resp = self._change(token)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()['access'])
        self.assertFalse(password_change_required(self.admin))
        self.assertEqual(self._login('admin').status_code, 401)
        self.assertTrue(self._login(NEW_PW).json()['access'])

    def test_token_is_single_use(self):
        token = self._login().json()['password_change_token']
        self.assertEqual(self._change(token).status_code, 200)
        self.assertEqual(self._change(token, 'Another-Strong-Pass-17!').status_code, 401)

    def test_rejects_same_or_weak_password_and_keeps_token_usable(self):
        token = self._login().json()['password_change_token']
        self.assertEqual(self._change(token, 'admin').status_code, 400)
        self.assertEqual(self._change(token, '123').status_code, 400)
        self.assertTrue(password_change_required(self.admin))
        self.assertEqual(self._change(token).status_code, 200)

    def test_unknown_token_rejected(self):
        self.assertEqual(self._change('nope').status_code, 401)

    def test_change_resumes_mfa_challenge_instead_of_issuing_tokens(self):
        Authenticator.objects.create(
            user=self.admin, type=Authenticator.Type.TOTP, data={'secret': 'x'})
        token = self._login().json()['password_change_token']
        body = self._change(token).json()
        self.assertTrue(body['mfa_required'])
        self.assertIsNone(body['access'])

    def test_sso_exchange_is_gated_then_resumes(self):
        code = mfa_api._issue_sso_code(self.admin)
        body = self.client.post('/api/v1/auth/sso/exchange', {'code': code}, content_type=JSON).json()
        self.assertTrue(body['password_change_required'])
        self.assertIsNone(body['access'])
        done = self._change(body['password_change_token']).json()
        self.assertTrue(done['access'])

    def test_session_login_blocked_while_flagged(self):
        resp = self.client.post('/_/auth/login/', {'username': 'admin', 'password': 'admin'})
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_password_change_revokes_refresh_tokens(self):
        from ninja_jwt.token_blacklist.models import BlacklistedToken
        refresh = mfa_api._mint_jwt_pair(self.admin)['refresh']
        token = self._login().json()['password_change_token']
        self._change(token)
        self.assertTrue(BlacklistedToken.objects.exists())
        resp = self.client.post(
            '/api/v1/auth/token/refresh', {'refresh': refresh}, content_type=JSON)
        self.assertEqual(resp.status_code, 401)

    def test_superuser_setting_password_clears_flag(self):
        boss = User.objects.create_superuser('boss', 'b@example.com', 'Boss-Pass-4455!')
        access = self.client.post(
            '/api/v1/auth/login', {'username': 'boss', 'password': 'Boss-Pass-4455!'},
            content_type=JSON).json()['access']
        resp = self.client.put(
            f'/api/v1/system/user/{self.admin.id}/', {'password': NEW_PW},
            content_type=JSON, HTTP_AUTHORIZATION=f'Bearer {access}')
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertFalse(password_change_required(self.admin))
        del boss

    def test_unflagged_user_logs_in_normally(self):
        User.objects.create_user('bob', password='Bob-Pass-9988!')
        body = self.client.post(
            '/api/v1/auth/login', {'username': 'bob', 'password': 'Bob-Pass-9988!'},
            content_type=JSON).json()
        self.assertTrue(body['access'])
        self.assertFalse(body['password_change_required'])


class SessionRevocationAndLoginRouteTests(TestCase):
    def setUp(self):
        cache.clear()

    def _superuser_token(self):
        User.objects.create_superuser('boss2', 'b2@example.com', 'Boss-Pass-4455!')
        return self.client.post(
            '/api/v1/auth/login', {'username': 'boss2', 'password': 'Boss-Pass-4455!'},
            content_type=JSON).json()['access']

    def test_admin_password_reset_revokes_refresh_tokens(self):
        victim = User.objects.create_user('victim', password='Old-Pass-1234!')
        refresh = mfa_api._mint_jwt_pair(victim)['refresh']
        resp = self.client.put(
            f'/api/v1/system/user/{victim.id}/', {'password': NEW_PW}, content_type=JSON,
            HTTP_AUTHORIZATION=f'Bearer {self._superuser_token()}')
        self.assertEqual(resp.status_code, 200, resp.content)
        refreshed = self.client.post(
            '/api/v1/auth/token/refresh', {'refresh': refresh}, content_type=JSON)
        self.assertEqual(refreshed.status_code, 401)

    def test_non_password_update_keeps_refresh_tokens(self):
        victim = User.objects.create_user('victim2', password='Old-Pass-1234!')
        refresh = mfa_api._mint_jwt_pair(victim)['refresh']
        self.client.put(
            f'/api/v1/system/user/{victim.id}/', {'email': 'v@example.com'}, content_type=JSON,
            HTTP_AUTHORIZATION=f'Bearer {self._superuser_token()}')
        refreshed = self.client.post(
            '/api/v1/auth/token/refresh', {'refresh': refresh}, content_type=JSON)
        self.assertEqual(refreshed.status_code, 200)

    def test_login_form_routes_redirect_to_spa(self):
        self.assertEqual(self.client.get('/_/auth/login/')['Location'], '/login')
        bad = self.client.post('/_/auth/login/', {'username': 'x', 'password': 'y'})
        self.assertEqual(bad.status_code, 302)
        self.assertEqual(bad['Location'], '/login')

    def test_migration_revokes_tokens_of_flagged_users(self):
        from importlib import import_module

        from django.apps import apps as django_apps
        from ninja_jwt.token_blacklist.models import BlacklistedToken

        user = User.objects.create_user('flagged', password='admin')
        PasswordChangeRequired.objects.create(user=user)
        other = User.objects.create_user('unflagged', password='Pw-1234-abcd!')
        mfa_api._mint_jwt_pair(user)
        mfa_api._mint_jwt_pair(other)
        import_module('p2.core.migrations.0007_revoke_flagged_user_tokens').revoke_tokens(
            django_apps, None)
        self.assertEqual(BlacklistedToken.objects.filter(token__user=user).count(), 1)
        self.assertEqual(BlacklistedToken.objects.filter(token__user=other).count(), 0)


class SelfServicePasswordChangeTests(TestCase):
    PW = 'Current-Pass-5566!'

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('carol', password=self.PW)
        pair = mfa_api._mint_jwt_pair(self.user)
        self.access, self.old_refresh = pair['access'], pair['refresh']

    def _change(self, current, new, access=None):
        headers = {'HTTP_AUTHORIZATION': f'Bearer {access or self.access}'}
        return self.client.post(
            '/api/v1/auth/change-password',
            {'current_password': current, 'new_password': new}, content_type=JSON, **headers)

    def test_requires_authentication(self):
        resp = self.client.post(
            '/api/v1/auth/change-password',
            {'current_password': self.PW, 'new_password': NEW_PW}, content_type=JSON)
        self.assertEqual(resp.status_code, 401)

    def test_change_returns_fresh_tokens_and_revokes_old_refresh(self):
        resp = self._change(self.PW, NEW_PW)
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(resp.json()['access'])
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(NEW_PW))
        old = self.client.post(
            '/api/v1/auth/token/refresh', {'refresh': self.old_refresh}, content_type=JSON)
        self.assertEqual(old.status_code, 401)
        new = self.client.post(
            '/api/v1/auth/token/refresh', {'refresh': resp.json()['refresh']}, content_type=JSON)
        self.assertEqual(new.status_code, 200)

    def test_wrong_current_password_rejected_and_throttled(self):
        for _ in range(5):
            self.assertEqual(self._change('wrong', NEW_PW).status_code, 400)
        self.assertEqual(self._change(self.PW, NEW_PW).status_code, 429)

    def test_weak_or_unchanged_password_rejected(self):
        self.assertEqual(self._change(self.PW, self.PW).status_code, 400)
        self.assertEqual(self._change(self.PW, '123').status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.PW))

    def test_sso_only_account_has_nothing_to_change(self):
        self.user.set_unusable_password()
        self.user.save()
        self.assertEqual(self._change('anything', NEW_PW).status_code, 400)


class InitialAdminSeedTests(TestCase):
    def _seed(self, **env):
        import os
        from importlib import import_module
        from unittest import mock

        from django.apps import apps as django_apps

        User.objects.filter(username='admin').delete()
        mod = import_module('p2.core.migrations.0002_default_admin')
        with mock.patch.dict(os.environ, env, clear=False):
            if not env:
                os.environ.pop('P2_ADMIN_PASSWORD', None)
            mod.create_default_admin(django_apps, None)
        return User.objects.get(username='admin')

    def test_env_password_is_used(self):
        admin = self._seed(P2_ADMIN_PASSWORD='Chosen-By-Operator-77!')
        self.assertTrue(admin.check_password('Chosen-By-Operator-77!'))

    def test_without_env_a_random_password_is_generated(self):
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            admin = self._seed()
        self.assertFalse(admin.check_password('admin'))
        self.assertIn('generated password', buf.getvalue())


class AdminRequirePasswordChangeTests(TestCase):
    def setUp(self):
        cache.clear()
        User.objects.create_superuser('boss3', 'b3@example.com', 'Boss-Pass-4455!')
        self.access = self.client.post(
            '/api/v1/auth/login', {'username': 'boss3', 'password': 'Boss-Pass-4455!'},
            content_type=JSON).json()['access']
        self.target = User.objects.create_user('dave', password='Dave-Pass-1234!')

    def _put(self, body):
        return self.client.put(
            f'/api/v1/system/user/{self.target.id}/', body, content_type=JSON,
            HTTP_AUTHORIZATION=f'Bearer {self.access}')

    def test_flagging_gates_login_and_revokes_sessions(self):
        refresh = mfa_api._mint_jwt_pair(self.target)['refresh']
        resp = self._put({'require_password_change': True})
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(resp.json()['password_change_required'])
        login = self.client.post(
            '/api/v1/auth/login', {'username': 'dave', 'password': 'Dave-Pass-1234!'},
            content_type=JSON).json()
        self.assertTrue(login['password_change_required'])
        self.assertIsNone(login['access'])
        refreshed = self.client.post(
            '/api/v1/auth/token/refresh', {'refresh': refresh}, content_type=JSON)
        self.assertEqual(refreshed.status_code, 401)

    def test_unflagging_restores_normal_login(self):
        self._put({'require_password_change': True})
        self._put({'require_password_change': False})
        self.assertFalse(password_change_required(self.target))

    def test_temporary_password_with_required_change_in_one_request(self):
        self._put({'password': 'Temp-Pass-8877!', 'require_password_change': True})
        self.assertTrue(password_change_required(self.target))
        login = self.client.post(
            '/api/v1/auth/login', {'username': 'dave', 'password': 'Temp-Pass-8877!'},
            content_type=JSON).json()
        self.assertTrue(login['password_change_required'])

    def test_unrelated_edit_keeps_existing_flag_and_sessions(self):
        self._put({'require_password_change': True})
        refresh = mfa_api._mint_jwt_pair(self.target)['refresh']
        self._put({'email': 'd@example.com', 'require_password_change': True})
        self.assertTrue(password_change_required(self.target))
        refreshed = self.client.post(
            '/api/v1/auth/token/refresh', {'refresh': refresh}, content_type=JSON)
        self.assertEqual(refreshed.status_code, 200)

    def test_non_superuser_cannot_flag(self):
        plain = mfa_api._mint_jwt_pair(self.target)['access']
        resp = self.client.put(
            f'/api/v1/system/user/{self.target.id}/', {'require_password_change': True},
            content_type=JSON, HTTP_AUTHORIZATION=f'Bearer {plain}')
        self.assertIn(resp.status_code, (401, 403))
        self.assertFalse(password_change_required(self.target))


class Migration0006FlaggingTests(TestCase):
    def _run(self, user):
        from importlib import import_module

        from django.apps import apps as django_apps
        PasswordChangeRequired.objects.all().delete()
        import_module('p2.core.migrations.0006_passwordchangerequired').flag_default_admin(
            django_apps, None)
        return password_change_required(user)

    def test_admin_with_default_password_is_flagged(self):
        admin = User.objects.get(username='admin')
        admin.set_password('admin')
        admin.save()
        self.assertTrue(self._run(admin))

    def test_admin_with_chosen_password_is_not_flagged(self):
        admin = User.objects.get(username='admin')
        admin.set_password('Chosen-By-Operator-77!')
        admin.save()
        self.assertFalse(self._run(admin))

    def test_other_users_with_password_admin_are_not_flagged(self):
        other = User.objects.create_user('someone', password='admin')
        self.assertFalse(self._run(other))

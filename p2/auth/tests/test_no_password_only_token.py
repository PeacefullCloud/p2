from django.contrib.auth import get_user_model
from django.test import TestCase


class PasswordOnlyTokenEndpointTests(TestCase):
    """The stock ninja-jwt /token/pair mints a JWT from a password alone,
    skipping the 2FA challenge and auth policy in /auth/login."""

    def test_token_pair_is_not_exposed(self):
        get_user_model().objects.create_user('alice', password='pw-12345-x')
        resp = self.client.post(
            '/api/v1/auth/token/pair',
            data={'username': 'alice', 'password': 'pw-12345-x'},
            content_type='application/json',
        )
        self.assertIn(resp.status_code, (404, 405))
        self.assertNotIn(b'access', resp.content)

    def test_refresh_still_available(self):
        resp = self.client.post(
            '/api/v1/auth/token/refresh',
            data={'refresh': 'not-a-token'},
            content_type='application/json',
        )
        self.assertIn(resp.status_code, (401, 422))

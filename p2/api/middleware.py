"""Middleware that skips CSRF only where it cannot apply.

CSRF protects ambient credentials (the session cookie). It does not apply to:

* requests authenticated with an ``Authorization: Bearer`` header, which a
  cross-site page cannot attach; and
* the unauthenticated login/token endpoints, which the SPA calls without any
  session or CSRF cookie.

Every other /api/ request, notably session-authenticated ones, keeps CSRF
checking (enforced by ninja's ``django_auth``).
"""
import re

_UNAUTHENTICATED_AUTH_PATHS = re.compile(
    r'^/api/v\d+/auth/('
    r'login|sso/exchange|password-change|'
    r'mfa/(verify|enroll-setup|enroll-confirm)|'
    r'token/(refresh|verify/verify)'
    r')/?$'
)


class ApiCSRFExemptMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/api/') and self._exempt(request):
            setattr(request, 'csrf_processing_done', True)
        return self.get_response(request)

    @staticmethod
    def _exempt(request) -> bool:
        if request.META.get('HTTP_AUTHORIZATION', '').startswith('Bearer '):
            return True
        return bool(_UNAUTHENTICATED_AUTH_PATHS.match(request.path))

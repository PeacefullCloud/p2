"""TOTP two-factor authentication API (ninja).

This sits in front of ninja-jwt's token issuance rather than replacing it:

  1. POST /api/v1/auth/login          — username + password.
       - If the user has no TOTP authenticator: mints and returns a normal
         ninja-jwt access/refresh pair immediately, same as calling
         /api/v1/auth/token/pair directly.
       - If the user *does* have TOTP enabled: password is verified, but no
         JWT is issued yet. Instead a short-lived, single-use "MFA challenge"
         id is returned. The client must immediately follow up with...
  2. POST /api/v1/auth/mfa/verify      — mfa_token + code (TOTP or a
         recovery code). A wrong code does NOT burn the challenge — the
         client may retry with the same mfa_token until it expires,
         succeeds, or hits the wrong-attempt limit. On success, the
         challenge is consumed (cannot be replayed) and the real
         ninja-jwt pair is minted and returned.

Enrollment (done once the user already holds a valid JWT, i.e. from
Settings in the SPA):
  3. POST /api/v1/auth/mfa/setup       — generates a new TOTP secret, returns
         the otpauth:// URI + an SVG QR code. Secret is cached server-side
         (not the Authenticator table) until confirmed via step 4.
  4. POST /api/v1/auth/mfa/confirm     — code -> activates the TOTP
         Authenticator + generates recovery codes (returned once, per
         allauth.mfa.RecoveryCodes semantics).
  5. POST /api/v1/auth/mfa/disable     — removes TOTP + recovery codes for
         the current user (requires a valid password to avoid a stolen
         access token silently disabling 2FA).
  6. GET  /api/v1/auth/mfa/status      — whether the current user has TOTP
         enabled.

All of this reuses allauth.mfa's own model (Authenticator) and its TOTP /
RecoveryCodes helper classes for secret generation, QR building, and code
validation — we do not reimplement TOTP math. We only replace allauth's own
views, which are session/HTML-form based and don't fit a JWT SPA.
"""
import logging
import re
import secrets

from allauth.mfa.adapter import get_adapter as get_mfa_adapter
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret, validate_totp_code
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.cache import cache
from ninja import Router, Schema
from ninja.errors import HttpError
from ninja_jwt.tokens import RefreshToken

LOGGER = logging.getLogger(__name__)
User = get_user_model()

router_login = Router(tags=["auth-login"])
router_mfa = Router(tags=["auth-mfa"])

_CHALLENGE_CACHE_PREFIX = 'p2:mfa:challenge:'
_PENDING_SECRET_CACHE_PREFIX = 'p2:mfa:pending_secret:'
_ATTEMPT_CACHE_PREFIX = 'p2:mfa:attempts:'

# How many wrong codes a single MFA challenge tolerates before it is
# discarded (forcing a fresh password login). The password was already
# verified to issue the challenge, so this is only a backstop against
# unbounded guessing on one challenge — not the primary rate limit.
_MAX_VERIFY_ATTEMPTS = 5


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LoginSchema(Schema):
    username: str
    password: str


class LoginResponseSchema(Schema):
    mfa_required: bool = False
    mfa_token: str | None = None
    mfa_setup_required: bool = False
    enrollment_token: str | None = None
    password_change_required: bool = False
    password_change_token: str | None = None
    access: str | None = None
    refresh: str | None = None


class SsoExchangeSchema(Schema):
    code: str


class PasswordChangeSchema(Schema):
    password_change_token: str
    new_password: str


class MfaVerifySchema(Schema):
    mfa_token: str
    code: str


class MfaConfirmSchema(Schema):
    code: str


class MfaDisableSchema(Schema):
    password: str


class MfaStatusSchema(Schema):
    enabled: bool


class MfaSetupResponseSchema(Schema):
    secret: str
    otpauth_url: str
    qr_svg: str


class MfaConfirmResponseSchema(Schema):
    recovery_codes: list[str]


class CurrentUserSchema(Schema):
    id: int
    username: str
    email: str
    is_superuser: bool
    is_staff: bool


def _revoke_refresh_tokens(user) -> None:
    """Blacklist every outstanding refresh token for *user*, so a security
    change (e.g. 2FA disabled) also cuts off sessions that already exist."""
    from ninja_jwt.token_blacklist.models import BlacklistedToken, OutstandingToken
    for outstanding in OutstandingToken.objects.filter(user=user):
        BlacklistedToken.objects.get_or_create(token=outstanding)


def _mint_jwt_pair(user) -> dict:
    refresh = RefreshToken.for_user(user)
    refresh['is_superuser'] = bool(user.is_superuser)
    refresh['is_staff'] = bool(user.is_staff)
    refresh['username'] = user.username
    return {'access': str(refresh.access_token), 'refresh': str(refresh)}


@router_login.get('/me', response=CurrentUserSchema)
def current_user(request):
    user = request.user
    if not getattr(user, 'is_authenticated', False):
        raise HttpError(401, "Not authenticated")
    return CurrentUserSchema(
        id=user.id,
        username=user.username,
        email=user.email or '',
        is_superuser=bool(user.is_superuser),
        is_staff=bool(user.is_staff),
    )


def _issue_mfa_challenge(user) -> str:
    """Create a single-use, short-lived token binding this login attempt to
    `user`, so /mfa/verify doesn't need the password again."""
    if _throttled('mfa-user', str(user.pk), _MFA_FAILS_PER_USER):
        raise HttpError(429, "Too many incorrect verification codes. Try again later.")
    token = secrets.token_urlsafe(32)
    cache.set(f'{_CHALLENGE_CACHE_PREFIX}{token}', user.pk, timeout=settings.MFA_CHALLENGE_TTL_SECONDS)
    return token


def _peek_mfa_challenge(token: str):
    """Return the User bound to a challenge token, or None, without
    consuming it — so a typo'd code doesn't burn the whole login attempt.
    The challenge is deleted only on success (see verify), on expiry, or
    after too many wrong guesses."""
    if not token:
        return None
    user_pk = cache.get(f'{_CHALLENGE_CACHE_PREFIX}{token}')
    if user_pk is None:
        return None
    return User.objects.filter(pk=user_pk, is_active=True).first()


def _delete_mfa_challenge(token: str) -> bool:
    """Burn a challenge. True only for the caller that actually removed it, so
    two concurrent verifications of one challenge cannot both succeed."""
    deleted = cache.delete(f'{_CHALLENGE_CACHE_PREFIX}{token}')
    cache.delete(f'{_ATTEMPT_CACHE_PREFIX}{token}')
    return bool(deleted)


# ---------------------------------------------------------------------------
# Failure throttling
# ---------------------------------------------------------------------------
# The per-challenge attempt cap only bounds guesses on one challenge; anyone
# holding the password could otherwise mint challenges forever. These counters
# are keyed on identity (account / client IP), not on a token.

_THROTTLE_PREFIX = 'p2:auth:fail:'
_THROTTLE_WINDOW_SECONDS = 15 * 60
_LOGIN_FAILS_PER_ACCOUNT_IP = 10
_LOGIN_FAILS_PER_ACCOUNT = 50
_LOGIN_FAILS_PER_IP = 100
_MFA_FAILS_PER_USER = 10
_DISABLE_FAILS_PER_USER = 5


def _client_ip(request) -> str:
    # REMOTE_ADDR only: X-Forwarded-For is client-controlled unless a trusted
    # proxy strips it, and a spoofable key would let attackers dodge the limit.
    return request.META.get('REMOTE_ADDR', '') or 'unknown'


def _throttle_key(scope: str, ident: str) -> str:
    return f'{_THROTTLE_PREFIX}{scope}:{ident}'


def _throttled(scope: str, ident: str, limit: int) -> bool:
    return (cache.get(_throttle_key(scope, ident)) or 0) >= limit


def _record_failure(scope: str, ident: str) -> None:
    key = _throttle_key(scope, ident)
    cache.add(key, 0, timeout=_THROTTLE_WINDOW_SECONDS)
    try:
        cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=_THROTTLE_WINDOW_SECONDS)


def _clear_failures(scope: str, ident: str) -> None:
    cache.delete(_throttle_key(scope, ident))


def _normalize_code(code: str) -> str:
    """Strip whitespace/dashes users often copy-paste from authenticator
    apps ("123 456", "123-456") before comparing."""
    return re.sub(r'[\s\-]+', '', code or '')


def _totp_authenticator(user) -> Authenticator | None:
    return Authenticator.objects.filter(user=user, type=Authenticator.Type.TOTP).first()


def _validate_second_factor(user, code: str) -> bool:
    """Accept either a live TOTP code or one of the user's recovery codes."""
    totp_auth = _totp_authenticator(user)
    if totp_auth and TOTP(totp_auth).validate_code(code):
        return True
    recovery_auth = Authenticator.objects.filter(
        user=user, type=Authenticator.Type.RECOVERY_CODES,
    ).first()
    if recovery_auth and RecoveryCodes(recovery_auth).validate_code(code):
        return True
    return False


_ENROLLMENT_CACHE_PREFIX = 'p2:mfa:enrollment:'


def _issue_enrollment_token(user) -> str:
    """Like an MFA challenge, but for forced TOTP enrollment."""
    token = secrets.token_urlsafe(32)
    cache.set(f'{_ENROLLMENT_CACHE_PREFIX}{token}', user.pk,
              timeout=settings.MFA_CHALLENGE_TTL_SECONDS)
    return token


def _peek_enrollment_token(token: str):
    if not token:
        return None
    user_pk = cache.get(f'{_ENROLLMENT_CACHE_PREFIX}{token}')
    if user_pk is None:
        return None
    return User.objects.filter(pk=user_pk, is_active=True).first()


def _delete_enrollment_token(token: str) -> None:
    cache.delete(f'{_ENROLLMENT_CACHE_PREFIX}{token}')


_PWCHANGE_CACHE_PREFIX = 'p2:auth:pwchange:'


def _issue_password_change_token(user, via: str) -> str:
    """Single-use token for the forced password change. Remembers which
    sign-in path produced it so the flow can resume exactly there."""
    token = secrets.token_urlsafe(32)
    cache.set(f'{_PWCHANGE_CACHE_PREFIX}{token}', {'pk': user.pk, 'via': via},
              timeout=settings.MFA_CHALLENGE_TTL_SECONDS)
    return token


def _peek_password_change_token(token: str):
    """Return (user, via) without consuming the token, or (None, None)."""
    if not token:
        return None, None
    data = cache.get(f'{_PWCHANGE_CACHE_PREFIX}{token}')
    if not data:
        return None, None
    user = User.objects.filter(pk=data['pk'], is_active=True).first()
    return (user, data['via']) if user else (None, None)


def _must_change_password(user) -> bool:
    from p2.core.auth_policy import password_change_required
    return password_change_required(user)


_SSO_CODE_CACHE_PREFIX = 'p2:sso:code:'
_SSO_CODE_TTL_SECONDS = 60


def _issue_sso_code(user) -> str:
    """Opaque single-use code handed to the SPA in the post-SSO redirect, in
    place of putting JWTs in the URL."""
    code = secrets.token_urlsafe(32)
    cache.set(f'{_SSO_CODE_CACHE_PREFIX}{code}', user.pk, timeout=_SSO_CODE_TTL_SECONDS)
    return code


def _consume_sso_code(code: str):
    """Return the active User for *code* and burn it, or None. The delete's
    return value is the atomic guard, so concurrent exchanges cannot both win."""
    if not code:
        return None
    key = f'{_SSO_CODE_CACHE_PREFIX}{code}'
    user_pk = cache.get(key)
    if user_pk is None or not cache.delete(key):
        return None
    return User.objects.filter(pk=user_pk, is_active=True).first()


# ---------------------------------------------------------------------------
# Login (first factor + MFA gate)
# ---------------------------------------------------------------------------

@router_login.post('/login', response=LoginResponseSchema, auth=None)
def login(request, payload: LoginSchema):
    """Password auth with auth-policy enforcement.

    Superusers are exempt from policy (lockout safety §5.1).  For everyone
    else the effective requirement may block password login entirely
    (SSO_REQUIRED), force TOTP enrollment (MFA_REQUIRED / SSO_OR_MFA), or
    allow bare password (NONE).
    """
    uname = (payload.username or '').strip().lower()[:150]
    ip = _client_ip(request)
    if (
        _throttled('login-acct-ip', f'{uname}|{ip}', _LOGIN_FAILS_PER_ACCOUNT_IP)
        or _throttled('login-acct', uname, _LOGIN_FAILS_PER_ACCOUNT)
        or _throttled('login-ip', ip, _LOGIN_FAILS_PER_IP)
    ):
        raise HttpError(429, "Too many failed sign-in attempts. Try again later.")

    user = authenticate(request, username=payload.username, password=payload.password)
    if user is None or not user.is_active:
        _record_failure('login-acct-ip', f'{uname}|{ip}')
        _record_failure('login-acct', uname)
        _record_failure('login-ip', ip)
        raise HttpError(401, "No active account found with the given credentials")
    _clear_failures('login-acct-ip', f'{uname}|{ip}')

    if _must_change_password(user):
        return LoginResponseSchema(
            password_change_required=True,
            password_change_token=_issue_password_change_token(user, 'password'),
        )
    return _finish_password_login(user)


def _finish_password_login(user) -> LoginResponseSchema:
    # ── superuser exemption (§5.1) ──────────────────────────────────────
    if user.is_superuser:
        if _totp_authenticator(user) is not None:
            return LoginResponseSchema(mfa_required=True, mfa_token=_issue_mfa_challenge(user))
        return LoginResponseSchema(**_mint_jwt_pair(user))

    # ── resolve effective auth policy ───────────────────────────────────
    from p2.core.auth_policy import AuthPolicy, resolve_policy
    policy = resolve_policy(user)

    if policy == AuthPolicy.Requirement.SSO_REQUIRED:
        raise HttpError(403, 'This account must sign in via SSO. Password login is disabled.')

    if policy in (AuthPolicy.Requirement.MFA_REQUIRED, AuthPolicy.Requirement.SSO_OR_MFA):
        if _totp_authenticator(user) is None:
            return LoginResponseSchema(
                mfa_setup_required=True,
                enrollment_token=_issue_enrollment_token(user),
            )
        return LoginResponseSchema(mfa_required=True, mfa_token=_issue_mfa_challenge(user))

    # policy == NONE — existing behaviour
    if _totp_authenticator(user) is not None:
        return LoginResponseSchema(mfa_required=True, mfa_token=_issue_mfa_challenge(user))
    return LoginResponseSchema(**_mint_jwt_pair(user))


@router_login.post('/sso/exchange', response=LoginResponseSchema, auth=None)
def sso_exchange(request, payload: SsoExchangeSchema):
    """Trade the single-use code from the SSO redirect for tokens, applying
    the auth policy: a user who must enrol TOTP gets an enrollment token
    instead of a JWT pair."""
    user = _consume_sso_code(payload.code)
    if user is None:
        raise HttpError(401, "SSO sign-in expired or already used. Please sign in again.")

    if _must_change_password(user):
        return LoginResponseSchema(
            password_change_required=True,
            password_change_token=_issue_password_change_token(user, 'sso'),
        )
    return _finish_sso_login(user)


def _finish_sso_login(user) -> LoginResponseSchema:
    if not user.is_superuser:
        try:
            from p2.core.auth_policy import AuthPolicy, resolve_policy
            needs_mfa = resolve_policy(user) == AuthPolicy.Requirement.MFA_REQUIRED
        except Exception:
            # Fail closed: an unevaluable policy must not yield a token.
            LOGGER.exception("Auth policy check failed during SSO exchange")
            raise HttpError(503, "Could not evaluate sign-in policy. Please try again.")
        if needs_mfa:
            if _totp_authenticator(user) is None:
                return LoginResponseSchema(
                    mfa_setup_required=True,
                    enrollment_token=_issue_enrollment_token(user),
                )
            # MFA_REQUIRED means a second factor on every sign-in, not only
            # at enrolment; SSO_OR_MFA accepts SSO alone.
            return LoginResponseSchema(mfa_required=True, mfa_token=_issue_mfa_challenge(user))
    return LoginResponseSchema(**_mint_jwt_pair(user))


@router_login.post('/password-change', response=LoginResponseSchema, auth=None)
def password_change(request, payload: PasswordChangeSchema):
    """Set a new password for an account flagged as needing one (e.g. the
    seeded ``admin/admin``), then resume the sign-in path that got us here —
    MFA, enrolment and policy still apply, so this alone never yields tokens
    for accounts that need a second factor."""
    from django.contrib.auth.password_validation import validate_password
    from django.core.exceptions import ValidationError
    from django.db import transaction

    from p2.core.auth_policy import PasswordChangeRequired

    ip = _client_ip(request)
    if _throttled('pwchange-ip', ip, _LOGIN_FAILS_PER_IP):
        raise HttpError(429, "Too many attempts. Try again later.")

    user, via = _peek_password_change_token(payload.password_change_token)
    if user is None:
        _record_failure('pwchange-ip', ip)
        raise HttpError(401, "Password change expired or already used. Please sign in again.")

    new_password = payload.new_password or ''
    if user.check_password(new_password):
        raise HttpError(400, "The new password must be different from the current one.")
    try:
        validate_password(new_password, user)
    except ValidationError as exc:
        raise HttpError(400, ' '.join(exc.messages))

    key = f'{_PWCHANGE_CACHE_PREFIX}{payload.password_change_token}'
    if not cache.delete(key):
        raise HttpError(401, "Password change expired or already used. Please sign in again.")
    with transaction.atomic():
        user.set_password(new_password)
        user.save(update_fields=['password'])
        PasswordChangeRequired.objects.filter(user=user).delete()
    _revoke_refresh_tokens(user)
    LOGGER.info("Forced password change completed for user=%s", user.get_username())

    if via == 'sso':
        return _finish_sso_login(user)
    return _finish_password_login(user)


@router_mfa.post('/verify', response=LoginResponseSchema, auth=None)
def verify(request, payload: MfaVerifySchema):
    """Second factor. The challenge stays valid for retries until it
    expires, succeeds, or exceeds the wrong-code limit — only a successful
    verification consumes it (so it still cannot be replayed for a second
    login) and mints the real JWT pair.
    """
    user = _peek_mfa_challenge(payload.mfa_token)
    if user is None:
        raise HttpError(401, "MFA challenge expired or already used. Please log in again.")

    if _throttled('mfa-user', str(user.pk), _MFA_FAILS_PER_USER):
        _delete_mfa_challenge(payload.mfa_token)
        raise HttpError(429, "Too many incorrect verification codes. Try again later.")

    code = _normalize_code(payload.code)
    if code and _validate_second_factor(user, code):
        if not _delete_mfa_challenge(payload.mfa_token):
            raise HttpError(401, "MFA challenge expired or already used. Please log in again.")
        _clear_failures('mfa-user', str(user.pk))
        LOGGER.debug("MFA verify: user=%s", user.get_username())
        return LoginResponseSchema(**_mint_jwt_pair(user))

    _record_failure('mfa-user', str(user.pk))
    attempts_key = f'{_ATTEMPT_CACHE_PREFIX}{payload.mfa_token}'
    try:
        attempts = cache.incr(attempts_key)
    except ValueError:
        cache.set(
            attempts_key,
            1,
            timeout=settings.MFA_CHALLENGE_TTL_SECONDS,
        )
        attempts = 1
    if attempts >= _MAX_VERIFY_ATTEMPTS:
        _delete_mfa_challenge(payload.mfa_token)
        raise HttpError(429, "Too many incorrect attempts. Please log in again.")

    raise HttpError(401, "Incorrect code.")


# ---------------------------------------------------------------------------
# Enrollment (requires an existing valid JWT — normal `auth` on this router)
# ---------------------------------------------------------------------------

@router_mfa.get('/status', response=MfaStatusSchema)
def status(request):
    return MfaStatusSchema(enabled=_totp_authenticator(request.user) is not None)


@router_mfa.post('/setup', response=MfaSetupResponseSchema)
def setup(request):
    """Generate a new TOTP secret and return the QR code. Not yet persisted
    to an Authenticator row — call /mfa/confirm with a valid code from the
    generated secret to actually activate it. Mirrors allauth.mfa's own
    session-held-pending-secret flow.
    """
    if _totp_authenticator(request.user) is not None:
        raise HttpError(400, "Two-factor authentication is already enabled.")

    secret = generate_totp_secret()
    cache.set(
        f'{_PENDING_SECRET_CACHE_PREFIX}{request.user.pk}',
        secret,
        timeout=settings.MFA_CHALLENGE_TTL_SECONDS,
    )

    adapter = get_mfa_adapter()
    otpauth_url = adapter.build_totp_url(request.user, secret)
    qr_svg = adapter.build_totp_svg(otpauth_url)
    return MfaSetupResponseSchema(secret=secret, otpauth_url=otpauth_url, qr_svg=qr_svg)


@router_mfa.post('/confirm', response=MfaConfirmResponseSchema)
def confirm(request, payload: MfaConfirmSchema):
    """Verify a code against the pending secret from /mfa/setup, and if
    correct, activate TOTP + generate recovery codes (shown once).
    """
    cache_key = f'{_PENDING_SECRET_CACHE_PREFIX}{request.user.pk}'
    secret = cache.get(cache_key)
    if not secret:
        raise HttpError(400, "No pending 2FA setup found. Call /mfa/setup first.")

    if not validate_totp_code(secret, payload.code):
        raise HttpError(400, "Incorrect code.")

    cache.delete(cache_key)
    TOTP.activate(request.user, secret)
    recovery_codes = RecoveryCodes.activate(request.user).generate_codes()

    LOGGER.debug("MFA enrolled: user=%s", request.user.get_username())
    return MfaConfirmResponseSchema(recovery_codes=recovery_codes)


@router_mfa.post('/disable')
def disable(request, payload: MfaDisableSchema):
    """Require the current password (not just a bearer token) before turning
    off 2FA, so a stolen/leaked access token alone can't disable it."""
    uid = str(request.user.pk)
    if _throttled('disable-user', uid, _DISABLE_FAILS_PER_USER):
        raise HttpError(429, "Too many incorrect passwords. Try again later.")
    if not request.user.check_password(payload.password):
        _record_failure('disable-user', uid)
        raise HttpError(401, "Incorrect password.")
    _clear_failures('disable-user', uid)
    _revoke_refresh_tokens(request.user)

    Authenticator.objects.filter(
        user=request.user,
        type__in=[Authenticator.Type.TOTP, Authenticator.Type.RECOVERY_CODES],
    ).delete()
    LOGGER.debug("MFA disabled: user=%s", request.user.get_username())
    return {'ok': True}


# ---------------------------------------------------------------------------
# Forced TOTP enrollment (policy-driven, before JWT exists)
# ---------------------------------------------------------------------------

class EnrollmentSetupSchema(Schema):
    enrollment_token: str


class EnrollmentConfirmSchema(Schema):
    enrollment_token: str
    code: str


@router_mfa.post('/enroll-setup', response=MfaSetupResponseSchema, auth=None)
def enroll_setup(request, payload: EnrollmentSetupSchema):
    """Generate a TOTP secret for a user in the forced-enrollment flow.
    Requires an enrollment_token (not a JWT)."""
    user = _peek_enrollment_token(payload.enrollment_token)
    if user is None:
        raise HttpError(401, 'Enrollment session expired. Please log in again.')

    secret = generate_totp_secret()
    cache.set(
        f'{_PENDING_SECRET_CACHE_PREFIX}{user.pk}',
        secret,
        timeout=settings.MFA_CHALLENGE_TTL_SECONDS,
    )
    adapter = get_mfa_adapter()
    otpauth_url = adapter.build_totp_url(user, secret)
    qr_svg = adapter.build_totp_svg(otpauth_url)
    return MfaSetupResponseSchema(secret=secret, otpauth_url=otpauth_url, qr_svg=qr_svg)


@router_mfa.post('/enroll-confirm', auth=None)
def enroll_confirm(request, payload: EnrollmentConfirmSchema):
    """Confirm the TOTP code, activate the authenticator, and mint a JWT
    pair — completing the forced-enrollment flow in one round trip."""
    user = _peek_enrollment_token(payload.enrollment_token)
    if user is None:
        raise HttpError(401, 'Enrollment session expired. Please log in again.')

    secret = cache.get(f'{_PENDING_SECRET_CACHE_PREFIX}{user.pk}')
    if not secret:
        raise HttpError(400, 'No pending 2FA setup. Call /mfa/enroll-setup first.')

    if _throttled('mfa-user', str(user.pk), _MFA_FAILS_PER_USER):
        raise HttpError(429, 'Too many incorrect codes. Try again later.')
    if not validate_totp_code(secret, payload.code):
        _record_failure('mfa-user', str(user.pk))
        raise HttpError(400, 'Incorrect code.')

    cache.delete(f'{_PENDING_SECRET_CACHE_PREFIX}{user.pk}')
    _delete_enrollment_token(payload.enrollment_token)
    TOTP.activate(user, secret)
    recovery_codes = RecoveryCodes.activate(user).generate_codes()

    LOGGER.debug('Forced MFA enrollment completed: user=%s', user.get_username())
    return {**_mint_jwt_pair(user), 'recovery_codes': recovery_codes}

"""Auth-policy model and resolution logic.

A super-admin can set an org-wide default login requirement (or per-Group
overrides).  ``resolve_policy(user)`` returns the strictest applicable
requirement — callers in the login flow use it to gate access.

Part of p2.core (no new INSTALLED_APPS entry).
"""
import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import models

LOGGER = logging.getLogger(__name__)
User = get_user_model()


class AuthPolicy(models.Model):
    """Org-wide default (group=NULL) or per-Group login-method override."""

    class Requirement(models.TextChoices):
        NONE = 'none', 'No requirement (password alone is allowed)'
        MFA_REQUIRED = 'mfa_required', 'Password + TOTP 2FA required'
        SSO_REQUIRED = 'sso_required', 'SSO only (password login disabled)'
        SSO_OR_MFA = 'sso_or_mfa', 'SSO or password+2FA (bare password forbidden)'

    group = models.OneToOneField(
        Group,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='auth_policy',
        help_text='NULL = org-wide default. Exactly one row may have group=NULL.',
    )
    requirement = models.CharField(
        max_length=20,
        choices=Requirement.choices,
        default=Requirement.NONE,
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['group'],
                condition=models.Q(group__isnull=True),
                name='authpolicy_one_global_default',
            ),
        ]

    def __str__(self):
        return f"AuthPolicy({self.group or 'GLOBAL'} -> {self.requirement})"


# Strictness ordering — strictest wins when a user is in multiple groups.
_STRICTNESS = {
    AuthPolicy.Requirement.NONE: 0,
    AuthPolicy.Requirement.MFA_REQUIRED: 1,
    AuthPolicy.Requirement.SSO_OR_MFA: 1,
    AuthPolicy.Requirement.SSO_REQUIRED: 2,
}


def resolve_policy(user) -> str:
    """Return the effective requirement for *user*.

    Resolution order:
      1. Collect requirements from every Group the user belongs to.
      2. Fall back to the global default (group IS NULL), or NONE.
      3. Pick the strictest.

    Superuser exemption is handled by the *caller*, not here — keeping
    this function purely "what would apply" makes it testable.
    """
    group_reqs = list(
        AuthPolicy.objects.filter(group__in=user.groups.all())
        .values_list('requirement', flat=True)
    )
    global_req = (
        AuthPolicy.objects.filter(group__isnull=True)
        .values_list('requirement', flat=True)
        .first()
    ) or AuthPolicy.Requirement.NONE

    candidates = group_reqs + [global_req]
    return max(candidates, key=lambda r: _STRICTNESS.get(r, 0))


class SSOSettings(models.Model):
    """Singleton (pk=1) holding admin-editable SSO sign-in rules."""

    allowed_email_domains = models.TextField(
        blank=True, default='',
        help_text='Comma-separated email domains allowed to sign in with SSO. '
                  'Empty falls back to the sso.allowed_email_domains config value, '
                  'and if that is empty too, any domain is allowed.',
    )
    allow_jit_signup = models.BooleanField(
        default=False,
        help_text='Create a local user on first SSO login when no existing user '
                  'matches. When off, only users an admin already created can sign in.',
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'SSO settings'
        verbose_name_plural = 'SSO settings'

    @classmethod
    def load(cls) -> 'SSOSettings':
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def domains(self) -> set[str]:
        raw = self.allowed_email_domains
        if not raw.strip():
            from p2.lib.config import CONFIG
            raw = str(CONFIG.y('sso.allowed_email_domains', '') or '')
        return {d.strip().lower().lstrip('@') for d in raw.split(',') if d.strip()}


class PasswordChangeRequired(models.Model):
    """Presence of a row means the user must set a new password before any
    sign-in path (password, SSO, session) is allowed to issue credentials."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='password_change_required')
    reason = models.CharField(max_length=64, default='default_credentials')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PasswordChangeRequired({self.user_id}: {self.reason})"


def password_change_required(user) -> bool:
    return PasswordChangeRequired.objects.filter(user=user).exists()

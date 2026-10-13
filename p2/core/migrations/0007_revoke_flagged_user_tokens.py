"""Blacklist refresh tokens issued before an account was flagged for a forced
password change, so sessions obtained with the default credentials end now."""
from django.db import migrations


def revoke_tokens(apps, schema_editor):
    Flag = apps.get_model('p2_core', 'PasswordChangeRequired')
    Outstanding = apps.get_model('token_blacklist', 'OutstandingToken')
    Blacklisted = apps.get_model('token_blacklist', 'BlacklistedToken')
    user_ids = Flag.objects.values_list('user_id', flat=True)
    for token in Outstanding.objects.filter(user_id__in=user_ids):
        Blacklisted.objects.get_or_create(token=token)


class Migration(migrations.Migration):

    dependencies = [
        ('p2_core', '0006_passwordchangerequired'),
        ('token_blacklist', '0012_alter_outstandingtoken_user'),
    ]

    operations = [
        migrations.RunPython(revoke_tokens, migrations.RunPython.noop),
    ]

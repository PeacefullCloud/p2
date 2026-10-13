"""Create the initial `admin` superuser if it does not exist yet.

The password comes from P2_ADMIN_PASSWORD when set. Otherwise a random one is
generated and printed once to stderr, so a fresh install never exposes a
well-known default credential. (Installs created before this change still have
admin/admin; migration 0006 flags those for a forced password change.)
"""
import os
import secrets
import sys

from django.db import migrations


def create_default_admin(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    if User.objects.filter(username='admin').exists():
        return
    password = os.environ.get('P2_ADMIN_PASSWORD', '')
    generated = not password
    if generated:
        password = secrets.token_urlsafe(16)
    User.objects.create_superuser(
        username='admin',
        email='admin@localhost',
        password=password,
    )
    if generated:
        print(
            f"\n[p2] Created initial superuser 'admin' with generated password: {password}\n"
            "[p2] Save it now, it is not shown again. Set P2_ADMIN_PASSWORD to choose your own.\n",
            file=sys.stderr,
        )


class Migration(migrations.Migration):

    dependencies = [
        ('p2_core', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_default_admin, migrations.RunPython.noop),
    ]

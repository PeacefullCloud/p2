"""SSOSettings singleton: allowed email domains + create-on-first-login switch."""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('p2_core', '0004_authpolicy'),
    ]

    operations = [
        migrations.CreateModel(
            name='SSOSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('allowed_email_domains', models.TextField(blank=True, default='', help_text='Comma-separated email domains allowed to sign in with SSO. Empty falls back to the sso.allowed_email_domains config value, and if that is empty too, any domain is allowed.')),
                ('allow_jit_signup', models.BooleanField(default=False, help_text='Create a local user on first SSO login when no existing user matches. When off, only users an admin already created can sign in.')),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'SSO settings',
                'verbose_name_plural': 'SSO settings',
            },
        ),
    ]

"""PasswordChangeRequired flag; flags any account still on the seeded admin/admin."""
import django.db.models.deletion
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.db import migrations, models


def flag_default_admin(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    Flag = apps.get_model('p2_core', 'PasswordChangeRequired')
    for user in User.objects.filter(username='admin'):
        if user.password and check_password('admin', user.password):
            Flag.objects.get_or_create(user=user, defaults={'reason': 'default_credentials'})


class Migration(migrations.Migration):

    dependencies = [
        ('p2_core', '0005_ssosettings'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PasswordChangeRequired',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reason', models.CharField(default='default_credentials', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='password_change_required', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RunPython(flag_default_admin, migrations.RunPython.noop),
    ]

# Generated by Django 5.1b1 on 2025-02-16 06:12

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0004_user_super_admin'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='super_admin',
            new_name='is_super_admin',
        ),
    ]

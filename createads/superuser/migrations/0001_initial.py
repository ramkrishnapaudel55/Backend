# Generated by Django 5.1b1 on 2025-02-18 05:43

import datetime
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AdminAdvertisement',
            fields=[
                ('id', models.CharField(default=None, editable=False, max_length=6, primary_key=True, serialize=False, unique=True)),
                ('title', models.CharField(blank=True, max_length=255, null=True)),
                ('details', models.TextField(blank=True, null=True)),
                ('discounts', models.CharField(blank=True, max_length=255, null=True)),
                ('offers', models.CharField(blank=True, max_length=255, null=True)),
                ('referral_code', models.CharField(blank=True, max_length=50, null=True)),
                ('guidelines', models.TextField(blank=True, null=True)),
                ('links', models.CharField(blank=True, max_length=255, null=True)),
                ('thumbnail', models.ImageField(blank=True, null=True, upload_to='Adminads/thumbnail')),
                ('is_running', models.BooleanField(default=True)),
                ('duration', models.DurationField(blank=True, default=datetime.timedelta(days=1), null=True)),
                ('priority', models.PositiveIntegerField(blank=True, default=1, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='UserDashboard',
            fields=[
                ('id', models.CharField(default=None, editable=False, max_length=5, primary_key=True, serialize=False, unique=True)),
                ('photo', models.ImageField(blank=True, null=True, upload_to='user_dashboard/photos/')),
                ('video', models.FileField(blank=True, null=True, upload_to='user_dashboard/videos/')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('priority', models.PositiveIntegerField(default=1)),
            ],
        ),
        migrations.CreateModel(
            name='AdminNotification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('is_read', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]

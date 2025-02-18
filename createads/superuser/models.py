from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError
import random
import string


class AdminAdvertisement(models.Model):
    id = models.CharField(max_length=6, primary_key=True, editable=False, unique=True,
                          default=None)  # 6-char alphanumeric ID
    title = models.CharField(max_length=255, blank=True, null=True)  # Optional
    details = models.TextField(blank=True, null=True)  # Optional
    discounts = models.CharField(max_length=255, blank=True, null=True)  # Optional
    offers = models.CharField(max_length=255, blank=True, null=True)  # Optional
    referral_code = models.CharField(max_length=50, blank=True, null=True)  # Optional
    guidelines = models.TextField(blank=True, null=True)  # Optional
    links = models.CharField(max_length=255, blank=True, null=True)  # Optional
    thumbnail = models.ImageField(upload_to='Adminads/thumbnail', blank=True, null=True)  # Optional
    is_running = models.BooleanField(default=True)
    duration = models.DurationField(default=timedelta(days=1), blank=True, null=True)  # Optional
    priority = models.PositiveIntegerField(default=1, blank=True, null=True)  # Optional
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        # Generate a unique ID if it doesn't exist
        if not self.id:
            self.id = generate_unique_id(AdminAdvertisement, 'id')  # Generate 6-char alphanumeric ID

        # Check if the advertisement is running based on duration and created_at
        if self.created_at and self.duration:
            if self.created_at + self.duration < timezone.now():
                self.is_running = False
            else:
                self.is_running = True

        # Call the parent save method
        super(AdminAdvertisement, self).save(*args, **kwargs)

    def __str__(self):
        return self.title or "Untitled Advertisement"


def generate_unique_id(model, field):
    length = 6
    while True:
        # Generate a random alphanumeric string of the specified length
        unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

        # Check if the generated ID is unique for the given model and field
        if not model.objects.filter(**{field: unique_id}).exists():
            return unique_id


class UserDashboard(models.Model):
    id = models.CharField(max_length=5, primary_key=True, editable=False, unique=True, default=None)  # Optimized ID
    photo = models.ImageField(upload_to='user_dashboard/photos/', null=True, blank=True)
    video = models.FileField(upload_to='user_dashboard/videos/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    priority = models.PositiveIntegerField(default=1)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_unique_id(UserDashboard, 'id')  # Generate 5-char alphanumeric ID
        super().save(*args, **kwargs)

    def clean(self):
        """Ensure that either photo or video is provided, not both."""
        if not self.photo and not self.video:
            raise ValidationError('You must upload either a photo or a video.')
        if self.photo and self.video:
            raise ValidationError('You can upload only one: either a photo or a video.')

    def __str__(self):
        return f"Dashboard media (ID: {self.id})"


class AdminNotification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()  # The message for the notification
    is_read = models.BooleanField(default=False)  # Whether the notification has been read
    created_at = models.DateTimeField(default=timezone.now)  # When the notification was created

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:50]}"

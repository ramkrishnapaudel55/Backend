import random
import string
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.utils import timezone
from datetime import timedelta


# Helper function to generate a unique 5-character alphanumeric user_id
def generate_unique_id():
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=5))


class User(AbstractUser):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, default='', blank=True)  # Added default=''
    is_verified = models.BooleanField(default=False)
    user_id = models.CharField(max_length=5, primary_key=True, unique=True, editable=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiration = models.DateTimeField(blank=True, null=True)
    referral_code = models.CharField(max_length=6, unique=True, blank=True, null=True)
    referral_count = models.PositiveIntegerField(default=0)
    referred_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='referrals')
    date_joined = models.DateField(default=timezone.now)
    is_super_admin = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)  # Add this field if not already present
    email_verified_at = models.DateTimeField(null=True, blank=True)  # Add this to track verification time

    REQUIRED_FIELDS = ['email']

    def save(self, *args, **kwargs):
        if not self.full_name and (self.first_name or self.last_name):
            self.full_name = f"{self.first_name} {self.last_name}".strip()
        super().save(*args, **kwargs)

    groups = models.ManyToManyField(Group, related_name='user_set_custom', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='user_set_custom', blank=True)

    def __str__(self):
        return self.username

    def save(self, *args, **kwargs):
        # Normalize email to lowercase before saving
        self.email = self.email.lower()

        if not self.user_id:
            self.user_id = self.generate_unique_id_safe()

        if not self.referral_code:
            self.generate_referral_code()

        super().save(*args, **kwargs)

    def generate_unique_id_safe(self):
        unique_id = self.generate_unique_id()
        while User.objects.filter(user_id=unique_id).exists():
            unique_id = self.generate_unique_id()
        return unique_id

    def generate_unique_id(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

    def generate_referral_code(self):
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        while User.objects.filter(referral_code=code).exists():
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        self.referral_code = code

    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.otp_expiration = timezone.now() + timedelta(minutes=10)
        self.save()

    def check_otp(self, otp):
        return self.otp == otp and timezone.now() < self.otp_expiration


class Meta:
    db_table = 'login_user'


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.message[:50]}"


class AdminSettings(models.Model):
    passkey = models.CharField(max_length=6, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def generate_new_passkey(self):
        new_passkey = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        while AdminSettings.objects.filter(passkey=new_passkey).exists():
            new_passkey = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return new_passkey

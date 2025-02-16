import string
import random

from django.db import models
from django.db.models import Sum
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField
from datetime import date
from django.contrib.auth import get_user_model
from .utils import generate_unique_id

User = get_user_model()  # Get the custom User model


class UserProfile(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other')
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    photo = models.ImageField(upload_to='profile_photos/', null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    nationality = models.CharField(max_length=50, null=True, blank=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, null=True, blank=True)
    bio = models.CharField(max_length=50, null=True, blank=True)
    phone_number = PhoneNumberField(blank=True, null=True)
    is_verify = models.BooleanField(default=False)

    def __str__(self):
        return f"Profile of {self.user.username}"

    @property
    def age(self):
        if self.date_of_birth:
            return (date.today() - self.date_of_birth).days // 365
        return None

    @property
    def wallet_balance(self):
        return self.user.userwallet.balance if hasattr(self.user, 'userwallet') else None


class Advertisement(models.Model):
    id = models.CharField(max_length=5, primary_key=True, editable=False, unique=True, default=None)
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=20, null=True, blank=True, default='default')
    budget = models.DecimalField(max_digits=10, decimal_places=2)
    remaining_budget = models.DecimalField(max_digits=10, decimal_places=2)
    per_job = models.DecimalField(max_digits=10, decimal_places=2)
    limit = models.CharField(max_length=10, choices=[('days', 'Days'), ('jobs', 'Jobs')])
    description = models.TextField()
    confirmation_requirements = models.TextField()
    requires_media = models.BooleanField(default=False)
    media_type = models.CharField(max_length=10, choices=[('photo', 'Photo'), ('video', 'Video'), ('both', 'Both')],
                                  null=True, blank=True)
    thumbnail = models.ImageField(upload_to='thumbnails/', null=True, blank=True)
    status = models.CharField(max_length=10, default='unapproved',
                              choices=[('Active', 'Active'), ('completed', 'completed'), ('draft', 'draft'),
                                       ('unapproved', 'Unapproved')])
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    terminate = models.DateField()
    created_at = models.DateTimeField(default=timezone.now)
    submissions = models.IntegerField(default=0, null=True)
    youtube_link = models.URLField(max_length=200, blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_unique_id(Advertisement, 'id')
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title

    def check_and_activate(self):
        if self.status == 'unapproved' and timezone.now() >= self.created_at + timezone.timedelta(seconds=15):
            self.status = 'active'
            self.save()


class UserWallet(models.Model):
    id = models.CharField(max_length=5, primary_key=True, editable=False, unique=True, default=None)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = self.generate_unique_id()
        super().save(*args, **kwargs)

    def generate_unique_id(self):
        unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        while UserWallet.objects.filter(id=unique_id).exists():
            unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        return unique_id

    @property
    def total_earning(self):
        earnings = UserTransaction.objects.filter(
            user=self.user,
            transaction_type='earn',
            status='approved'
        ).aggregate(total=Sum('amount'))['total'] or 0
        return earnings

    @property
    def total_spending(self):
        spendings = UserTransaction.objects.filter(
            user=self.user,
            transaction_type='spend',
            status__in=['verified', 'approved']
        ).aggregate(total=Sum('amount'))['total'] or 0
        return spendings

    def __str__(self):
        return f"Wallet of {self.user.username}"


class UserTransaction(models.Model):
    TRANSACTION_TYPES = [
        ('deposit', 'Deposit'),
        ('withdraw', 'Withdraw'),
        ('earn', 'Earn'),
        ('spend', 'Spend'),
        ('refund', 'Refund')
    ]
    TRANSACTION_STATUS = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('refund', 'Refund'),
        ('verified', 'Verified')
    ]
    id = models.CharField(max_length=5, primary_key=True, editable=False, unique=True, default=None)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    advertisement = models.ForeignKey(Advertisement, null=True, blank=True, on_delete=models.SET_NULL)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    advertisement_title = models.CharField(max_length=255, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=TRANSACTION_STATUS, default='pending')

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_unique_id(UserTransaction, 'id')
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.transaction_type.capitalize()} of {self.amount} by {self.user.username}"


class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('info', 'Information'),
        ('warning', 'Warning'),
        ('success', 'Success'),
        ('error', 'Error'),
    ]

    id = models.CharField(max_length=5, primary_key=True, editable=False, unique=True, default=None)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    notification_type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES, default='info')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    advertisement = models.ForeignKey(Advertisement, null=True, blank=True, on_delete=models.SET_NULL,
                                      related_name='notifications')

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_unique_id(Notification, 'id')
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:50]}"


class Proof(models.Model):
    id = models.CharField(max_length=5, primary_key=True, editable=False, unique=True, default=None)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    photo = models.ImageField(upload_to='proofs/photos/', null=True, blank=True)
    video = models.FileField(upload_to='proofs/videos/', null=True, blank=True)
    proof_id = models.CharField(max_length=5, unique=True, editable=False)
    advertisement = models.ForeignKey(Advertisement, on_delete=models.CASCADE)
    status = models.CharField(max_length=10,
                              choices=[('unapproved', 'Unapproved'), ('approved', 'Approved'), ('denied', 'Denied')],
                              default='unapproved')
    advertisement_title = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_unique_id(Proof, 'id')
        if not self.proof_id:
            self.proof_id = generate_unique_id(Proof, 'proof_id')
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Proof {self.proof_id} for {self.advertisement.title}"

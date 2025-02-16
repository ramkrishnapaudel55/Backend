from django.core.mail import send_mail
from django.conf import settings
import random
import string


def send_verification_email(user):
    user.generate_otp()
    subject = 'Your Verification Code'
    message = f'Your verification code is {user.otp}. It is valid for 10 minutes.'
    email_from = settings.EMAIL_HOST
    send_mail(subject, message, email_from, [user.email])


def generate_unique_id(model, field, length=5):
    """Generates a unique alphanumeric ID of the specified length."""
    characters = string.ascii_letters + string.digits
    while True:
        unique_id = ''.join(random.choices(characters, k=length))
        if not model.objects.filter(**{field: unique_id}).exists():
            return unique_id

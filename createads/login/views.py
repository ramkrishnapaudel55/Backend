from django.contrib.auth import authenticate, update_session_auth_hash
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.utils import IntegrityError
from jsonschema import ValidationError
from rest_framework import status, permissions
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User, AdminSettings
from .permissions import IsAdminUserCustom
from .serializers import (
    UserSerializer, AdminRegisterSerializer, ForgotPasswordSerializer,
    ChangePasswordAdminSerializer
)
from django.contrib.auth import get_user_model
from rest_framework import status
from create.models import Notification
# from .notifications import create_notification
from .utils import send_verification_email
from django.utils import timezone
from django.core.mail import send_mail
from django.db import transaction
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from django.core.validators import validate_email
from django.db.models import Q

import random
import string
import redis
import logging
import re

logger = logging.getLogger(__name__)
User = get_user_model()

# Initialize Redis connection
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def create_notification(user, message):
    """
    Helper function to create a notification for a user.
    """
    try:
        Notification.objects.create(user=user, message=message)
    except Exception as e:
        print(f"Failed to create notification for user {user}: {e}")


def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def store_otp(email, otp):
    """Store OTP in Redis with 10-minute expiration"""
    redis_client.setex(f"email_otp:{email}", 600, otp)  # 600 seconds = 10 minutes


def verify_stored_otp(email, otp):
    """Verify OTP from Redis"""
    stored_otp = redis_client.get(f"email_otp:{email}")
    return stored_otp == otp


def send_otp_email(email, otp):
    """Send OTP via email"""
    subject = 'Email Verification OTP'
    message = f'Your verification code is: {otp}\nThis code will expire in 10 minutes.'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list, fail_silently=False)


class SendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email', '').strip()
        if not email:
            return Response({"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))

            # Save OTP to user model
            user.otp = otp
            user.otp_expiration = timezone.now() + timezone.timedelta(minutes=10)
            user.save()

            # Send email
            send_mail(
                subject='Email Verification OTP',
                message=f'Your verification code is: {otp}. This code will expire in 10 minutes.',
                from_email='noreply@yourdomain.com',
                recipient_list=[email],
                fail_silently=False,
            )

            return Response({"detail": "OTP sent successfully to your email."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"detail": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            print("Received data:", request.data)

            password = request.data.get('password')
            password_confirmation = request.data.get('reEnterPassword')

            if password != password_confirmation:
                return Response(
                    {"detail": "Passwords do not match."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Split full name into first and last name
            full_name = request.data.get('fullName', '').strip()
            name_parts = full_name.split(' ', 1)  # Split on first space only
            first_name = name_parts[0] if name_parts else ''
            last_name = name_parts[1] if len(name_parts) > 1 else ''

            # Prepare data for serializer
            serializer_data = {
                'username': request.data.get('userName'),
                'email': request.data.get('email'),
                'password': password,
                'full_name': request.data.get('fullName', '').strip(),
                'referral_code': request.data.get('referralCode', '')
            }

            print("Serializer data:", serializer_data)

            serializer = UserSerializer(data=serializer_data)

            if serializer.is_valid():
                try:
                    with transaction.atomic():
                        user = serializer.save()
                        create_notification(user, "Registration successful!")
                        return Response(
                            {"detail": "User registered successfully."},
                            status=status.HTTP_201_CREATED
                        )
                except IntegrityError as e:
                    return Response(
                        {"detail": "Registration failed. Username or email already exists."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            print("Serializer errors:", serializer.errors)
            return Response(
                {"detail": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return Response(
                {"detail": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile(request):
    """Get user profile data including correct email verification status"""
    try:
        # Get user and profile
        user = request.user
        profile = user.userprofile

        # Create serialized response with all needed fields
        response_data = {
            'user_name': user.username,
            'id': user.user_id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'photo': profile.photo.url if profile.photo else None,
            'date_of_birth': profile.date_of_birth.isoformat() if profile.date_of_birth else None,
            'nationality': profile.nationality,
            'gender': profile.gender,
            'phone_number': str(profile.phone_number) if profile.phone_number else None,
            'bio': profile.bio,
            'referral_code': user.referral_code,
            'referral_count': user.referral_count,
            'date_joined': user.date_joined.isoformat() if user.date_joined else None,
            'is_email_verified': user.is_verified  # Use the actual field name from your model
        }

        # Return the response
        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error fetching profile: {str(e)}")
        return Response(
            {'detail': 'Failed to fetch profile data'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_email(request):
    """Update user's email address with comprehensive error handling and validation"""
    # Use pk instead of id for logging - more reliable
    logger.info(f"Email update request received for user {request.user.pk}")

    try:
        # Get and validate email from request data
        email = request.data.get('email')

        # Validate email presence
        if not email:
            return Response(
                {'detail': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Remove whitespace
        email = email.strip()

        # Basic email validation
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return Response(
                {'detail': 'Invalid email format'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if email is unchanged
        if email.lower() == request.user.email.lower():
            return Response(
                {'detail': 'Email unchanged'},
                status=status.HTTP_200_OK
            )

        # Check if email is already in use
        if User.objects.filter(email__iexact=email).exclude(pk=request.user.pk).exists():
            return Response(
                {'detail': 'Email already in use'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update user's email
        request.user.email = email
        request.user.is_email_verified = False  # Reset verification status
        request.user.save()

        return Response(
            {'detail': 'Email updated successfully'},
            status=status.HTTP_200_OK
        )

    except Exception as e:
        logger.error(f"Error updating email: {str(e)}")
        return Response(
            {'detail': 'Failed to update email'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = str(request.data.get('email', '')).strip()
            otp = str(request.data.get('otp', '')).strip()

            logger.info(f"OTP Verification attempt - Email: {email}, OTP length: {len(otp)}")

            if not email or not otp:
                logger.warning("Missing email or OTP in request")
                return Response(
                    {"detail": "Email and OTP are required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not otp.isdigit() or len(otp) != 6:
                logger.warning(f"Invalid OTP format: {otp}")
                return Response(
                    {"detail": "Invalid OTP format. Must be 6 digits."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                logger.warning(f"User not found for email: {email}")
                return Response(
                    {"detail": "User with this email does not exist."},
                    status=status.HTTP_404_NOT_FOUND
                )

            if user.otp_expiration and user.otp_expiration < timezone.now():
                logger.warning(f"Expired OTP for user: {email}")
                return Response(
                    {"detail": "OTP has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not user.otp or user.otp != otp:
                logger.warning(f"Invalid OTP for user: {email}")
                return Response(
                    {"detail": "Invalid OTP."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update verification status with timestamp
            user.is_email_verified = True
            user.email_verified_at = timezone.now()
            user.otp = None
            user.otp_expiration = None
            user.save()

            # Return additional verification data
            logger.info(f"Email verification successful for user: {email}")
            return Response({
                "detail": "Email verified successfully.",
                "verified_at": user.email_verified_at.isoformat(),
                "is_verified": True
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in OTP verification: {str(e)}", exc_info=True)
            return Response(
                {"detail": "An unexpected error occurred. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(APIView):
    """
    View for user login.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email_or_username = request.data.get('email_or_username')
        password = request.data.get('password')

        if not email_or_username or not password:
            return Response({"detail": "Email/Username and password are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=email_or_username, password=password)
        if user:
            return self.login_success_response(user)
        return Response({"detail": "Invalid credentials."},
                        status=status.HTTP_400_BAD_REQUEST)

    def login_success_response(self, user):
        """
        Helper method to generate login success response.
        """
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        create_notification(user, "Logged in successfully.")
        return Response({
            "user_id": user.user_id,
            "username": user.username,
            "access_token": access_token,
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    View for user logout.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            request.auth.delete()
            create_notification(request.user, "Logged out successfully.")
            return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)
        except AttributeError:
            return Response({"detail": "No valid token provided."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({"detail": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(APIView):
    """
    View for changing user password.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_new_password = request.data.get('confirm_new_password')

        if not all([old_password, new_password, confirm_new_password]):
            return Response({"detail": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(old_password):
            return Response({"detail": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_new_password:
            return Response({"detail": "New passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        if old_password == new_password:
            return Response({"detail": "New password must be different from the old password."},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            self.change_user_password(user, new_password)
            return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"detail": "An error occurred while changing the password."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def change_user_password(self, user, new_password):
        """
        Helper method to change user password.
        """
        user.set_password(new_password)
        user.save()
        update_session_auth_hash(self.request, user)
        create_notification(user, "Password changed successfully.")


class GenerateOTPForResetView(APIView):
    """
    View for generating OTP for password reset.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
            send_verification_email(user)
            create_notification(user, "OTP sent to your email.")
            return Response({"detail": "OTP sent to your email."}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)


class ResetPasswordWithOTPView(APIView):
    """
    View for resetting password using OTP.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        try:
            user = User.objects.get(email=email)
            if user.check_otp(otp):
                self.reset_user_password(user, new_password)
                return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)
            return Response({"detail": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            return Response({"detail": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)

    def reset_user_password(self, user, new_password):
        """
        Helper method to reset user password.
        """
        user.set_password(new_password)
        user.is_verified = True
        user.otp = None
        user.otp_expiration = None
        user.save()
        create_notification(user, "Password reset successfully.")


class AdminRegisterView(APIView):
    """
    View for admin registration.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = AdminRegisterSerializer(data=request.data)

        if serializer.is_valid():
            passkey = serializer.validated_data.get('passkey')

            if not self.is_valid_passkey(passkey):
                return Response({"detail": "Invalid passkey."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                with transaction.atomic():
                    self.create_admin_user(serializer)
                    return Response({"detail": "Admin registered successfully."}, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({"detail": "User with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)
            except Exception:
                return Response({"detail": "An unexpected error occurred."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def is_valid_passkey(self, passkey):
        """
        Helper method to validate admin passkey.
        """
        try:
            settings = AdminSettings.objects.first()
            return settings and settings.passkey == passkey
        except AdminSettings.DoesNotExist:
            return False

    def create_admin_user(self, serializer):
        """
        Helper method to create an admin user.
        """
        validated_data = serializer.validated_data
        email = validated_data.get('email').lower()

        if User.objects.filter(email=email).exists():
            raise IntegrityError("User with this email already exists.")

        return serializer.save(is_admin=True)


class ForgotPasswordView(APIView):
    """
    View for handling forgot password requests.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            try:
                with transaction.atomic():
                    serializer.save()
                    return Response({"detail": "Password reset successfully."}, status=status.HTTP_200_OK)
            except IntegrityError:
                return Response({"detail": "An error occurred during password reset."},
                                status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasskeyView(APIView):
    """
    View for changing admin passkey.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        new_passkey = request.data.get('new_passkey')

        if not new_passkey or len(new_passkey) != 6:
            return Response({"detail": "Invalid passkey format."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            settings, created = AdminSettings.objects.get_or_create(id=1)
            settings.passkey = new_passkey
            settings.save()
            return Response({"detail": "Passkey updated successfully."}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"detail": "An error occurred while updating the passkey."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminLoginView(APIView):
    """
    View for admin login.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email_or_username = request.data.get('email_or_username')
        password = request.data.get('password')

        if not email_or_username or not password:
            return Response({"detail": "Email/Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=email_or_username, password=password)
        if user and user.is_verified and user.is_admin:
            refresh = RefreshToken.for_user(user)
            return Response({
                "user_id": user.user_id,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"detail": "Invalid credentials or unverified account."}, status=status.HTTP_400_BAD_REQUEST)


class AdminLogoutView(APIView):
    """
    View for admin logout.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"detail": "Logged out successfully."}, status=status.HTTP_205_RESET_CONTENT)
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({"detail": "An error occurred during logout."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordAdminView(APIView):
    """
    View for changing admin password.
    """
    permission_classes = [IsAdminUserCustom]

    def post(self, request):
        serializer = ChangePasswordAdminSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Password updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
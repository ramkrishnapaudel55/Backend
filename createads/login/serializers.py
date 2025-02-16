from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from .models import AdminSettings
from create.models import UserWallet, UserProfile
from django.core.validators import EmailValidator
from django.db import transaction

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(max_length=255, required=True)
    referral_code = serializers.CharField(write_only=True, required=False, allow_blank=True)
    email = serializers.EmailField(validators=[EmailValidator()])

    class Meta:
        model = User
        fields = ['user_id', 'email', 'username', 'full_name',
                  'password', 'referral_code', 'referral_count', 'date_joined', 'is_email_verified']
        extra_kwargs = {
            'password': {'write_only': True},
            'user_id': {'read_only': True},
            'referral_count': {'read_only': True},
            'date_joined': {'read_only': True},
            'is_email_verified': {'read_only': True}
        }

    def create(self, validated_data):
        validated_data['email'] = validated_data['email'].lower()
        referral_code = validated_data.pop('referral_code', None)

        # Extract and handle full_name
        full_name = validated_data.pop('full_name', '')
        name_parts = full_name.split(' ', 1)
        first_name = name_parts[0] if name_parts else ''
        last_name = name_parts[1] if len(name_parts) > 1 else ''

        with transaction.atomic():  # Ensures atomicity
            # Create the User
            user = User.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password'],
                first_name=first_name,
                last_name=last_name,
                full_name=full_name
            )

            # Create the UserProfile
            UserProfile.objects.create(user=user)

            # Create the UserWallet
            UserWallet.objects.create(user=user, balance=0.0)  # Initialize with 0 balance

            # Handle Referral System
            if referral_code:
                try:
                    referrer = User.objects.get(referral_code=referral_code)
                    referrer.referral_count += 1
                    referrer.save()
                    user.referred_by = referrer
                    user.save()
                except User.DoesNotExist:
                    pass

        return user



class AdminRegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for admin user registration.
    Includes passkey validation for admin creation.
    """
    passkey = serializers.CharField(max_length=6, write_only=True)
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'passkey', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        # Validate admin passkey
        if data.get('passkey') != AdminSettings.objects.first().passkey:
            raise serializers.ValidationError("Invalid admin passkey.")
        return data

    def create(self, validated_data):
        validated_data.pop('passkey')
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            is_admin=True,
            is_verified=True
        )
        user.set_password(validated_data['password'])
        user.save()
        UserWallet.objects.create(user=user)
        UserProfile.objects.create(user=user)
        return user


class ForgotPasswordSerializer(serializers.Serializer):
    """
    Serializer for handling password reset requests.
    Validates username and admin passkey before allowing password change.
    """
    username = serializers.CharField(max_length=150)
    passkey = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        # Validate username and passkey
        try:
            User.objects.get(username=data['username'])
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid username.")

        if AdminSettings.objects.first().passkey != data['passkey']:
            raise serializers.ValidationError("Invalid passkey.")

        return data

    def save(self):
        user = User.objects.get(username=self.validated_data['username'])
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class ChangePasswordAdminSerializer(serializers.Serializer):
    """
    Serializer for handling admin password change requests.
    Validates old password before allowing the change.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        if not check_password(value, self.context['request'].user.password):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def validate_new_password(self, value):
        if len(value) < 6:
            raise serializers.ValidationError("New password must be at least 6 characters long.")
        return value

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user
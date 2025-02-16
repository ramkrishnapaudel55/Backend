import logging
from datetime import timezone, timedelta, datetime, date

from django.utils.dateparse import parse_date
from phonenumber_field.serializerfields import PhoneNumberField
from .models import Advertisement, UserWallet, UserTransaction, UserProfile, Notification, Proof
from django.contrib.auth.models import AbstractUser
from rest_framework import serializers

from rest_framework import serializers

from superuser.models import UserDashboard, AdminAdvertisement

from django.contrib.auth import get_user_model


class AdvertisementSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.CharField(source='user.user_id', read_only=True)
    terminate = serializers.DateField(format="%Y-%m-%d", input_formats=["%Y-%m-%d", "iso-8601"])

    class Meta:
        model = Advertisement
        fields = [
            'id', 'title', 'category', 'budget', 'remaining_budget',
            'per_job', 'limit', 'description', 'confirmation_requirements',
            'requires_media', 'media_type', 'thumbnail', 'status',
            'user', 'terminate', 'created_at', 'submissions', 'youtube_link',
            'user_name', 'user_id'
        ]
        read_only_fields = ['id', 'created_at', 'remaining_budget', 'submissions']

    def to_internal_value(self, data):
        mutable_data = data.copy() if hasattr(data, 'copy') else data
        if 'terminate' in mutable_data:
            terminate_value = mutable_data['terminate']
            if isinstance(terminate_value, str):
                try:
                    parsed_date = parse_date(terminate_value)
                    if parsed_date is None:
                        raise ValueError("Invalid date format")
                    mutable_data['terminate'] = parsed_date
                except ValueError:
                    raise serializers.ValidationError({"terminate": "Invalid date format. Use YYYY-MM-DD."})
            elif isinstance(terminate_value, (date, datetime)):
                mutable_data['terminate'] = terminate_value.date() if isinstance(terminate_value,
                                                                                 datetime) else terminate_value
            else:
                raise serializers.ValidationError({"terminate": "Invalid data type. Expected string or date object."})
        return super().to_internal_value(mutable_data)

    def validate(self, data):
        # Determine the status (use existing status for partial updates)
        status = data.get('status', self.instance.status if self.instance else 'unapproved')
        # Skip full validation for drafts and partial updates
        if status == 'draft' or self.partial:
            return data

        required_fields = ['title', 'description', 'confirmation_requirements', 'budget', 'per_job', 'limit',
                           'category']
        errors = {}
        for field in required_fields:
            if field not in data and (not self.instance or not getattr(self.instance, field)):
                errors[field] = "This field is required."

        if data.get('limit') == 'days' and 'terminate' not in data and (
                not self.instance or not self.instance.terminate):
            errors['terminate'] = "Termination date must be provided for 'days' limit."

        if errors:
            raise serializers.ValidationError(errors)

        return data

    def create(self, validated_data):
        # Set default values for drafts
        if validated_data.get('status') == 'draft':
            validated_data.setdefault('budget', 0)
            validated_data.setdefault('per_job', 0)
            validated_data.setdefault('limit', 'days')
            validated_data.setdefault('terminate', (datetime.now() + timedelta(days=7)).date())
            validated_data.setdefault('description', 'description here')
            validated_data.setdefault('confirmation_requirements', 'To be provided')

        # Set remaining_budget equal to budget if not provided
        if 'remaining_budget' not in validated_data:
            validated_data['remaining_budget'] = validated_data.get('budget', 0)

        # Saving the category properly
        advertisement = super().create(validated_data)
        return advertisement

    def update(self, instance, validated_data):
        # Update instance with validated data
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Ensure remaining_budget is updated if the budget changes and remaining_budget is not set
        if 'budget' in validated_data and 'remaining_budget' not in validated_data:
            instance.remaining_budget = validated_data.get('budget', instance.remaining_budget)

        instance.save()
        return instance


class UserWalletSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.get_full_name', read_only=True)
    profile_photo = serializers.ImageField(source='user.userprofile.photo', read_only=True)
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)

    class Meta:
        model = UserWallet
        fields = ['id', 'balance', 'total_earning', 'total_spending', 'full_name', 'profile_photo', 'user_name',
                  'user_id']


class UserTransactionSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)
    advertisement_title = serializers.CharField(source='advertisement.title', read_only=True)

    class Meta:
        model = UserTransaction
        fields = ['id', 'user_name', 'user_id', 'advertisement_title', 'transaction_type', 'amount', 'date', 'status']


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AbstractUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'password']
        extra_kwargs = {'password': {'write_only': True}}


class AddBalanceSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)


class AdvertisementAllSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    reward = serializers.DecimalField(source='per_job', max_digits=10, decimal_places=2)

    class Meta:
        model = Advertisement
        fields = ['id', 'title', 'description', 'confirmation_requirements', 'reward', 'user_name', 'user_id',
                  'category_name',
                  'submissions', 'status', 'thumbnail', 'remaining_budget', 'budget']


class UserProfileSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    wallet_balance = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    referral_code = serializers.CharField(source='user.referral_code', read_only=True)
    referral_count = serializers.IntegerField(source='user.referral_count', read_only=True)
    phone_number = PhoneNumberField(required=False, allow_null=True, allow_blank=True)
    date_joined = serializers.DateField(source='user.date_joined', read_only=True)

    is_email_verified = serializers.BooleanField(source='user.is_email_verified', read_only=True)

    class Meta:
        model = UserProfile
        fields = ['id', 'user_name', 'user_id', 'email', 'first_name', 'last_name', 'photo', 'date_of_birth',
                  'age', 'nationality', 'gender', 'wallet_balance', 'referral_code', 'is_email_verified', 'referral_count', 'bio',
                  'phone_number', 'date_joined']
        read_only_fields = ['user_name', 'user_id', 'email', 'first_name', 'last_name', 'age', 'wallet_balance', 'id',
                            'date_joined']


class ProfileUpdateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    phone_number = PhoneNumberField(required=False, allow_null=True, allow_blank=True)
    photo = serializers.ImageField(required=False)

    class Meta:
        model = UserProfile
        fields = ['photo', 'date_of_birth', 'age', 'nationality', 'gender', 'phone_number', 'bio', 'first_name',
                  'last_name']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        instance = super().update(instance, validated_data)

        if user_data:
            user = instance.user
            user.first_name = user_data.get('first_name', user.first_name)
            user.last_name = user_data.get('last_name', user.last_name)
            user.save()

        return instance


class NotificationSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)

    class Meta:
        model = Notification
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'user', 'user_name', 'user_id']


class ProofSerializer(serializers.ModelSerializer):
    photo = serializers.ImageField(required=False, allow_null=True)
    video = serializers.FileField(required=False, allow_null=True)
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)

    class Meta:
        model = Proof
        fields = ['id', 'photo', 'video', 'advertisement', 'status', 'advertisement_title', 'proof_id', 'user_name',
                  'user_id']
        read_only_fields = ['proof_id']

    def validate(self, data):
        advertisement = self.get_advertisement()
        media_type = advertisement.media_type

        if media_type == 'photo' and not data.get('photo'):
            raise serializers.ValidationError("This proof requires a photo to be submitted.")
        if media_type == 'video' and not data.get('video'):
            raise serializers.ValidationError("This proof requires a video to be submitted.")
        if media_type == 'both':
            if not data.get('photo'):
                raise serializers.ValidationError("This proof requires a photo to be submitted.")
            if not data.get('video'):
                raise serializers.ValidationError("This proof requires a video to be submitted.")

        data['advertisement'] = advertisement
        data['user'] = self.context.get('user')
        return data

    def get_advertisement(self):
        advertisement_id = self.context.get('advertisement_id')
        if not advertisement_id:
            raise serializers.ValidationError("No advertisement ID provided.")
        try:
            return Advertisement.objects.get(id=advertisement_id)
        except Advertisement.DoesNotExist:
            raise serializers.ValidationError("Advertisement not found.")


class CategoryListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Advertisement
        fields = ['id', 'title', 'budget', 'remaining_budget', 'per_job', 'description', 'status', 'thumbnail',
                  'youtube_link', 'created_at']


# Serializer to group advertisements by category
class CategoryAdvertisementSerializer(serializers.Serializer):
    category = serializers.CharField()  # Category name
    advertisements = CategoryListSerializer(many=True)  # List of advertisements under the category


class UserDashboardSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDashboard
        fields = ['id', 'photo', 'video', 'created_at', 'priority']


class AdminAdvertisementSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminAdvertisement
        fields = [
            'id', 'title', 'details', 'discounts', 'offers', 'referral_code',
            'guidelines', 'links', 'thumbnail', 'is_running', 'duration',
            'priority', 'created_at', 'updated_at'
        ]


class ChangeProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['photo']

    def update(self, instance, validated_data):
        instance.photo = validated_data.get('photo', instance.photo)
        instance.save()
        return instance


User = get_user_model()


class ChangeNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name']

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.save()
        return instance


class ChangeEmailSerializer(serializers.ModelSerializer):
    new_email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ['new_email']

    def validate_new_email(self, value):
        # Check if email is already in use
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def update(self, instance, validated_data):
        instance.email = validated_data['new_email']
        instance.save()
        return instance


class AdminProfileSerializer(serializers.ModelSerializer):
    user_id = serializers.ReadOnlyField(source="user.user_id")
    username = serializers.ReadOnlyField(source="user.username")
    email = serializers.ReadOnlyField(source="user.email")
    is_verified = serializers.ReadOnlyField(source="user.is_verified")
    photo = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            "user_id", "username", "email", "is_verified",
            "photo", "date_of_birth", "nationality", "gender", "bio", "phone_number"
        ]

    def get_photo(self, obj):
        """Returns the absolute URL for the photo."""
        request = self.context.get("request")
        if obj.photo and request:
            return request.build_absolute_uri(obj.photo.url)
        return None

    def update(self, instance, validated_data):
        """Updates the profile and handles photo uploads."""
        if "photo" in validated_data:
            instance.photo = validated_data["photo"]

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance



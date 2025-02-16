from rest_framework import serializers
from .models import AdminAdvertisement, UserDashboard, AdminNotification
from create.models import UserWallet, Advertisement, Proof, UserTransaction, UserProfile
from login.models import User


class AdminAdvertisementSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminAdvertisement
        fields = [
            'id',
            'title',
            'details',
            'discounts',
            'offers',
            'referral_code',
            'guidelines',
            'links',
            'thumbnail',
            'is_running',
            'duration',
            'priority',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_duration(self, value):
        """
        Ensure the duration is at least 1 day.
        """
        if value.total_seconds() < 86400:  # 1 day in seconds
            raise serializers.ValidationError("Duration must be at least 1 day.")
        return value


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'date_joined', 'is_admin', 'is_super_admin']
        read_only_fields = ['user_id', 'date_joined']


class WalletSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Nest user details

    class Meta:
        model = UserWallet
        fields = ['id', 'user', 'balance', 'total_earning', 'total_spending']
        read_only_fields = ['id']


class AdvertisementSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Include user details in the advertisement

    class Meta:
        model = Advertisement
        fields = [
            'id',
            'title',
            'category',
            'budget',
            'remaining_budget',
            'per_job',
            'limit',
            'description',
            'confirmation_requirements',
            'requires_media',
            'media_type',
            'thumbnail',
            'status',
            'terminate',
            'created_at',
            'submissions',
            'user',  # Include the user (advertiser) details
        ]
        read_only_fields = ['id', 'created_at', 'user']


class ProofSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Include user details in the proof
    advertisement = AdvertisementSerializer(read_only=True)  # Include ad details

    class Meta:
        model = Proof
        fields = ['id', 'user', 'photo', 'video', 'advertisement', 'status', 'advertisement_title']
        read_only_fields = ['id']


class TransactionSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Include user details in the transaction
    advertisement = AdvertisementSerializer(read_only=True)  # Include advertisement details

    class Meta:
        model = UserTransaction
        fields = ['id', 'user', 'advertisement', 'transaction_type', 'advertisement_title', 'amount', 'date', 'status']
        read_only_fields = ['id', 'date']


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Include user details in the profile

    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'photo', 'date_of_birth', 'nationality', 'gender', 'bio', 'phone_number']
        read_only_fields = ['id']


class AdminUserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new users by admin.
    Handles password hashing, verification, and referral logic.
    """
    password = serializers.CharField(write_only=True, required=True)
    referral_code = serializers.CharField(write_only=True, required=False, allow_blank=True)
    is_verified = serializers.BooleanField(required=False)  # Include is_verified in the serializer

    class Meta:
        model = User
        fields = ['user_id', 'username', 'email', 'first_name', 'last_name', 'password', 'referral_code',
                  'is_verified']  # Add is_verified
        read_only_fields = ['user_id']  # user_id is auto-generated

    def create(self, validated_data):
        password = validated_data.pop('password')
        referral_code = validated_data.pop('referral_code', None)
        is_verified = validated_data.pop('is_verified', False)  # Get is_verified from data

        # Create the user
        user = User(**validated_data)
        user.set_password(password)  # Hash the password
        user.is_verified = is_verified  # Set the verification status
        user.save()

        UserWallet.objects.create(user=user)  #added line
        UserProfile.objects.create(user=user)  #added line

        # Handle referral code logic
        if referral_code:
            try:
                referrer = User.objects.get(referral_code=referral_code)
                referrer.referral_count += 1
                referrer.save()
                user.referred_by = referrer
                user.save()
            except User.DoesNotExist:
                pass  # Handle invalid referral code case

        return user


class AdminAdvertisementCreateSerializer(serializers.ModelSerializer):
    user_id = serializers.CharField(write_only=True)  # Accept `user_id` from the request

    class Meta:
        model = Advertisement
        fields = [
            'user_id', 'title', 'category', 'budget', 'remaining_budget', 'per_job',
            'limit', 'description', 'confirmation_requirements', 'requires_media',
            'media_type', 'thumbnail', 'terminate'
        ]
        extra_kwargs = {'remaining_budget': {'required': False}}

    def validate_user_id(self, value):
        try:
            # Fetch the user object using the `user_id`
            user = User.objects.get(user_id=value)  # Use `user_id` to retrieve the user
            return user
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this ID does not exist.")

    def create(self, validated_data):
        # Retrieve the validated user object and assign it to 'user'
        user = self.validated_data.get('user_id')  # This retrieves the user object from `validate_user_id`
        validated_data['user'] = user  # Explicitly set the user in the validated data
        validated_data['remaining_budget'] = validated_data.get('budget', 0)
        return Advertisement.objects.create(**validated_data)  # Create the advertisement


class AdminActionSerializer(serializers.Serializer):
    ad_id = serializers.CharField(max_length=5)


class AdminNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminNotification
        fields = ['id', 'message', 'is_read', 'created_at']


class UserDashboardSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDashboard
        fields = ['id', 'photo', 'video', 'priority']  # Add fields that you need to handle

    # Custom validation to ensure either photo or video is provided, not both
    def validate(self, data):
        """Ensure that either photo or video is provided, not both."""
        photo = data.get('photo')
        video = data.get('video')

        # Handle creation (POST): At least one of photo or video must be provided
        if self.instance is None:
            if not photo and not video:
                raise serializers.ValidationError('You must upload either a photo or a video.')

        # Handle updates (PUT/PATCH): Allow updates without photo/video unless they're being modified
        else:
            if 'photo' in data and 'video' in data:
                if data.get('photo') and data.get('video'):
                    raise serializers.ValidationError('You can upload only one: either a photo or a video.')
            elif not self.partial and not photo and not video:
                raise serializers.ValidationError('You must upload either a photo or a video.')

        return data

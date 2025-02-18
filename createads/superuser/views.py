from django.contrib.auth import authenticate
from django.db.models.functions import TruncDate
from django.db.models import Count, Sum
from django.http import Http404
from django.utils import timezone
from django.utils.timezone import make_aware
from django.conf import settings
from django.conf.urls.static import static
from datetime import datetime, timedelta

from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .models import AdminAdvertisement, UserDashboard, AdminNotification
from create.models import Advertisement, Proof, UserTransaction, UserWallet, UserProfile, Notification
from login.models import User
from .serializers import (
    AdminAdvertisementSerializer, UserSerializer, WalletSerializer,
    AdvertisementSerializer, ProofSerializer, TransactionSerializer,
    UserProfileSerializer, AdminUserCreateSerializer, UserDashboardSerializer, AdminAdvertisementCreateSerializer,
    AdminActionSerializer, AdminNotificationSerializer
)
from .permissions import IsAdminUser  # Ensure this custom permission is correctly defined
from rest_framework.permissions import AllowAny, IsAuthenticated
from .permissions import IsAdminUserCustom

# Utility function for generating unique 5-character IDs
from .utils import generate_unique_id

from django.db.models import Case, When, IntegerField

from rest_framework import generics, permissions
from create.models import UserProfile
from create.serializers import UserProfileSerializer

from django.db import IntegrityError, transaction
from rest_framework.exceptions import ValidationError
import logging
from django.db import transaction

logger = logging.getLogger(__name__)


# --- Admin Advertisement Views ---


class AdminNotificationListView(generics.ListAPIView):
    permission_classes = [IsAdminUserCustom]  # Ensure only admins can access
    serializer_class = AdminNotificationSerializer

    def get_queryset(self):
        # Use self.request.user to fetch notifications for the logged-in admin
        return AdminNotification.objects.filter(user=self.request.user).order_by('-created_at')


class MarkAllNotificationsAsReadView(APIView):
    permission_classes = [IsAdminUserCustom]  # Ensure only admins can access

    def patch(self, request):
        user = request.user  # The logged-in admin
        # Mark all unread notifications for this admin as read
        unread_notifications = AdminNotification.objects.filter(user=user, is_read=False)
        unread_notifications.update(is_read=True)  # Bulk update
        return Response({"message": "All notifications marked as read."}, status=status.HTTP_200_OK)


class AdminAdvertisementListCreateView(generics.ListCreateAPIView):
    """
    Admin view to list all advertisements or create a new advertisement.
    Only accessible by admin users.
    """
    queryset = AdminAdvertisement.objects.all().order_by('priority')
    serializer_class = AdminAdvertisementSerializer
    permission_classes = [IsAdminUserCustom]

    def get_serializer_context(self):
        """
        Ensure that the serializer gets the request context,
        which is needed for building absolute URLs.
        """
        return {'request': self.request}

    def perform_create(self, serializer):
        serializer.save()


class AdminAdvertisementDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin view to retrieve, update (partial or full), or delete a specific advertisement.
    Only accessible by admin users.
    """
    queryset = AdminAdvertisement.objects.all()
    serializer_class = AdminAdvertisementSerializer
    permission_classes = [IsAdminUserCustom]  # Modify this to restrict access as needed
    lookup_field = 'id'  # Assuming 'id' is the 6-character alphanumeric field

    def update(self, request, *args, **kwargs):
        """
        Override the update method to allow for partial updates.
        """
        partial = kwargs.pop('partial', False)  # Get whether the update is partial or full
        instance = self.get_object()  # Get the instance to update
        serializer = self.get_serializer(instance, data=request.data,
                                         partial=partial)  # Pass 'partial' flag to the serializer

        serializer.is_valid(raise_exception=True)  # Validate the data
        self.perform_update(serializer)  # Save the updates

        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        """
        Handle partial updates via PATCH request.
        """
        kwargs['partial'] = True  # Set partial=True to allow partial updates
        return self.update(request, *args, **kwargs)


class UserDashboardDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserDashboard.objects.all()
    serializer_class = UserDashboardSerializer
    permission_classes = [IsAdminUserCustom]
    lookup_field = 'id'  # This will match the 'id' field in the URL for lookup

    # Overriding the delete method to return custom response
    def delete(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response({'detail': 'UserDashboard object deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Overriding the update method for partial updates
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)  # To allow partial updates using PATCH
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


from collections import defaultdict  # Add this import
from django.db.models import Count, Sum, Avg  # Add Avg here


# --- Dashboard View ---
class DashboardAPIView(APIView):
    permission_classes = [permissions.AllowAny]  # Restrict to admin users

    def get(self, request):
        end_date = timezone.now()
        start_date = end_date - timedelta(days=30)  # Last 30 days

        # User Statistics
        users = User.objects.all()
        total_users = users.count()
        new_users = users.filter(date_joined__range=(start_date, end_date)).count()
        user_status = {
            'active': users.filter(is_active=True).count(),
            'inactive': users.filter(is_active=False).count()
        }

        # Manually group user signups by date in Python (since TruncDate is not supported in SQLite)
        user_growth = users.filter(date_joined__range=(start_date, end_date)).values('date_joined')
        user_growth_data = defaultdict(int)
        for user in user_growth:
            date_str = user['date_joined'].strftime('%Y-%m-%d')  # Corrected this line
            user_growth_data[date_str] += 1

        user_growth_list = [{'date': date, 'count': count} for date, count in user_growth_data.items()]

        # Gender distribution (assuming you have a UserProfile model with a gender field)
        gender_distribution = UserProfile.objects.values('gender').annotate(count=Count('user_id'))

        # Advertisement Statistics
        ads = Advertisement.objects.all()
        total_advertisements = ads.count()
        ads_by_status = dict(ads.values('status').annotate(count=Count('id')).values_list('status', 'count'))
        ads_by_category = dict(ads.values('category').annotate(count=Count('id')).values_list('category', 'count'))

        # Manually group ad creation by date in Python
        ad_creation_trend = ads.filter(created_at__range=(start_date, end_date)).values('created_at')
        ad_creation_data = defaultdict(int)
        for ad in ad_creation_trend:
            date_str = ad['created_at'].date().strftime('%Y-%m-%d')
            ad_creation_data[date_str] += 1

        ad_creation_list = [{'date': date, 'count': count} for date, count in ad_creation_data.items()]

        # Transaction Statistics
        transactions = UserTransaction.objects.all()
        total_transactions = transactions.count()
        transaction_volume = transactions.aggregate(total_amount=Sum('amount'))['total_amount'] or 0
        transactions_by_type = dict(
            transactions.values('transaction_type').annotate(total_amount=Sum('amount')).values_list('transaction_type',
                                                                                                     'total_amount')
        )

        # Manually group transactions by date
        transaction_trend = transactions.filter(date__range=(start_date, end_date)).values('date')
        transaction_data = defaultdict(int)
        for transaction in transaction_trend:
            date_str = transaction['date'].strftime('%Y-%m-%d')
            transaction_data[date_str] += 1

        transaction_trend_list = [{'date': date, 'total': count} for date, count in transaction_data.items()]

        # Proof Statistics
        proofs = Proof.objects.all()
        total_proofs = proofs.count()
        proofs_by_status = dict(proofs.values('status').annotate(count=Count('id')).values_list('status', 'count'))

        # Manually group proof submissions by date
        proof_submission_trend = proofs.filter(created_at__range=(start_date, end_date)).values('created_at')
        proof_submission_data = defaultdict(int)
        for proof in proof_submission_trend:
            date_str = proof['created_at'].date().strftime('%Y-%m-%d')
            proof_submission_data[date_str] += 1

        proof_submission_list = [{'date': date, 'count': count} for date, count in proof_submission_data.items()]

        # Wallet Statistics
        total_wallet_balance = UserWallet.objects.aggregate(total=Sum('balance'))['total'] or 0
        avg_wallet_balance = UserWallet.objects.aggregate(avg=Avg('balance'))['avg'] or 0

        data = {
            'user_statistics': {
                'total_users': total_users,
                'new_users': new_users,
                'user_status': user_status,
                'user_growth': user_growth_list,
                'gender_distribution': list(gender_distribution)
            },
            'advertisement_statistics': {
                'total_advertisements': total_advertisements,
                'advertisements_by_status': ads_by_status,
                'advertisements_by_category': ads_by_category,
                'ad_creation_trend': ad_creation_list
            },
            'transaction_statistics': {
                'total_transactions': total_transactions,
                'transaction_volume': transaction_volume,
                'transactions_by_type': transactions_by_type,
                'transaction_trend': transaction_trend_list
            },
            'proof_statistics': {
                'total_proofs': total_proofs,
                'proofs_by_status': proofs_by_status,
                'proof_submission_trend': proof_submission_list
            },
            'wallet_statistics': {
                'total_wallet_balance': total_wallet_balance,
                'average_wallet_balance': avg_wallet_balance
            }
        }

        return Response(data, status=200)


# --- Wallet Views ---

class WalletListView(generics.ListAPIView):
    """
    Admin view to list all user wallets.
    Only accessible by admin users.
    """
    queryset = UserWallet.objects.all()
    serializer_class = WalletSerializer
    permission_classes = [IsAdminUserCustom]


class WalletDetailView(generics.RetrieveUpdateAPIView):
    """
    Admin view to retrieve or update a specific user's wallet using the user's ID.
    Only accessible by admin users.
    """
    queryset = UserWallet.objects.all()
    serializer_class = WalletSerializer
    permission_classes = [IsAdminUserCustom]

    def get_object(self):
        # Get the user_id from the URL
        user_id = self.kwargs.get('user_id')

        # Fetch the wallet for the given user_id
        try:
            wallet = UserWallet.objects.get(user_id=user_id)
            return wallet
        except UserWallet.DoesNotExist:
            raise Http404("Wallet not found for this user.")


# --- User Management Views ---


class UserListview(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUserCustom]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        # Return the serialized data as an array
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin view to retrieve, update, or delete a specific user.
    Only accessible by admin users.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUserCustom]
    lookup_field = 'user_id'  # Assuming 'id' is the 5-character alphanumeric field


# --- Advertisement Management Views ---


class AdvertisementListCreateView(generics.ListCreateAPIView):
    """
    Admin view to list all advertisements or create a new advertisement.
    Only accessible by admin users.
    """
    serializer_class = AdvertisementSerializer
    permission_classes = [IsAdminUserCustom]

    def get_queryset(self):
        queryset = Advertisement.objects.all()

        # Get filter parameters from the request
        filter_by = self.request.query_params.get('filter', None)

        # Default: order by budget (highest to lowest)
        if not filter_by:
            queryset = queryset.order_by('-budget')

        # Filter by per_job (highest to lowest)
        elif filter_by == 'per_job':
            queryset = queryset.order_by('-per_job')

        # Filter by status, first by Active, then Unapproved, Completed, and Draft
        elif filter_by == 'status':
            queryset = queryset.order_by(
                Case(
                    When(status='Active', then=1),
                    When(status='unapproved', then=2),
                    When(status='completed', then=3),
                    When(status='draft', then=4),
                    default=5,
                    output_field=IntegerField(),
                )
            )

        # Filter all unapproved advertisements, oldest first
        elif filter_by == 'unapproved':
            queryset = queryset.filter(status='unapproved').order_by('created_at')

        # Filter by terminate date (nearest terminate to oldest)
        elif filter_by == 'terminate':
            queryset = queryset.order_by('terminate')

        # Additional filtering logic can be added here

        return queryset


class AdvertisementDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin view to retrieve, update, or delete a specific advertisement.
    Only accessible by admin users.
    """
    queryset = Advertisement.objects.all()
    serializer_class = AdvertisementSerializer
    permission_classes = [IsAdminUserCustom]
    lookup_field = 'id'  # Assuming 'id' is the 5-character alphanumeric field


# --- Proof Management Views ---
class ProofListView(generics.ListAPIView):
    """
    Admin view to list all proofs filtered by user_id and advertisement_title.
    Only accessible by admin users.
    """
    serializer_class = ProofSerializer
    permission_classes = [IsAdminUserCustom]

    def get_queryset(self):
        """
        Optionally filters the queryset by user_id and advertisement_title passed as query parameters.
        Logs the received query parameters and filtered queryset.
        """
        queryset = Proof.objects.all()

        # Get query parameters from the request
        user_id = self.request.query_params.get('user_id')
        advertisement_title = self.request.query_params.get('advertisement_title')

        # Log the received query parameters
        logger.debug(f"Received query parameters: user_id={user_id}, advertisement_title={advertisement_title}")

        # Filter proofs based on user_id and advertisement_title if provided
        if user_id:
            queryset = queryset.filter(user__id=user_id)
        if advertisement_title:
            queryset = queryset.filter(advertisement_title__icontains=advertisement_title)

        # Log the filtered queryset count
        logger.debug(f"Filtered queryset contains {queryset.count()} proofs")

        return queryset

    def list(self, request, *args, **kwargs):
        """
        Override list method to log the response data before returning it.
        """
        response = super().list(request, *args, **kwargs)

        # Log the serialized response data
        logger.debug(f"Responding with {len(response.data)} proofs")

        return response


class ProofDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin view to retrieve, update, or delete a specific proof.
    Only accessible by admin users.
    """
    queryset = Proof.objects.all()
    serializer_class = ProofSerializer
    permission_classes = [IsAdminUserCustom]
    lookup_field = 'id'  # Assuming 'id' is the 5-character alphanumeric field


# --- Transaction Management Views ---

class TransactionListView(generics.ListAPIView):
    """
    Admin view to list all user transactions for a specific user.
    Only accessible by admin users.
    """
    serializer_class = TransactionSerializer
    permission_classes = [IsAdminUserCustom]

    def get_queryset(self):
        user_id = self.kwargs.get('user_id')  # Extract user_id from URL path
        return UserTransaction.objects.filter(user=user_id)  # Filter transactions by user_id


class TransactionDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin view to retrieve, update, or delete a specific transaction.
    Only accessible by admin users.
    """
    queryset = UserTransaction.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [IsAdminUserCustom]
    lookup_field = 'id'  # Assuming 'id' is the 5-character alphanumeric field


# --- User Profile Management Views ---

class UserProfileListView(generics.ListAPIView):
    """
    Admin view to list all user profiles.
    Only accessible by admin users.
    """
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAdminUserCustom]


class UserProfileDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin view to retrieve, update, or delete a specific user profile.
    Only accessible by admin users.
    """
    serializer_class = UserProfileSerializer
    permission_classes = [IsAdminUserCustom]
    lookup_field = 'user__user_id'  # Custom lookup field based on User's user_id

    def get_object(self):
        user_id = self.kwargs['id']
        try:
            return UserProfile.objects.get(user__user_id=user_id)  # Directly access UserProfile via user__user_id
        except UserProfile.DoesNotExist:
            raise Http404("UserProfile not found.")


class UserDashboardCreateAPIView(APIView):
    # Allow any user to access this view
    permission_classes = [IsAdminUserCustom]

    # Handle GET requests to fetch all dashboard objects
    def get(self, request, *args, **kwargs):
        dashboard_objects = UserDashboard.objects.all()  # Fetch all dashboard objects
        serializer = UserDashboardSerializer(dashboard_objects, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Handle POST requests to create a new dashboard object
    def post(self, request, *args, **kwargs):
        serializer = UserDashboardSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminUserCreateView(APIView):
    """
    Admin view to create a new user.
    Handles custom logic for user creation, including setting user verification.
    Only accessible by admin users.
    """
    permission_classes = [IsAdminUserCustom]  # Only admin users can access

    def post(self, request, *args, **kwargs):
        # Initialize serializer with request data
        serializer = AdminUserCreateSerializer(data=request.data)

        # Check if the data is valid
        if serializer.is_valid():
            try:
                # Custom user creation logic
                user = self.create_user(serializer)

                # Log success
                logger.info(f"User {user.username} created successfully by admin. Verified: {user.is_verified}")

                # Return success response
                return Response({"detail": "User created successfully."}, status=status.HTTP_201_CREATED)

            # Handle case where the email already exists or other integrity issues
            except IntegrityError:
                logger.warning(f"User with email {request.data.get('email')} already exists.")
                return Response({"detail": "User with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

            # Handle validation errors
            except ValidationError as e:
                logger.warning(f"Validation error: {e}")
                return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            # Handle any unexpected errors
            except Exception as e:
                logger.error(f"Unexpected error during user creation: {e}", exc_info=True)
                return Response({"detail": "An unexpected error occurred."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            # Log serializer errors if validation fails
            self.log_serializer_errors(serializer)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_user(self, serializer):
        """
        Custom method to create a user. This method handles password hashing,
        setting verification, referral code, and other custom logic.
        """
        user = serializer.save()

        # Additional logic for the user (e.g., generating a referral code)
        user.generate_referral_code()  # Assuming this method is defined in the User model
        user.generate_otp()  # Assuming this method is defined in the User model

        logger.debug(f"User created with ID: {user.user_id}, Verified: {user.is_verified}")
        return user

    def log_serializer_errors(self, serializer):
        """
        Log serializer errors for debugging purposes.
        """
        for field, errors in serializer.errors.items():
            logger.error(f"Field: {field}, Errors: {errors}")


logger = logging.getLogger(__name__)


class AdminAdvertisementCreateView(APIView):
    """
    Admin view to create an advertisement on behalf of a user.
    """
    permission_classes = [IsAdminUserCustom]

    def post(self, request):
        # Log incoming request data
        logger.debug(f"Received data from frontend: {request.data}")

        thumbnail = request.FILES.get('thumbnail')

        # Include thumbnail in the data to be validated if needed
        data = request.data
        if thumbnail:
            data['thumbnail'] = thumbnail

        # Ensure remaining_budget is set
        request.data['remaining_budget'] = request.data.get('budget', '0')

        # Validate and serialize the data
        serializer = AdminAdvertisementCreateSerializer(data=request.data)
        if serializer.is_valid():
            logger.debug(f"Validated data: {serializer.validated_data}")
            try:
                # Fetch the user object using the validated user_id
                user = serializer.validated_data.pop('user_id')  # This will now contain the user object
                return self.create_advertisement(user,
                                                 serializer.validated_data)  # Pass user to the create_advertisement method
            except Exception as e:
                logger.error(f"Error while creating advertisement: {str(e)}", exc_info=True)
                return Response({"detail": "An error occurred while creating the advertisement."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            logger.error(f"Invalid data: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def create_advertisement(self, user, validated_data):
        """
        Create the advertisement on behalf of the user.
        """
        with transaction.atomic():
            try:
                logger.debug(f"Fetching user wallet for user: {user.user_id}")
                user_wallet = UserWallet.objects.select_for_update().get(user=user)

                ad_budget = validated_data.get('budget', 0)
                logger.debug(f"User wallet balance: {user_wallet.balance}, Advertisement budget: {ad_budget}")

                if user_wallet.balance >= ad_budget:
                    # Deduct budget from user's wallet
                    user_wallet.balance -= ad_budget
                    user_wallet.save()

                    # Create advertisement
                    logger.debug(f"Creating advertisement for user: {user.user_id}")
                    advertisement = Advertisement.objects.create(
                        user=user,
                        status='Active',  # Set status as Active by default
                        **validated_data
                    )

                    # Log advertisement creation
                    logger.debug(f"Advertisement created with ID: {advertisement.id}")

                    # Create transaction and notification
                    self.create_user_transaction(user, advertisement, ad_budget)
                    self.create_notification(user, advertisement)

                    # Log success response
                    logger.debug(f"Advertisement creation successful for user: {user.user_id}")

                    return Response({
                        "message": "Advertisement created successfully and is now active.",
                        "spend": ad_budget,
                        "remaining_balance": user_wallet.balance,
                        "ad_id": advertisement.id
                    }, status=status.HTTP_201_CREATED)
                else:
                    logger.warning(f"Insufficient balance in user's wallet: {user_wallet.balance}")
                    return Response({"detail": "Insufficient balance in user's wallet."},
                                    status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Error during advertisement creation for user {user.user_id}: {str(e)}", exc_info=True)
                raise

    def create_user_transaction(self, user, advertisement, ad_budget):
        """
        Create a transaction for the advertisement creation.
        """
        try:
            UserTransaction.objects.create(
                user=user,
                advertisement=advertisement,
                transaction_type='spend',
                advertisement_title=advertisement.title,
                amount=ad_budget,
                status='approved'  # Set as approved since it's created by admin
            )
            logger.debug(f"Transaction created for user: {user.user_id}, advertisement: {advertisement.id}")
        except Exception as e:
            logger.error(f"Error creating transaction for user {user.user_id}: {str(e)}", exc_info=True)
            raise

    def create_notification(self, user, advertisement):
        """
        Create a notification for the user after the advertisement is created.
        """
        try:
            Notification.objects.create(
                user=user,
                message=f"An advertisement '{advertisement.title}' has been created for you by an admin and is now active."
            )
            logger.debug(f"Notification created for user: {user.user_id}, advertisement: {advertisement.id}")
        except Exception as e:
            logger.error(f"Error creating notification for user {user.user_id}: {str(e)}", exc_info=True)
            raise


class AdminApproveDeleteAdvertisementView(APIView):
    """Admin view to approve or delete advertisements."""

    permission_classes = [IsAdminUserCustom]  # Ensure only admin can access this view

    def post(self, request):
        serializer = AdminActionSerializer(data=request.data)
        if serializer.is_valid():
            ad_id = serializer.validated_data['ad_id']
            try:
                advertisement = Advertisement.objects.get(id=ad_id)
            except Advertisement.DoesNotExist:
                return Response({"detail": "Advertisement not found."}, status=status.HTTP_404_NOT_FOUND)

            if 'approve' in request.data:
                return self.approve_advertisement(advertisement)
            elif 'delete' in request.data:
                return self.delete_advertisement(advertisement)
            else:
                return Response({"detail": "Invalid action."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def approve_advertisement(self, advertisement):
        """Approve advertisement and update transactions."""

        advertisement.status = 'Active'
        advertisement.save()

        transactions = UserTransaction.objects.filter(advertisement=advertisement, status='pending')
        for transaction in transactions:
            transaction.status = 'approved'
            transaction.save()

        # Notify the user
        notification_message = f"Hurray! Your ad '{advertisement.title}' is approved by admin. See it in Earn."
        Notification.objects.create(
            user=advertisement.user,
            message=notification_message
        )

        return Response({
            "message": "Advertisement approved and notifications sent.",
            "ad_id": advertisement.id
        }, status=status.HTTP_200_OK)

    def delete_advertisement(self, advertisement):
        """Delete advertisement and handle refunding if applicable."""
        with transaction.atomic():
            user_wallet = advertisement.user.userwallet
            ad_budget = advertisement.budget

            # Handle refund based on status
            if advertisement.status in ['active', 'unapproved']:
                user_wallet.balance += ad_budget
                user_wallet.save()

            # Delete advertisement
            advertisement.delete()

            # Notify the user
            notification_message = "Your advertisement has been deleted by admin."
            Notification.objects.create(
                user=advertisement.user,
                message=notification_message
            )

            return Response({
                "message": "Advertisement deleted and notifications sent.",
                "ad_id": advertisement.id
            }, status=status.HTTP_200_OK)

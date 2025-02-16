import logging
from collections import defaultdict
from datetime import timedelta, datetime, date
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import transaction
from django.db.models import F
from django.shortcuts import get_object_or_404

from rest_framework import generics, status, permissions, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.exceptions import ValidationError, NotFound

from .models import Advertisement, UserWallet, UserTransaction, UserProfile, Notification, Proof
from .permissions import IsAdminUserCustom
from .serializers import (
    AdvertisementSerializer, UserWalletSerializer, UserTransactionSerializer,
    AddBalanceSerializer, AdvertisementAllSerializer, UserProfileSerializer,
    ProfileUpdateSerializer, NotificationSerializer, ProofSerializer, CategoryListSerializer, UserDashboardSerializer,
    AdminAdvertisementSerializer, ChangeProfilePictureSerializer, ChangeNameSerializer, AdminProfileSerializer, ChangeEmailSerializer
)
from .pagination import CustomPagination
from superuser.models import AdminNotification, AdminAdvertisement, UserDashboard

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

User = get_user_model()


# Notification Views
# ==================
class NotificationListView(generics.ListAPIView):
    """Fetch and paginate notifications for the authenticated user."""
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPagination

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class NotificationMarkAsReadView(APIView):
    """Mark a single notification as read."""
    permission_classes = [IsAuthenticated]

    def post(self, request, notification_id):
        notification = self.get_notification(notification_id)
        if not notification:
            return Response({"detail": "Notification not found."}, status=status.HTTP_404_NOT_FOUND)

        notification.is_read = True
        notification.save()
        return Response({"detail": "Notification marked as read."}, status=status.HTTP_200_OK)

    def get_notification(self, notification_id):
        return Notification.objects.filter(id=notification_id, user=self.request.user).first()


class MarkAllNotificationsAsReadView(APIView):
    """Mark all notifications as read for the authenticated user."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        unread_notifications = Notification.objects.filter(user=request.user, is_read=False)
        unread_notifications.update(is_read=True)
        return Response({"detail": "All notifications marked as read."}, status=status.HTTP_200_OK)


# Advertisement Views
# ===================
class AdvertisementViewSet(viewsets.ModelViewSet):
    """ViewSet to manage Advertisement CRUD operations."""
    queryset = Advertisement.objects.all()
    serializer_class = AdvertisementSerializer


class AdvertisementListView(generics.ListAPIView):
    """List advertisements for the authenticated user, filtered by status."""
    serializer_class = AdvertisementSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPagination  # Use custom pagination

    def get_queryset(self):
        user = self.request.user
        status = self.request.query_params.get('status', None)
        queryset = Advertisement.objects.filter(user=user).order_by('-created_at')  # Order by created_at descending

        if status and status != 'all':
            queryset = queryset.filter(status=status)
        return queryset


class AdvertisementCreateView(APIView):
    """Create an advertisement with initial budget checks and default values."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        logger.debug(f"Received POST request: {request.data}")
        data = request.data.copy()
        data['user'] = request.user.pk

        # Set default values if missing
        self.set_default_values(data)

        # Calculate terminate date based on limit type (days/jobs)
        self.calculate_terminate_date(data)

        # Ensure remaining_budget is set
        data['remaining_budget'] = data.get('budget', '0')

        serializer = AdvertisementSerializer(data=data)
        if serializer.is_valid():
            return self.save_advertisement(serializer, request.user, data)
        else:
            logger.error(f"Serializer errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def set_default_values(self, data):
        """Set default values for required fields."""
        required_fields = {
            'title': 'Untitled',
            'category': 'default',
            'budget': '0',
            'per_job': '0',
            'limit': 'days',
            'description': 'To be filled',
            'confirmation_requirements': 'To be filled'
        }
        for field, default_value in required_fields.items():
            if field not in data or not data[field]:
                data[field] = default_value

    def calculate_terminate_date(self, data):
        """Calculate the terminate date based on the limit type (jobs or days)."""
        if data.get('limit') == 'jobs':
            budget = float(data.get('budget', 0))
            days = budget / 100  # Assuming $100 equals 1 day
            data['terminate'] = (datetime.now() + timedelta(days=days)).date()
        elif not data.get('terminate'):
            data['terminate'] = (datetime.now() + timedelta(days=7)).date()

    def save_advertisement(self, serializer, user, data):
        """Save advertisement with atomic transaction and update wallet balance."""
        with transaction.atomic():
            user_wallet = UserWallet.objects.select_for_update().get(user=user)
            ad_budget = serializer.validated_data.get('budget', 0)
            status_choice = data.get('status', 'unapproved')

            # For draft, save without deducting balance
            if status_choice == 'draft':
                advertisement = serializer.save()
                return self.create_response(0, user_wallet.balance, advertisement, status_choice)

            # Ensure sufficient balance for active advertisements
            if user_wallet.balance >= ad_budget:
                user_wallet.balance -= ad_budget
                user_wallet.save()
                advertisement = serializer.save()
                self.create_user_transaction(user, advertisement, ad_budget)
                self.create_notification(user, advertisement)

                # Add notification for admin if the advertisement is not a draft
                self.create_admin_notification(advertisement)

                return self.create_response(ad_budget, user_wallet.balance, advertisement, status_choice)
            else:
                return Response({"detail": "Insufficient balance in wallet."}, status=status.HTTP_400_BAD_REQUEST)

    def create_user_transaction(self, user, advertisement, ad_budget):
        """Log transaction for the advertisement budget deduction."""
        UserTransaction.objects.create(
            user=user,
            advertisement=advertisement,
            transaction_type='spend',
            advertisement_title=advertisement.title,
            amount=ad_budget,
            status='pending'
        )

    def create_notification(self, user, advertisement):
        """Notify user that their advertisement has been created."""
        Notification.objects.create(
            user=user,
            message=f"Your advertisement '{advertisement.title}' is created and waiting for approval."
        )

    def create_admin_notification(self, advertisement):
        """Create a notification for all admin users about the new unapproved advertisement."""
        message = f"New unapproved advertisement '{advertisement.title}' has been created and is waiting for approval."
        users = User.objects.filter(is_admin=True)  # Get all admin users

        for admin in users:
            AdminNotification.objects.create(
                user=admin,
                message=message
            )

    def create_response(self, ad_budget, remaining_balance, advertisement, status_choice):
        """Create a response object indicating the success or draft save."""
        message = "Advertisement saved as draft." if status_choice == 'draft' else (
            "Advertisement created successfully and is unapproved. Waiting for approval. Estimated time for approval is 1 hour."
        )
        return Response({
            "message": message,
            "spend": 0 if status_choice == 'draft' else ad_budget,
            "remaining_balance": remaining_balance,
            "ad_id": advertisement.id
        }, status=status.HTTP_201_CREATED)


# Add balance to wallet and adjust advertisement termination
class AddFundView(APIView):
    """Add funds to an advertisement and update termination date."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        with transaction.atomic():
            advertisement, user_wallet = self.get_advertisement_and_wallet(request.data, request.user)

            if user_wallet.balance < Decimal(request.data.get('amount')):
                return Response({"detail": "Insufficient balance in wallet."}, status=status.HTTP_400_BAD_REQUEST)

            self.update_funds_and_terminate(advertisement, user_wallet, request.data)

            # Notify admin about the fund addition
            self.create_admin_notification(advertisement, request.data.get('amount'))

            return Response({
                "detail": "Funds added successfully and termination date updated.",
                "remaining_budget": advertisement.remaining_budget,
                "terminate": advertisement.terminate,
            }, status=status.HTTP_200_OK)

    def get_advertisement_and_wallet(self, data, user):
        advertisement = Advertisement.objects.select_for_update().get(id=data.get('advertisement_id'))
        user_wallet = UserWallet.objects.select_for_update().get(user=user)
        return advertisement, user_wallet

    def update_funds_and_terminate(self, advertisement, user_wallet, data):
        amount = Decimal(data.get('amount'))
        user_wallet.balance -= amount
        user_wallet.save()

        advertisement.remaining_budget += amount
        advertisement.budget += amount

        if advertisement.status == 'completed':
            advertisement.status = 'Active'

        self.extend_termination_date(advertisement, amount)
        advertisement.save()

        self.log_fund_transaction(advertisement, user_wallet.user, amount)

        # Notify the user about the fund addition
        Notification.objects.create(
            user=user_wallet.user,
            message=f"Funds added to your advertisement '{advertisement.title}'. Termination date updated."
        )

    def extend_termination_date(self, advertisement, amount):
        original_budget = advertisement.budget - amount

        # Check if original_budget is zero or negative
        if original_budget <= 0:
            # Set a default extension percentage, e.g., 10%
            default_percentage = 10
            added_percentage = default_percentage
        else:
            # Calculate the added percentage normally
            added_percentage = (amount / original_budget) * 100

        # Calculate additional days based on the advertisement's limit type
        if advertisement.limit == 'jobs':
            additional_days = int((added_percentage / 100) * 60)  # 60 days as full period for jobs
        elif advertisement.limit == 'days':
            # Calculate additional days based on remaining days before termination
            remaining_days = (advertisement.terminate - timezone.now().date()).days
            additional_days = int((added_percentage / 100) * remaining_days)

        # Extend the termination date from the **current date**
        advertisement.terminate = timezone.now().date() + timedelta(days=additional_days)
        advertisement.save()

    def log_fund_transaction(self, advertisement, user, amount):
        UserTransaction.objects.create(
            user=user,
            advertisement=advertisement,
            transaction_type='spend',
            amount=amount,
            status='approved'
        )

    def create_admin_notification(self, advertisement, amount):
        """Notify all admin users about the fund addition to the advertisement."""
        message = f"An additional amount of {amount} has been added to the advertisement '{advertisement.title}'."
        users = User.objects.filter(is_admin=True)  # Get all admin users

        for admin in users:
            AdminNotification.objects.create(
                user=admin,
                message=message
            )


# Proof submission and approval views
class SubmitProofView(APIView):
    """Submit proof for an advertisement."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        """Submit proof, handle file uploads (photo/video), and create a pending transaction."""
        try:
            with transaction.atomic():
                advertisement = self.get_advertisement(request.data)

                if not advertisement:
                    return Response({"detail": "Advertisement not found."}, status=status.HTTP_404_NOT_FOUND)

                # Check if the advertisement has expired by comparing with terminate_date
                if advertisement.terminate and advertisement.terminate < date.today():
                    # Set the advertisement status to 'completed'
                    advertisement.status = 'completed'
                    advertisement.save()

                    # Notify the advertiser
                    Notification.objects.create(
                        user=advertisement.user,
                        message=f"Your advertisement '{advertisement.title}' has expired and is now completed."
                    )

                    return Response({"detail": "This advertisement has expired. Try a new advertisement."},
                                    status=status.HTTP_400_BAD_REQUEST)

                # Check if the user is trying to submit proof on their own advertisement
                if advertisement.user == request.user:
                    return Response({"detail": "You cannot submit proof for your own advertisement."},
                                    status=status.HTTP_403_FORBIDDEN)

                # Check if the remaining budget is more than per_job
                if advertisement.remaining_budget < advertisement.per_job:
                    return Response({"detail": "No rewards left."},
                                    status=status.HTTP_400_BAD_REQUEST)

                proof_serializer = self.prepare_proof_serializer(request, advertisement)

                if proof_serializer.is_valid():
                    return self.handle_proof_submission(proof_serializer, advertisement, request.user)
                else:
                    return Response({"errors from backend": proof_serializer.errors},
                                    status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_advertisement(self, data):
        """Fetch the advertisement based on advertisement ID."""
        return Advertisement.objects.filter(id=data.get('advertisement_id')).first()

    def prepare_proof_serializer(self, request, advertisement):
        """Prepare proof data including photo/video for serializer validation."""
        proof_data = {
            'advertisement': advertisement.id,
            'advertisement_title': advertisement.title,
            'status': 'unapproved',
            'user': request.user.pk
        }

        if 'photo' in request.FILES:
            proof_data['photo'] = request.FILES['photo']
        if 'video' in request.FILES:
            proof_data['video'] = request.FILES['video']

        return ProofSerializer(
            data=proof_data,
            context={'advertisement_id': advertisement.id, 'user': request.user}
        )

    def handle_proof_submission(self, proof_serializer, advertisement, user):
        """Save the proof, increment advertisement submissions, and create a pending transaction."""
        proof = proof_serializer.save()

        # Update advertisement's submission count
        advertisement.submissions += 1
        advertisement.save()

        # Log the user transaction for pending earnings
        UserTransaction.objects.create(
            user=user,
            advertisement=advertisement,
            advertisement_title=advertisement.title,
            transaction_type='earn',
            amount=advertisement.per_job,
            status='pending',
        )

        # Notify the advertiser
        Notification.objects.create(
            user=advertisement.user,
            message=f"A submission was made to your advertisement '{advertisement.title}'."
        )

        return Response({"detail": "Proof submitted and transaction created successfully."}, status=status.HTTP_200_OK)


class ApproveSubmissionView(APIView):
    """Approve or deny submission for an advertisement."""
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, advertisement_id):
        """Handle approval/denial of a submission."""
        try:
            with transaction.atomic():
                advertisement, proof = self.get_advertisement_and_proof(advertisement_id, request.data.get('proof_id'),
                                                                        request.user)

                if request.data.get('action', 'approve') == 'approve':
                    return self.approve_submission(proof, advertisement)
                else:
                    return self.deny_submission(proof, advertisement)

        except Advertisement.DoesNotExist:
            return Response({"detail": "Advertisement not found."}, status=status.HTTP_404_NOT_FOUND)
        except Proof.DoesNotExist:
            return Response({"detail": "Proof not found or already processed."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"detail": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_advertisement_and_proof(self, advertisement_id, proof_id, user):
        """Retrieve advertisement and proof objects."""
        advertisement = Advertisement.objects.get(id=advertisement_id, user=user)
        proof = Proof.objects.get(id=proof_id, advertisement=advertisement, status='unapproved')
        return advertisement, proof

    def approve_submission(self, proof, advertisement):
        """Approve the submission, update balances, and log the transaction."""
        amount_to_credit = advertisement.per_job

        # Check if remaining_budget is enough to approve the submission
        if advertisement.remaining_budget < amount_to_credit:
            # Change advertisement status to 'completed' if not enough remaining budget
            advertisement.status = 'completed'
            advertisement.save()
            return Response({"detail": "Remaining budget is insufficient, advertisement marked as completed."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Deduct from advertisement's budget and reduce submission count
        advertisement.remaining_budget -= amount_to_credit
        advertisement.submissions -= 1
        advertisement.save()

        # Credit the submitter's wallet
        user_wallet = UserWallet.objects.get(user=proof.user)
        user_wallet.balance += amount_to_credit
        user_wallet.save()

        # Mark proof as approved
        proof.status = 'approved'
        proof.save()

        # Log the transaction
        self.log_transaction(proof.user, advertisement, 'earn', amount_to_credit, 'approved')

        # Notify the submitter
        self.create_notification(proof.user,
                                 f"Your submission for advertisement '{advertisement.title}' has been approved.")

        return Response({"detail": "Submission approved, user wallet credited, and transaction logged."},
                        status=status.HTTP_200_OK)

    def deny_submission(self, proof, advertisement):
        """Deny the submission and refund the user."""
        amount_to_refund = advertisement.per_job

        advertisement.submissions -= 1
        advertisement.save()

        # Mark proof as denied
        proof.status = 'denied'
        proof.save()

        # Log the refund transaction
        self.log_transaction(proof.user, advertisement, 'earn', amount_to_refund, 'rejected')

        # Notify the submitter
        self.create_notification(proof.user,
                                 f"Your submission for advertisement '{advertisement.title}' has been denied.")

        return Response({"detail": "Submission denied, refund processed, and user notified."},
                        status=status.HTTP_200_OK)

    def log_transaction(self, user, advertisement, transaction_type, amount, status):
        """Log transactions for the wallet operations."""
        UserTransaction.objects.create(
            user=user,
            advertisement=advertisement,
            advertisement_title=advertisement.title,
            transaction_type=transaction_type,
            amount=amount,
            status=status
        )

    def create_notification(self, user, message):
        """Send a notification to the user."""
        Notification.objects.create(user=user, message=message)


# Wallet and transaction views
class UserWalletView(generics.RetrieveAPIView):
    """Retrieve the current user's wallet balance."""
    serializer_class = UserWalletSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return UserWallet.objects.get(user=self.request.user)


class UserTransactionListView(generics.ListAPIView):
    """List transactions for the authenticated user with optional date filters."""
    serializer_class = UserTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get_queryset(self):
        """Get the user's transactions and filter by date range."""
        user = self.request.user
        filter_value = self.request.query_params.get('filter', None)
        queryset = UserTransaction.objects.filter(user=user)

        if filter_value:
            now = timezone.now()
            queryset = self.filter_by_date_range(queryset, filter_value, now)

        return queryset.order_by(F('date').desc())

    def filter_by_date_range(self, queryset, filter_value, now):
        """Filter transactions by specific date range."""
        date_ranges = {
            '7days': now - timedelta(days=7),
            '15days': now - timedelta(days=15),
            '3months': now - timedelta(days=90)
        }
        if filter_value in date_ranges:
            start_date = date_ranges[filter_value]
            queryset = queryset.filter(date__gte=start_date)
        return queryset


# Balance addition view
class AddBalanceView(APIView):
    """Add balance to the user's wallet."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = AddBalanceSerializer(data=request.data)
        if serializer.is_valid():
            return self.add_balance(serializer, request.user)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    def add_balance(self, serializer, user):
        """Add balance to the user's wallet with transaction logging."""
        amount = serializer.validated_data['amount']
        user_wallet, created = UserWallet.objects.select_for_update().get_or_create(user=user)
        user_wallet.balance += amount
        user_wallet.save()

        # Log the transaction
        UserTransaction.objects.create(
            user=user,
            transaction_type='deposit',
            amount=amount,
            status='approved'
        )

        # Notify admin about the balance addition
        self.create_admin_notification(user, amount)

        return Response({"detail": "Balance added successfully."}, status=status.HTTP_200_OK)

    def create_admin_notification(self, user, amount):
        """Notify all admin users about the balance addition to the user's wallet."""
        message = f"User '{user.username}' has added {amount} to their wallet."
        admin_users = User.objects.filter(is_admin=True)

        AdminNotification.objects.bulk_create([
            AdminNotification(user=admin, message=message)
            for admin in admin_users
        ])


# Advertisement category-based views
class AdvertisementsByCategoryView(APIView):
    """Fetch advertisements based on a category."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, category_id):
        """Return advertisements based on the category ID."""
        advertisements = Advertisement.objects.filter(category_id=category_id)
        serializer = AdvertisementSerializer(advertisements, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserAdvertisementsByCategoryView(APIView):
    """Fetch advertisements grouped by category for the authenticated user."""
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """Group the user's advertisements by category."""
        user = request.user
        advertisements = Advertisement.objects.filter(user=user)

        # Group advertisements by category
        category_dict = defaultdict(list)
        for ad in advertisements:
            category_dict[ad.category].append(ad)

        # Serialize grouped data
        category_ad_data = []
        for category, ads in category_dict.items():
            category_ad_data.append({
                'category': category,
                'advertisements': CategoryListSerializer(ads, many=True).data
            })

        return Response(category_ad_data)


# Advertisement submission and detail views
class AdvertisementSubmissionsView(generics.ListAPIView):
    """List submissions for an advertisement based on the advertisement ID."""
    serializer_class = UserTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Get submissions for the specific advertisement."""
        advertisement_id = self.kwargs['advertisement_id']
        return UserTransaction.objects.filter(
            advertisement_id=advertisement_id,
            advertisement__user=self.request.user,
            transaction_type='earn',
            status='pending'
        )


class AdvertisementListAllView(generics.ListAPIView):
    """List all active advertisements for authenticated users with pagination and budget filtering."""
    serializer_class = AdvertisementAllSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get_queryset(self):
        """Return advertisements filtered by status and optionally remaining_budget."""
        queryset = Advertisement.objects.filter(status='Active')

        # Optional budget filtering
        budget_high = self.request.query_params.get('budget_high')
        budget_low = self.request.query_params.get('budget_low')

        if budget_high and budget_low:
            queryset = queryset.filter(
                remaining_budget__lte=budget_high,
                remaining_budget__gte=budget_low
            )

        return queryset


class SeeProofView(generics.ListAPIView):
    """View proofs submitted by the authenticated user with pagination and optional budget filtering."""
    serializer_class = ProofSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPagination  # Replace with your pagination class

    def get_queryset(self):
        """Filter proofs by status and the current user, optionally by remaining_budget."""
        user = self.request.user
        status = self.request.query_params.get('status', 'unapproved')

        queryset = Proof.objects.filter(status=status, user=user)
        return queryset


class UnapprovedProofView(generics.ListAPIView):
    """View unapproved proofs for a specific advertisement."""
    serializer_class = ProofSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter unapproved proofs for the specific advertisement."""
        advertisement_id = self.kwargs.get('advertisement_id')
        advertisement = get_object_or_404(Advertisement, id=advertisement_id)
        return Proof.objects.filter(advertisement=advertisement, status='unapproved')


# Advertisement Detail and Update Views

class AdvertisementDetailView(viewsets.ModelViewSet):
    queryset = Advertisement.objects.all()
    serializer_class = AdvertisementSerializer
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        logger.info(f"Updating advertisement. User: {request.user.user_id}, Data: {request.data}")
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        if 'thumbnail' in request.data and request.data['thumbnail'] in ['null', 'undefined', '']:
            request.data.pop('thumbnail')

        serializer = self.get_serializer(instance, data=request.data, partial=partial)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            logger.error(f"Validation error: {e.detail}")
            return Response({"error": str(e.detail)}, status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"Advertisement status: {instance.status}")
        logger.info(f"Current terminate date: {instance.terminate}")
        logger.info(f"New terminate date in request: {serializer.validated_data.get('terminate')}")

        new_terminate = serializer.validated_data.get('terminate')
        old_terminate = instance.terminate

        # Ensure terminate field is properly handled
        if new_terminate and new_terminate != old_terminate:
            logger.info(f"Terminate date has changed. Old: {old_terminate}, New: {new_terminate}")

            # Handle the advertisement status appropriately
            if instance.status == 'draft':
                logger.info(f"Updating draft advertisement. ID: {instance.id}")
                return self.update_draft_advertisement(instance, serializer)
            elif instance.status in ['unapproved', 'Active']:  # Correct condition here to handle 'Active'
                logger.info(f"Updating {instance.status} advertisement. ID: {instance.id}")
                return self.update_active_or_unapproved_advertisement(request, instance, serializer)
            else:
                logger.error(f"Unexpected status {instance.status} for advertisement. ID: {instance.id}")
                return Response(
                    {"error": "You Cannot Change Completed Advertisements. Add Funds To Re-run The Advertisement"},
                    status=status.HTTP_400_BAD_REQUEST)
        else:
            # If terminate hasn't changed, perform regular update
            logger.info("Terminate date hasn't changed or is invalid, performing regular update")
            return self.perform_regular_update(instance, serializer)

    def update_draft_advertisement(self, instance, serializer):
        logger.info(f"Updating draft advertisement. ID: {instance.id}")
        try:
            with transaction.atomic():
                current_date = timezone.now().date()
                new_terminate = serializer.validated_data.get('terminate', instance.terminate)
                days_difference = (new_terminate - current_date).days
                new_budget = days_difference * 100  # Assuming $100 per day

                logger.info(
                    f"New terminate date: {new_terminate}, Days difference: {days_difference}, New budget: ${new_budget}")

                user = instance.user
                user_wallet = UserWallet.objects.select_for_update().get(user=user)

                # Check if user has enough balance to publish the ad
                if user_wallet.balance < new_budget:
                    logger.warning(f"Insufficient balance. Required: ${new_budget}, Available: ${user_wallet.balance}")
                    return Response({
                        "error": f"Insufficient balance in wallet. Required: ${new_budget}, Available: ${user_wallet.balance}"
                    }, status=status.HTTP_400_BAD_REQUEST)

                # Deduct the amount from the user's wallet
                user_wallet.balance -= new_budget
                user_wallet.save()

                # Save the advertisement as updated
                advertisement = serializer.save(
                    budget=new_budget,
                    remaining_budget=new_budget,
                    status='unapproved'  # Move the draft to 'unapproved' state for verification
                )

                # Create a pending transaction for the deduction
                user_transaction = UserTransaction.objects.create(
                    user=user,
                    advertisement=advertisement,
                    transaction_type='spend',
                    amount=new_budget,
                    status='pending',  # Mark as pending until verification is complete
                )
                logger.info(f"Transaction created. ID: {user_transaction.id}, Amount: ${new_budget}")

                # Create notification for the user
                notification = Notification.objects.create(
                    user=user,
                    message=f"Your draft advertisement '{advertisement.title}' is under verification by admin. New budget: ${new_budget}"
                )
                logger.info(f"Notification created. ID: {notification.id}")

                logger.info(f"Draft advertisement updated successfully. New budget: ${new_budget}")
                return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error updating draft advertisement: {str(e)}", exc_info=True)
            return Response({"error": f"An error occurred while updating the draft advertisement: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update_active_or_unapproved_advertisement(self, request, instance, serializer):
        logger.info(f"Updating {instance.status} advertisement. ID: {instance.id}")
        try:
            with transaction.atomic():
                user = request.user
                user_wallet = UserWallet.objects.select_for_update().get(user=user)

                # Get old and new terminate dates
                old_terminate = instance.terminate
                new_terminate = serializer.validated_data.get('terminate')

                logger.info(f"Old terminate date: {old_terminate}")
                logger.info(f"New terminate date: {new_terminate}")

                # Ensure new terminate date is provided and is greater than the old one
                if new_terminate and new_terminate > old_terminate:
                    days_extended = (new_terminate - old_terminate).days
                    additional_budget = days_extended * 100  # Assuming $100 per day

                    logger.info(f"Days extended: {days_extended}, Additional budget: ${additional_budget}")

                    if user_wallet.balance < additional_budget:
                        logger.warning(
                            f"Insufficient balance. Required: ${additional_budget}, Available: ${user_wallet.balance}")
                        return Response({
                            "error": f"Insufficient balance in wallet for extension. Required: ${additional_budget}, Available: ${user_wallet.balance}"
                        }, status=status.HTTP_400_BAD_REQUEST)

                    # Update the budget and terminate date
                    new_total_budget = instance.budget + additional_budget
                    advertisement = serializer.save(
                        budget=new_total_budget,
                        remaining_budget=instance.remaining_budget + additional_budget,
                        terminate=new_terminate
                    )

                    # Deduct from wallet
                    user_wallet.balance -= additional_budget
                    user_wallet.save()

                    # Log the transaction
                    user_transaction = UserTransaction.objects.create(
                        user=user,
                        advertisement=advertisement,
                        transaction_type='spend',
                        amount=additional_budget,
                        status='pending',
                    )
                    logger.info(f"Transaction created. ID: {user_transaction.id}, Amount: ${additional_budget}")

                    # Create notification
                    notification = Notification.objects.create(
                        user=user,
                        message=f"Your {instance.status} advertisement '{advertisement.title}' has been extended by {days_extended} days. Additional budget: ${additional_budget}"
                    )
                    logger.info(f"Notification created. ID: {notification.id}")

                    logger.info(
                        f"{instance.status.capitalize()} advertisement extended successfully. New budget: ${new_total_budget}, New terminate date: {new_terminate}")
                else:
                    # If no extension is needed, perform a regular update
                    logger.info("No extension needed or invalid new terminate date.")
                    advertisement = serializer.save()
                    logger.info(f"{instance.status.capitalize()} advertisement updated without extension")

                return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error updating {instance.status} advertisement: {str(e)}", exc_info=True)
            return Response(
                {"error": f"An error occurred while updating the {instance.status} advertisement. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def perform_regular_update(self, instance, serializer):
        logger.info(f"Performing regular update for advertisement. ID: {instance.id}")
        try:
            advertisement = serializer.save()

            notification = Notification.objects.create(
                user=advertisement.user,
                message=f"Your advertisement '{advertisement.title}' has been updated."
            )
            logger.info(f"Notification created. ID: {notification.id}")

            logger.info("Regular update completed successfully")
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during regular update: {str(e)}", exc_info=True)
            return Response({"error": f"An error occurred while updating the advertisement: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        logger.info(f"Attempting to delete advertisement. ID: {instance.id}")
        try:
            instance.delete()
            logger.info(f"Advertisement deleted successfully. ID: {instance.id}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting advertisement: {str(e)}", exc_info=True)
            return Response({"error": f"An error occurred while deleting the advertisement: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# User Profile Views
class UserProfileDetail(generics.RetrieveUpdateAPIView):
    """Retrieve or update the user's profile."""
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        """Fetch the user's profile object."""
        return self.request.user.userprofile


class ProfileUpdateAPIView(generics.UpdateAPIView):
    """Update the user's profile details."""
    queryset = UserProfile.objects.all()
    serializer_class = ProfileUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        """Fetch the user's profile object."""
        return self.request.user.userprofile

    def put(self, request, *args, **kwargs):
        """Handle full updates."""
        return self.update(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        """Handle partial updates."""
        return self.partial_update(request, *args, **kwargs)


class ProofDeleteView(APIView):
    """Handle deletion of a specific proof by the authenticated user."""
    permission_classes = [IsAuthenticated]

    def delete(self, request, proof_id):
        """Delete a specific proof by its alphanumeric id if it belongs to the user."""
        user = request.user

        # Adjust the lookup to use the correct field type
        proof = get_object_or_404(Proof, proof_id=proof_id, user=user)

        proof.delete()
        return Response({"detail": "Proof deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


class UserDashboardListView(generics.ListAPIView):
    queryset = UserDashboard.objects.all()
    serializer_class = UserDashboardSerializer

    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class AdminAdvertisementListView(generics.ListAPIView):
    queryset = AdminAdvertisement.objects.filter(is_running=True).order_by('-priority')
    serializer_class = AdminAdvertisementSerializer


class AdminAdvertisementDetailView(generics.RetrieveAPIView):
    queryset = AdminAdvertisement.objects.all()
    serializer_class = AdminAdvertisementSerializer
    lookup_field = 'id'

    def get_object(self):
        try:
            return AdminAdvertisement.objects.get(id=self.kwargs['id'], is_running=True)
        except AdminAdvertisement.DoesNotExist:
            raise NotFound(detail="Advertisement not found or it is not currently running.")


class ChangeProfilePictureView(APIView):
    permission_classes = [IsAdminUserCustom]  # Restrict to admin users

    def put(self, request, *args, **kwargs):
        profile = request.user.userprofile  # Assuming a OneToOne relation with User
        serializer = ChangeProfilePictureSerializer(profile, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Profile picture updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangeNameView(APIView):
    permission_classes = [IsAdminUserCustom]  # Restrict to admin users

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = ChangeNameSerializer(user, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Name updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangeEmailView(APIView):
    permission_classes = [IsAdminUserCustom]  # Restrict to admin users

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = ChangeEmailSerializer(user, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Email updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Retrieves the admin profile and returns absolute URL for the photo."""
        if not request.user.is_admin:
            return Response({"error": "Unauthorized"}, status=403)

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        serializer = AdminProfileSerializer(profile, context={"request": request})
        return Response(serializer.data)

    def put(self, request):
        """Updates admin profile and supports file uploads."""
        if not request.user.is_admin:
            return Response({"error": "Unauthorized"}, status=403)

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        data = request.data.copy()

        # Handling file uploads correctly
        if "photo" in request.FILES:
            data["photo"] = request.FILES["photo"]

        serializer = AdminProfileSerializer(profile, data=data, partial=True, context={"request": request})

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=400)

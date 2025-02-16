from django.urls import path
from .views import (
    AdminAdvertisementListCreateView,
    AdminAdvertisementDetailView,
    DashboardAPIView,
    WalletListView,
    WalletDetailView,
    UserListview,
    UserDetailView,
    AdvertisementListCreateView,
    AdvertisementDetailView,
    ProofListView,
    ProofDetailView,
    TransactionListView,
    TransactionDetailView,
    UserProfileListView,
    UserProfileDetailView,
    UserDashboardCreateAPIView,
    AdminUserCreateView, AdminAdvertisementCreateView, AdminApproveDeleteAdvertisementView, AdminNotificationListView,
    MarkAllNotificationsAsReadView,

)

urlpatterns = [

    path('notifications-admin/', AdminNotificationListView.as_view(), name='admin_notifications'),
    path('notifications-admin/mark-all/', MarkAllNotificationsAsReadView.as_view(), name='notifications_mark_all'),

    # --- Advertisement URLs ---
    path('advertisements_admin/', AdminAdvertisementListCreateView.as_view(), name='advertisement-list-create'),
    path('advertisements_admin/<str:id>/', AdminAdvertisementDetailView.as_view(), name='advertisement-detail'),

    # --- Dashboard URL ---d
    path('dashboard/', DashboardAPIView.as_view(), name='dashboard'),

    # --- Wallet URLs ---
    path('wallets/', WalletListView.as_view(), name='wallet-list'),
    path('wallets/<str:user_id>/', WalletDetailView.as_view(), name='wallet-detail'),

    # --- User Management URLs --- d-
    path('users/', UserListview.as_view(), name='user-list'),
    path('wallets/<str:id>/', WalletDetailView.as_view(), name='wallet-detail'),
    # Ensure <str:id> matches the expected keyword

    # --- Advertisement Management URLs ---
    path('advertisement/manage/<str:id>/', AdvertisementDetailView.as_view(), name='advertisement-manage-detail'),
    path('advertisement/manage/', AdvertisementListCreateView.as_view(), name='advertisement-manage-list-create'),

    path('advertisement/create/', AdminAdvertisementCreateView.as_view(), name='admin-advertisement-create'),

    # --- Proof Management URLs ---
    path('uproofs/', ProofListView.as_view(), name='proof-list'),
    path('proofs/<str:id>/', ProofDetailView.as_view(), name='proof-detail'),

    # --- Transaction Management URLs ---
    path('user_transactionsDetails_admin_panel/<str:id>/', TransactionDetailView.as_view(), name='transaction-detail'),
    path('user_transactions_admin_panel/<str:user_id>/', TransactionListView.as_view(), name='transaction-list'),

    # --- User Profile Management URLs ---d
    path('user-profiles/', UserProfileListView.as_view(), name='userprofile-list'),
    path('user-profiles/<str:id>/', UserProfileDetailView.as_view(), name='userprofile-detail'),

    # d
    path('admin_user_dashboard/', UserDashboardCreateAPIView.as_view(), name='dashboard-create'),
    path('advertisement/action/', AdminApproveDeleteAdvertisementView.as_view(), name='admin_ad_action'),

    # Admin user creation
    path('admin_user_create/create/', AdminUserCreateView.as_view(), name='admin-user-create'),

]

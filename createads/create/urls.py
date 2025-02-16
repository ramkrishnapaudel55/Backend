from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from .views import (
    AdvertisementListView,
    AdvertisementCreateView,
    AddFundView,
    UserWalletView,
    UserTransactionListView,
    SeeProofView,
    ApproveSubmissionView,
    AddBalanceView,
    AdvertisementsByCategoryView,
    AdvertisementListAllView,
    AdvertisementDetailView,
    UserProfileDetail,
    ProfileUpdateAPIView,
    NotificationListView,
    NotificationMarkAsReadView,
    MarkAllNotificationsAsReadView,
    ChangeProfilePictureView,    UnapprovedProofView,
    SubmitProofView, UserAdvertisementsByCategoryView, AdminProfileView, ProofDeleteView, UserDashboardListView,
    AdminAdvertisementListView, AdminAdvertisementDetailView)

urlpatterns = [
    # Advertisement URLs
    path('advertisements/', AdvertisementListView.as_view(), name='advertisement-list'),
    path('advertisements/create/', AdvertisementCreateView.as_view(), name='advertisement-create'),
    path('advertisements/category/<int:category_id>/', AdvertisementsByCategoryView.as_view(),
         name='advertisements-by-category'),
    path('advertisements/all/', AdvertisementListAllView.as_view(), name='advertisement-list-all'),
    path('advertisements/<str:id>/', AdvertisementDetailView.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='advertisement-detail'),
    path('advertisements/<str:id>/publish/', AdvertisementDetailView.as_view({'post': 'publish'}),
         name='advertisement-publish'),

    # Fund addition URL
    path('add-fund/', AddFundView.as_view(), name='add-fund'),

    # Wallet URLs
    path('wallet/', UserWalletView.as_view(), name='user-wallet'),

    # Transaction URLs
    path('transactions/', UserTransactionListView.as_view(), name='user-transaction-list'),
    path('proofs/<str:advertisement_id>/approve/', ApproveSubmissionView.as_view(), name='approve-deny-proof'),

    # Proof Submission and Approval URLs
    path('submit-proof/', SubmitProofView.as_view(), name='submit-proof'),
    path('uproofs/<str:advertisement_id>/unapproved/', UnapprovedProofView.as_view(), name='unapproved-proofs'),
    path('proofs/', SeeProofView.as_view(), name='filtered-proofs'),
    path('proofs/delete/<str:proof_id>/', ProofDeleteView.as_view(), name='delete-proof'),

    # Add Balance URL
    path('add-balance/', AddBalanceView.as_view(), name='add-balance'),

    # Profile URLs
    path('profile/', UserProfileDetail.as_view(), name='user-profile'),
    path('update-profile/', ProfileUpdateAPIView.as_view(), name='profile-update'),
    path('change-profile-picture/', ChangeProfilePictureView.as_view(), name='change-profile-picture/'),

    # Notification URLs
    path('notifications/', NotificationListView.as_view(), name='notifications_list'),
    path('notifications/<int:notification_id>/read/', NotificationMarkAsReadView.as_view(),
         name='notification_mark_as_read'),
    path('notifications/mark_all_as_read/', MarkAllNotificationsAsReadView.as_view(), name='mark_all_as_read'),

    path('user/advertisements-by-category/', UserAdvertisementsByCategoryView.as_view(),
         name='user-advertisements-by-category'),

    path('user-dashboard/',UserDashboardListView.as_view(), name='user-dashboard'),
    path('admin-advertisements/', AdminAdvertisementListView.as_view(), name='admin-advertisements'),
    path('admin-advertisements/<str:id>/', AdminAdvertisementDetailView.as_view(), name='admin-advertisement-detail'),

    path('admin-profile/', AdminProfileView.as_view(), name='admin_profile'),
    # path('update-admin-profile/', AdminProfileView.as_view(), name='update-admin-profile/'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
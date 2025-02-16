from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

from .views import RegisterView, SendOTPView, VerifyOTPView, LoginView, LogoutView, ChangePasswordView, GenerateOTPForResetView, \
    ResetPasswordWithOTPView, AdminRegisterView, AdminLoginView, AdminLogoutView, ChangePasskeyView, ForgotPasswordView, \
    ChangePasswordAdminView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('send-email-otp/', SendOTPView.as_view(), name='send-email-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('update-email/', views.update_email, name='update-email'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('generate-otp/', GenerateOTPForResetView.as_view(), name='generate-otp'),
    path('reset-password/', ResetPasswordWithOTPView.as_view(), name='reset-password'),

    path('register_admin/', AdminRegisterView.as_view(), name='admin-register'),
    path('login_admin/', AdminLoginView.as_view(), name='admin-login'),
    path('logout_admin/', AdminLogoutView.as_view(), name='admin-logout'),
    path('change-passkey_admin/', ChangePasskeyView.as_view(), name='change-passkey'),
    path('forgot-password-admin/', ForgotPasswordView.as_view(), name='forgot-password'),  #later added
    path('change-password-admin/', ChangePasswordAdminView.as_view(), name='change_password_admin'),

    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # Login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),  # Optional: verify token
]
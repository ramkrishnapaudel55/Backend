from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model


class CustomBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()  # Get the custom user model (User)

        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)  # Default to username if no email

        try:
            # Attempt to fetch the user by email first
            user = UserModel.objects.get(email=username)
        except UserModel.DoesNotExist:
            # If no user found with the email, fallback to username lookup
            try:
                user = UserModel.objects.get(username=username)
            except UserModel.DoesNotExist:
                return None

        # Check if the password matches and if the user can be authenticated
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

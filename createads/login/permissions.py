from rest_framework.permissions import BasePermission


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_admin


class IsAdminUserCustom(BasePermission):
    """
    Custom permission to check if the user has 'is_admin=True' instead of 'is_staff'.
    """
    def has_permission(self, request, view):
        # Check if the user is authenticated and has 'is_admin=True'
        return bool(request.user and request.user.is_authenticated and request.user.is_admin)

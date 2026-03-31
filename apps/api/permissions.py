# apps/api/permissions.py

from rest_framework import permissions


class HasRole(permissions.BasePermission):
    """
    RBAC permission check against UserProfile.role.
    Set `required_role` on the view.
    """

    ROLE_HIERARCHY = {
        'viewer': 1,
        'operator': 2,
        'admin': 3,
    }

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser:
            return True

        required = getattr(view, 'required_role', None)
        if required is None:
            return True

        try:
            user_role = user.profile.role
        except Exception:
            user_role = 'viewer'

        return (
            self.ROLE_HIERARCHY.get(user_role, 0)
            >= self.ROLE_HIERARCHY.get(required, 0)
        )


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser:
            return True
        try:
            return user.profile.role == 'admin'
        except Exception:
            return False


class IsOperatorOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser:
            return True
        try:
            return user.profile.role in ('operator', 'admin')
        except Exception:
            return False


class ReadOnlyOrOperator(permissions.BasePermission):
    """Any authenticated can read. Operator+ can write."""

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        if user.is_superuser:
            return True
        try:
            return user.profile.role in ('operator', 'admin')
        except Exception:
            return False
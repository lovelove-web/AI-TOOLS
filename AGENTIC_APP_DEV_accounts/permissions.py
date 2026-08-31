"""Role-based access control helpers.

Server-side enforcement is mandatory: templates may hide buttons for a role,
but every view that mutates or exposes sensitive data must also declare an
allowed-roles mixin/decorator here. Never rely on hidden UI alone.
"""
from functools import wraps

from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import PermissionDenied

from accounts.models import Role


class RoleRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Class-based-view mixin restricting access to a set of roles."""

    allowed_roles = ()  # e.g. (Role.ADMIN, Role.ANALYST)
    raise_exception = True

    def test_func(self):
        user = self.request.user
        return user.is_authenticated and (user.role in self.allowed_roles or user.is_superuser)


def role_required(*roles):
    """Function-view decorator restricting access to a set of roles."""

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                raise PermissionDenied
            if request.user.role not in roles and not request.user.is_superuser:
                raise PermissionDenied
            return view_func(request, *args, **kwargs)

        return _wrapped

    return decorator


# Convenience role groupings used across apps
CAN_MANAGE_USERS = (Role.ADMIN,)
CAN_EDIT_COMPLIANCE = (Role.ADMIN, Role.ANALYST)
CAN_VIEW_COMPLIANCE = (Role.ADMIN, Role.ANALYST, Role.AUDITOR)
CAN_EDIT_VULNERABILITIES = (Role.ADMIN, Role.ANALYST)
CAN_EDIT_ASSETS = (Role.ADMIN, Role.ANALYST)
CAN_RUN_REPORTS = (Role.ADMIN, Role.ANALYST, Role.AUDITOR)

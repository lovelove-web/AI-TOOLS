from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.TextChoices):
    ADMIN = "admin", "Administrator"
    ANALYST = "analyst", "Security Analyst"
    AUDITOR = "auditor", "Auditor"


class User(AbstractUser):
    """Custom user with a role used for RBAC across the application."""

    role = models.CharField(max_length=16, choices=Role.choices, default=Role.ANALYST)
    department = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["username"]

    def __str__(self):
        return f"{self.get_full_name() or self.username} ({self.get_role_display()})"

    @property
    def is_admin_role(self):
        return self.role == Role.ADMIN

    @property
    def is_analyst_role(self):
        return self.role == Role.ANALYST

    @property
    def is_auditor_role(self):
        return self.role == Role.AUDITOR

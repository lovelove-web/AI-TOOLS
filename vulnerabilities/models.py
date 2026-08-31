from django.conf import settings
from django.db import models
from django.utils import timezone


class Severity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"


class VulnStatus(models.TextChoices):
    OPEN = "open", "Open"
    IN_PROGRESS = "in_progress", "In Progress"
    RESOLVED = "resolved", "Resolved"
    CLOSED = "closed", "Closed"


class Vulnerability(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices, db_index=True)
    status = models.CharField(max_length=15, choices=VulnStatus.choices, default=VulnStatus.OPEN, db_index=True)
    asset = models.ForeignKey(
        "assets.CloudAsset", on_delete=models.SET_NULL, null=True, blank=True, related_name="vulnerabilities"
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_vulns"
    )
    due_date = models.DateField(null=True, blank=True)
    remediation_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "Vulnerabilities"
        indexes = [
            models.Index(fields=["severity", "status"]),
            models.Index(fields=["due_date"]),
        ]

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title}"

    @property
    def is_overdue(self):
        return bool(self.due_date and self.due_date < timezone.localdate() and self.status not in (VulnStatus.RESOLVED, VulnStatus.CLOSED))

    def save(self, *args, **kwargs):
        # Auto-stamp resolved_at when moving into a terminal state.
        if self.status in (VulnStatus.RESOLVED, VulnStatus.CLOSED) and not self.resolved_at:
            self.resolved_at = timezone.now()
        if self.status not in (VulnStatus.RESOLVED, VulnStatus.CLOSED):
            self.resolved_at = None
        super().save(*args, **kwargs)

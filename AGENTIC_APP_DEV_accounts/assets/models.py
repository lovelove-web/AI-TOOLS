from django.conf import settings
from django.db import models


class CloudProvider(models.TextChoices):
    AWS = "aws", "Amazon Web Services"
    AZURE = "azure", "Microsoft Azure"
    GCP = "gcp", "Google Cloud"


class CloudAsset(models.Model):
    """A cloud resource being tracked (EC2 instance, storage bucket, VM, etc.)."""

    name = models.CharField(max_length=200)
    provider = models.CharField(max_length=10, choices=CloudProvider.choices, db_index=True)
    resource_type = models.CharField(max_length=100, help_text="e.g. EC2 Instance, S3 Bucket, VM, Storage Account")
    resource_id = models.CharField(max_length=255, blank=True, help_text="Provider-native resource identifier/ARN")
    region = models.CharField(max_length=100, blank=True)
    tags = models.JSONField(default=dict, blank=True, help_text="Free-form key/value tags")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="owned_assets", help_text="Security owner responsible for this asset",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["provider", "is_active"])]

    def __str__(self):
        return f"{self.name} ({self.get_provider_display()})"

    @property
    def open_vulnerability_count(self):
        return self.vulnerabilities.exclude(status__in=["resolved", "closed"]).count()

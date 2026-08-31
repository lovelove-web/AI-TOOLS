import os

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class Framework(models.Model):
    """A compliance framework, e.g. ISO 27001, NIST CSF, CIS Controls, GDPR."""

    name = models.CharField(max_length=150, unique=True)
    short_name = models.CharField(max_length=30, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Control(models.Model):
    """A single control/requirement within a framework."""

    framework = models.ForeignKey(Framework, on_delete=models.CASCADE, related_name="controls")
    code = models.CharField(max_length=30, help_text="e.g. A.9.2, PR.AC-1, CIS-4.1")
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["framework", "code"]
        unique_together = ("framework", "code")

    def __str__(self):
        return f"{self.framework.short_name} {self.code} — {self.title}"


class ComplianceStatus(models.TextChoices):
    COMPLIANT = "compliant", "Compliant"
    NON_COMPLIANT = "non_compliant", "Non-Compliant"
    IN_PROGRESS = "in_progress", "In Progress"
    NOT_APPLICABLE = "not_applicable", "Not Applicable"


class ComplianceRecord(models.Model):
    """Tracks the compliance status of a Control, optionally scoped to a CloudAsset."""

    control = models.ForeignKey(Control, on_delete=models.CASCADE, related_name="records")
    asset = models.ForeignKey(
        "assets.CloudAsset", on_delete=models.SET_NULL, null=True, blank=True, related_name="compliance_records"
    )
    status = models.CharField(max_length=20, choices=ComplianceStatus.choices, default=ComplianceStatus.IN_PROGRESS, db_index=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="owned_compliance_records")
    last_reviewed = models.DateField(null=True, blank=True)
    next_review_due = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["control__framework", "control__code"]
        indexes = [models.Index(fields=["status"])]

    def __str__(self):
        return f"{self.control} — {self.get_status_display()}"

    @property
    def is_review_overdue(self):
        return bool(self.next_review_due and self.next_review_due < timezone.localdate())


def evidence_upload_path(instance, filename):
    return f"evidence/{instance.compliance_record.control.framework.short_name}/{instance.compliance_record_id}/{filename}"


def validate_evidence_file(value):
    ext = os.path.splitext(value.name)[1].lower()
    if ext not in settings.ALLOWED_EVIDENCE_EXTENSIONS:
        raise ValidationError(f"Unsupported file type '{ext}'. Allowed: {', '.join(settings.ALLOWED_EVIDENCE_EXTENSIONS)}")
    max_bytes = settings.MAX_EVIDENCE_UPLOAD_MB * 1024 * 1024
    if value.size > max_bytes:
        raise ValidationError(f"File too large. Max size is {settings.MAX_EVIDENCE_UPLOAD_MB}MB.")


class Evidence(models.Model):
    """A supporting document/screenshot proving a control's compliance status."""

    compliance_record = models.ForeignKey(ComplianceRecord, on_delete=models.CASCADE, related_name="evidence_items")
    file = models.FileField(upload_to=evidence_upload_path, validators=[validate_evidence_file])
    description = models.CharField(max_length=255, blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-uploaded_at"]
        verbose_name_plural = "Evidence"

    def __str__(self):
        return f"Evidence for {self.compliance_record} @ {self.uploaded_at:%Y-%m-%d}"

from django.contrib import admin

from compliance.models import ComplianceRecord, Control, Evidence, Framework


@admin.register(Framework)
class FrameworkAdmin(admin.ModelAdmin):
    list_display = ("name", "short_name")
    search_fields = ("name", "short_name")


@admin.register(Control)
class ControlAdmin(admin.ModelAdmin):
    list_display = ("framework", "code", "title")
    list_filter = ("framework",)
    search_fields = ("code", "title")


@admin.register(ComplianceRecord)
class ComplianceRecordAdmin(admin.ModelAdmin):
    list_display = ("control", "status", "asset", "owner", "next_review_due")
    list_filter = ("status", "control__framework")


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ("compliance_record", "description", "uploaded_by", "uploaded_at")

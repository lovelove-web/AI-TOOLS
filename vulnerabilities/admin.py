from django.contrib import admin

from vulnerabilities.models import Vulnerability


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "status", "asset", "assigned_to", "due_date", "is_overdue")
    list_filter = ("severity", "status")
    search_fields = ("title", "description")
    date_hierarchy = "created_at"

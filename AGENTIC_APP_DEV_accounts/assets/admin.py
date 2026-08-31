from django.contrib import admin

from assets.models import CloudAsset


@admin.register(CloudAsset)
class CloudAssetAdmin(admin.ModelAdmin):
    list_display = ("name", "provider", "resource_type", "region", "owner", "is_active", "created_at")
    list_filter = ("provider", "is_active", "region")
    search_fields = ("name", "resource_id")

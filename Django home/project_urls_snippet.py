# Your project's main urls.py (the one next to settings.py)

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("menu.urls")),
]

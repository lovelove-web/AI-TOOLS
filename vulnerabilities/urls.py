from django.urls import path

from vulnerabilities import views

app_name = "vulnerabilities"

urlpatterns = [
    path("", views.VulnerabilityListView.as_view(), name="list"),
    path("new/", views.VulnerabilityCreateView.as_view(), name="create"),
    path("<int:pk>/", views.VulnerabilityDetailView.as_view(), name="detail"),
    path("<int:pk>/edit/", views.VulnerabilityUpdateView.as_view(), name="update"),
    path("<int:pk>/delete/", views.VulnerabilityDeleteView.as_view(), name="delete"),
]

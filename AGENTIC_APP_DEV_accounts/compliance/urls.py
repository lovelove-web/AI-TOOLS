from django.urls import path

from compliance import views

app_name = "compliance"

urlpatterns = [
    path("", views.ComplianceRecordListView.as_view(), name="list"),
    path("audit-prep/", views.AuditPrepView.as_view(), name="audit_prep"),
    path("new/", views.ComplianceRecordCreateView.as_view(), name="create"),
    path("<int:pk>/", views.ComplianceRecordDetailView.as_view(), name="detail"),
    path("<int:pk>/edit/", views.ComplianceRecordUpdateView.as_view(), name="update"),
    path("<int:pk>/delete/", views.ComplianceRecordDeleteView.as_view(), name="delete"),
    path("<int:pk>/evidence/upload/", views.UploadEvidenceView.as_view(), name="upload_evidence"),
]

from django.urls import path

from reports import views

app_name = "reports"

urlpatterns = [
    path("", views.ReportsHomeView.as_view(), name="home"),
    path("compliance/csv/", views.compliance_report_csv, name="compliance_csv"),
    path("compliance/pdf/", views.compliance_report_pdf, name="compliance_pdf"),
    path("vulnerabilities/csv/", views.vulnerability_report_csv, name="vulnerability_csv"),
    path("vulnerabilities/pdf/", views.vulnerability_report_pdf, name="vulnerability_pdf"),
]

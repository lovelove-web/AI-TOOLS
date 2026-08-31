from django.views.generic import TemplateView

from accounts.permissions import CAN_RUN_REPORTS, role_required, RoleRequiredMixin
from compliance.models import ComplianceRecord
from reports.generators import build_csv_response, build_pdf_response
from vulnerabilities.models import Vulnerability


class ReportsHomeView(RoleRequiredMixin, TemplateView):
    template_name = "reports/home.html"
    allowed_roles = CAN_RUN_REPORTS


def _compliance_rows():
    records = ComplianceRecord.objects.select_related("control", "control__framework", "asset", "owner")
    headers = ["Framework", "Control Code", "Control Title", "Status", "Asset", "Owner", "Next Review"]
    rows = [
        [
            r.control.framework.short_name,
            r.control.code,
            r.control.title,
            r.get_status_display(),
            r.asset.name if r.asset else "-",
            (r.owner.get_full_name() or r.owner.username) if r.owner else "-",
            r.next_review_due or "-",
        ]
        for r in records
    ]
    return headers, rows


def _vulnerability_rows():
    vulns = Vulnerability.objects.select_related("asset", "assigned_to")
    headers = ["Title", "Severity", "Status", "Asset", "Provider", "Assigned To", "Due Date"]
    rows = [
        [
            v.title,
            v.get_severity_display(),
            v.get_status_display(),
            v.asset.name if v.asset else "-",
            v.asset.get_provider_display() if v.asset else "-",
            (v.assigned_to.get_full_name() or v.assigned_to.username) if v.assigned_to else "-",
            v.due_date or "-",
        ]
        for v in vulns
    ]
    return headers, rows


@role_required(*CAN_RUN_REPORTS)
def compliance_report_csv(request):
    headers, rows = _compliance_rows()
    return build_csv_response("compliance_report", headers, rows)


@role_required(*CAN_RUN_REPORTS)
def compliance_report_pdf(request):
    headers, rows = _compliance_rows()
    return build_pdf_response("compliance_report", "Compliance Report", headers, rows)


@role_required(*CAN_RUN_REPORTS)
def vulnerability_report_csv(request):
    headers, rows = _vulnerability_rows()
    return build_csv_response("vulnerability_report", headers, rows)


@role_required(*CAN_RUN_REPORTS)
def vulnerability_report_pdf(request):
    headers, rows = _vulnerability_rows()
    return build_pdf_response("vulnerability_report", "Security / Vulnerability Report", headers, rows)

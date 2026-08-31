import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count, Q
from django.utils import timezone
from django.views.generic import TemplateView

from assets.models import CloudAsset, CloudProvider
from compliance.models import ComplianceRecord, ComplianceStatus
from vulnerabilities.models import Severity, Vulnerability, VulnStatus


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/home.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)

        # --- Compliance score ---
        total_records = ComplianceRecord.objects.exclude(status=ComplianceStatus.NOT_APPLICABLE).count()
        compliant_records = ComplianceRecord.objects.filter(status=ComplianceStatus.COMPLIANT).count()
        compliance_score = round((compliant_records / total_records) * 100, 1) if total_records else 0.0

        # --- Vulnerabilities ---
        open_statuses = [VulnStatus.OPEN, VulnStatus.IN_PROGRESS]
        open_vulns = Vulnerability.objects.filter(status__in=open_statuses)
        open_vuln_count = open_vulns.count()
        remediated_count = Vulnerability.objects.filter(status__in=[VulnStatus.RESOLVED, VulnStatus.CLOSED]).count()

        severity_breakdown = {
            row["severity"]: row["count"]
            for row in open_vulns.values("severity").annotate(count=Count("id"))
        }
        severity_labels = [Severity.CRITICAL.label, Severity.HIGH.label, Severity.MEDIUM.label, Severity.LOW.label]
        severity_values = [
            severity_breakdown.get(Severity.CRITICAL, 0),
            severity_breakdown.get(Severity.HIGH, 0),
            severity_breakdown.get(Severity.MEDIUM, 0),
            severity_breakdown.get(Severity.LOW, 0),
        ]

        # --- Cloud provider stats ---
        provider_rows = CloudAsset.objects.values("provider").annotate(count=Count("id"))
        provider_map = {row["provider"]: row["count"] for row in provider_rows}
        provider_labels = [CloudProvider.AWS.label, CloudProvider.AZURE.label, CloudProvider.GCP.label]
        provider_values = [
            provider_map.get(CloudProvider.AWS, 0),
            provider_map.get(CloudProvider.AZURE, 0),
            provider_map.get(CloudProvider.GCP, 0),
        ]

        provider_risk_rows = CloudAsset.objects.values("provider").annotate(
            assets=Count("id", distinct=True),
            open_findings=Count(
                "vulnerabilities",
                filter=Q(vulnerabilities__status__in=open_statuses),
            ),
            critical_findings=Count(
                "vulnerabilities",
                filter=Q(
                    vulnerabilities__status__in=open_statuses,
                    vulnerabilities__severity=Severity.CRITICAL,
                ),
            ),
        )
        provider_risk_map = {row["provider"]: row for row in provider_risk_rows}
        provider_posture = [
            {
                "name": provider.label,
                "assets": provider_risk_map.get(provider.value, {}).get("assets", 0),
                "open_findings": provider_risk_map.get(provider.value, {}).get("open_findings", 0),
                "critical_findings": provider_risk_map.get(provider.value, {}).get("critical_findings", 0),
                "icon": icon,
            }
            for provider, icon in (
                (CloudProvider.AWS, "fa-aws"),
                (CloudProvider.AZURE, "fa-microsoft"),
                (CloudProvider.GCP, "fa-google"),
            )
        ]

        # --- Compliance status breakdown per framework (for trend/bars) ---
        status_rows = ComplianceRecord.objects.values("status").annotate(count=Count("id"))
        status_map = {row["status"]: row["count"] for row in status_rows}
        status_labels = [s.label for s in ComplianceStatus]
        status_values = [status_map.get(s.value, 0) for s in ComplianceStatus]

        ctx.update({
            "compliance_score": compliance_score,
            "open_vuln_count": open_vuln_count,
            "remediated_count": remediated_count,
            "asset_count": CloudAsset.objects.count(),
            "critical_count": severity_breakdown.get(Severity.CRITICAL, 0),
            "overdue_count": open_vulns.filter(due_date__lt=timezone.localdate()).count(),
            "recent_vulnerabilities": Vulnerability.objects.select_related("asset").order_by("-created_at")[:6],
            "urgent_vulnerabilities": open_vulns.select_related("asset", "assigned_to").filter(
                Q(severity=Severity.CRITICAL) | Q(due_date__lt=timezone.localdate())
            ).order_by("due_date", "-created_at")[:5],
            "provider_posture": provider_posture,
            "non_compliant_count": ComplianceRecord.objects.filter(status=ComplianceStatus.NON_COMPLIANT).count(),
            "review_due_count": ComplianceRecord.objects.filter(next_review_due__lte=timezone.localdate()).count(),
            "chart_severity_labels": json.dumps(severity_labels),
            "chart_severity_values": json.dumps(severity_values),
            "chart_provider_labels": json.dumps(provider_labels),
            "chart_provider_values": json.dumps(provider_values),
            "chart_status_labels": json.dumps(status_labels),
            "chart_status_values": json.dumps(status_values),
        })
        return ctx

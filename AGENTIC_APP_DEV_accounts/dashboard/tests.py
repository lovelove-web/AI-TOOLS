from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import Role, User
from assets.models import CloudAsset, CloudProvider
from compliance.models import ComplianceRecord, ComplianceStatus, Control, Framework
from vulnerabilities.models import Severity, Vulnerability, VulnStatus


class DashboardTests(TestCase):
    def test_dashboard_shows_posture_and_urgent_queue(self):
        user = User.objects.create_user(username="analyst", password="pw12345678", role=Role.ANALYST)
        asset = CloudAsset.objects.create(name="payments-api", provider=CloudProvider.AWS, resource_type="EC2 Instance")
        Vulnerability.objects.create(
            title="Missing MFA", severity=Severity.CRITICAL, status=VulnStatus.OPEN,
            asset=asset, due_date=timezone.localdate() - timedelta(days=1),
        )
        framework = Framework.objects.create(name="NIST", short_name="NIST")
        control = Control.objects.create(framework=framework, code="PR.AC-1", title="Access control")
        ComplianceRecord.objects.create(control=control, status=ComplianceStatus.NON_COMPLIANT)

        self.client.force_login(user)
        response = self.client.get(reverse("dashboard:home"))
        self.assertContains(response, "Provider risk posture")
        self.assertContains(response, "Missing MFA")
        self.assertContains(response, "Amazon Web Services")

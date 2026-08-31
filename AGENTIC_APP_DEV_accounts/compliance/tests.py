from django.test import TestCase
from datetime import timedelta
from django.utils import timezone

from compliance.forms import ComplianceRecordForm
from compliance.models import ComplianceRecord, ComplianceStatus, Control, Framework


class ComplianceRecordTests(TestCase):
    def setUp(self):
        self.framework = Framework.objects.create(name="ISO 27001", short_name="ISO27001")
        self.control = Control.objects.create(framework=self.framework, code="A.9.2", title="User access management")

    def test_record_str(self):
        record = ComplianceRecord.objects.create(control=self.control, status=ComplianceStatus.COMPLIANT)
        self.assertIn("Compliant", str(record))

    def test_review_date_cannot_precede_last_review(self):
        form = ComplianceRecordForm(data={
            "control": self.control.pk,
            "status": ComplianceStatus.COMPLIANT,
            "last_reviewed": timezone.localdate(),
            "next_review_due": timezone.localdate() - timedelta(days=1),
        })
        self.assertFalse(form.is_valid())
        self.assertIn("cannot be before", form.errors["next_review_due"][0])

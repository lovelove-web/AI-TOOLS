"""Seeds a small realistic demo dataset: cloud assets, vulnerabilities, and
compliance record statuses. Run AFTER `manage.py seed_frameworks`.

Usage: python manage.py seed_demo_data
"""
import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from assets.models import CloudAsset, CloudProvider
from compliance.models import ComplianceRecord, ComplianceStatus, Control
from vulnerabilities.models import Severity, Vulnerability, VulnStatus

ASSET_SEED = [
    ("prod-web-ec2-01", CloudProvider.AWS, "EC2 Instance", "us-east-1"),
    ("prod-data-s3-bucket", CloudProvider.AWS, "S3 Bucket", "us-east-1"),
    ("billing-sql-vm", CloudProvider.AZURE, "Virtual Machine", "eastus"),
    ("hr-storage-account", CloudProvider.AZURE, "Storage Account", "westeurope"),
    ("analytics-gke-cluster", CloudProvider.GCP, "GKE Cluster", "us-central1"),
    ("marketing-cloud-sql", CloudProvider.GCP, "Cloud SQL", "europe-west1"),
]

VULN_SEED = [
    ("Publicly exposed S3 bucket", Severity.CRITICAL),
    ("Outdated TLS version on load balancer", Severity.HIGH),
    ("Missing MFA on privileged IAM role", Severity.CRITICAL),
    ("Unpatched OS on VM", Severity.HIGH),
    ("Overly permissive security group", Severity.MEDIUM),
    ("Verbose error messages in production", Severity.LOW),
    ("Storage account allows anonymous access", Severity.HIGH),
    ("Default credentials on database", Severity.CRITICAL),
]


class Command(BaseCommand):
    help = "Seed demo cloud assets, vulnerabilities, and compliance record statuses for evaluation."

    def handle(self, *args, **options):
        assets = []
        for name, provider, rtype, region in ASSET_SEED:
            asset, _ = CloudAsset.objects.get_or_create(
                name=name, defaults={"provider": provider, "resource_type": rtype, "region": region}
            )
            assets.append(asset)

        for title, severity in VULN_SEED:
            Vulnerability.objects.get_or_create(
                title=title,
                defaults={
                    "severity": severity,
                    "status": random.choice([VulnStatus.OPEN, VulnStatus.IN_PROGRESS, VulnStatus.RESOLVED]),
                    "asset": random.choice(assets),
                    "due_date": timezone.localdate() + timedelta(days=random.choice([-5, 3, 10, 20])),
                },
            )

        controls = list(Control.objects.all())
        for control in controls:
            ComplianceRecord.objects.get_or_create(
                control=control,
                defaults={
                    "status": random.choice([
                        ComplianceStatus.COMPLIANT, ComplianceStatus.COMPLIANT,
                        ComplianceStatus.IN_PROGRESS, ComplianceStatus.NON_COMPLIANT,
                    ]),
                    "asset": random.choice(assets) if assets else None,
                    "next_review_due": timezone.localdate() + timedelta(days=random.choice([-10, 15, 45])),
                },
            )

        self.stdout.write(self.style.SUCCESS(
            f"Demo data seeded: {len(assets)} assets, {len(VULN_SEED)} vulnerabilities, {len(controls)} compliance records."
        ))

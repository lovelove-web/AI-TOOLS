from datetime import timedelta
from random import choice, randint

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import User
from assets.models import CloudAsset, CloudProvider
from compliance.models import (
    ComplianceRecord,
    ComplianceStatus,
    Control,
)
from vulnerabilities.models import (
    Severity,
    VulnStatus,
    Vulnerability,
)


class Command(BaseCommand):
    help = "Generate a large realistic dataset for the security dashboard."

    def handle(self, *args, **options):
        today = timezone.localdate()

        # ---------------------------------------------------------
        # Users
        # ---------------------------------------------------------
        users = list(User.objects.all())

        if not users:
            self.stdout.write(
                self.style.ERROR(
                    "No users found. Run 'python manage.py createsuperuser' first."
                )
            )
            return

        # ---------------------------------------------------------
        # Cloud assets
        # ---------------------------------------------------------
        provider_data = [
            (
                CloudProvider.AWS,
                [
                    "EC2 Instance",
                    "S3 Bucket",
                    "RDS Database",
                    "Lambda Function",
                    "VPC",
                ],
                [
                    "eu-north-1",
                    "eu-west-1",
                    "us-east-1",
                ],
            ),
            (
                CloudProvider.AZURE,
                [
                    "Virtual Machine",
                    "Storage Account",
                    "SQL Database",
                    "App Service",
                    "Key Vault",
                ],
                [
                    "West Europe",
                    "North Europe",
                    "East US",
                ],
            ),
            (
                CloudProvider.GCP,
                [
                    "Compute Engine",
                    "Cloud Storage Bucket",
                    "Cloud SQL",
                    "GKE Cluster",
                    "Cloud Function",
                ],
                [
                    "europe-north1",
                    "europe-west1",
                    "us-central1",
                ],
            ),
        ]

        asset_prefixes = [
            "production",
            "staging",
            "development",
            "billing",
            "marketing",
            "customer",
            "analytics",
            "hr",
            "finance",
            "internal",
            "security",
            "data",
        ]

        existing_assets = CloudAsset.objects.count()
        target_assets = 50

        assets_created = 0

        for i in range(existing_assets + 1, target_assets + 1):
            provider, resource_types, regions = choice(provider_data)

            prefix = choice(asset_prefixes)
            resource_type = choice(resource_types)
            region = choice(regions)

            asset = CloudAsset.objects.create(
                name=f"{prefix}-{provider}-{i:03d}",
                provider=provider,
                resource_type=resource_type,
                resource_id=f"{provider}-resource-{i:06d}",
                region=region,
                tags={
                    "environment": choice(
                        ["production", "staging", "development"]
                    ),
                    "department": choice(
                        [
                            "Security",
                            "Finance",
                            "Engineering",
                            "HR",
                            "Marketing",
                            "IT",
                        ]
                    ),
                    "criticality": choice(
                        ["critical", "high", "medium", "low"]
                    ),
                },
                owner=choice(users),
                is_active=True,
            )

            assets_created += 1

        # ---------------------------------------------------------
        # Reload assets
        # ---------------------------------------------------------
        assets = list(CloudAsset.objects.filter(is_active=True))

        # ---------------------------------------------------------
        # Vulnerabilities
        # ---------------------------------------------------------
        vulnerability_titles = [
            "Unpatched operating system",
            "Missing MFA on privileged account",
            "Overly permissive security group",
            "Publicly accessible storage bucket",
            "Weak database credentials",
            "Outdated TLS configuration",
            "Exposed administrative interface",
            "Missing encryption at rest",
            "Insecure IAM policy",
            "Anonymous access enabled",
            "Open management port",
            "Outdated application dependency",
            "Insufficient logging configuration",
            "Excessive user permissions",
            "Missing security headers",
            "Weak password policy",
            "Unrestricted network access",
            "Production debug mode enabled",
            "Expired SSL certificate",
            "Unprotected API endpoint",
        ]

        descriptions = [
            "Security configuration requires review and remediation.",
            "The resource does not meet the organization's security baseline.",
            "This finding may expose the resource to unauthorized access.",
            "Security controls should be updated according to organizational policy.",
            "The configuration increases the risk of compromise.",
        ]

        severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]

        statuses = [
            VulnStatus.OPEN,
            VulnStatus.OPEN,
            VulnStatus.OPEN,
            VulnStatus.IN_PROGRESS,
            VulnStatus.IN_PROGRESS,
            VulnStatus.RESOLVED,
            VulnStatus.CLOSED,
        ]

        existing_vulns = Vulnerability.objects.count()
        target_vulns = 100

        vulnerabilities_created = 0

        for i in range(existing_vulns + 1, target_vulns + 1):
            severity = choice(severities)
            status = choice(statuses)

            # Produce realistic due dates:
            # some overdue, some due soon, some in the future.
            days_offset = randint(-30, 60)
            due_date = today + timedelta(days=days_offset)

            vuln = Vulnerability(
                title=f"{choice(vulnerability_titles)} #{i:03d}",
                description=choice(descriptions),
                severity=severity,
                status=status,
                asset=choice(assets),
                assigned_to=choice(users),
                due_date=due_date,
            )

            if status in (VulnStatus.RESOLVED, VulnStatus.CLOSED):
                vuln.remediation_notes = (
                    "Finding remediated and verified by the security team."
                )

            vuln.save()
            vulnerabilities_created += 1

        # ---------------------------------------------------------
        # Compliance records
        # ---------------------------------------------------------
        controls = list(Control.objects.select_related("framework"))

        if not controls:
            self.stdout.write(
                self.style.ERROR(
                    "No controls found. Run 'python manage.py seed_frameworks' first."
                )
            )
            return

        compliance_statuses = [
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.NON_COMPLIANT,
            ComplianceStatus.IN_PROGRESS,
            ComplianceStatus.NOT_APPLICABLE,
        ]

        existing_records = ComplianceRecord.objects.count()
        target_records = 250

        records_created = 0

        for i in range(existing_records + 1, target_records + 1):
            control = choice(controls)
            asset = choice(assets)
            status = choice(compliance_statuses)

            last_reviewed = today - timedelta(days=randint(0, 180))
            next_review_due = today + timedelta(days=randint(-30, 180))

            ComplianceRecord.objects.create(
                control=control,
                asset=asset,
                status=status,
                owner=choice(users),
                last_reviewed=last_reviewed,
                next_review_due=next_review_due,
                notes=choice(
                    [
                        "Reviewed by security team.",
                        "Evidence verified.",
                        "Control implementation requires monitoring.",
                        "Control is operating effectively.",
                        "Remediation activity is in progress.",
                        "Annual compliance review completed.",
                    ]
                ),
            )

            records_created += 1

        # ---------------------------------------------------------
        # Summary
        # ---------------------------------------------------------
        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS("Large demo data generation complete!")
        )
        self.stdout.write(
            f"New assets created: {assets_created}"
        )
        self.stdout.write(
            f"New vulnerabilities created: {vulnerabilities_created}"
        )
        self.stdout.write(
            f"New compliance records created: {records_created}"
        )
        self.stdout.write("")
        self.stdout.write(
            f"Total assets: {CloudAsset.objects.count()}"
        )
        self.stdout.write(
            f"Total vulnerabilities: {Vulnerability.objects.count()}"
        )
        self.stdout.write(
            f"Total compliance records: {ComplianceRecord.objects.count()}"
        )

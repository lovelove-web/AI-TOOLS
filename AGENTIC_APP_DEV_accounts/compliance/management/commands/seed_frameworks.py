from django.core.management.base import BaseCommand

from compliance.models import Control, Framework

SEED_DATA = {
    "ISO 27001": {
        "short_name": "ISO27001",
        "description": "ISO/IEC 27001 Information Security Management System standard.",
        "controls": [
            ("A.5.1", "Policies for information security"),
            ("A.6.1", "Internal organization"),
            ("A.8.1", "Responsibility for assets"),
            ("A.9.2", "User access management"),
            ("A.12.6", "Technical vulnerability management"),
            ("A.17.1", "Information security continuity"),
        ],
    },
    "NIST Cybersecurity Framework": {
        "short_name": "NIST-CSF",
        "description": "NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover).",
        "controls": [
            ("ID.AM-1", "Physical devices and systems are inventoried"),
            ("PR.AC-1", "Identities and credentials are managed"),
            ("PR.DS-1", "Data-at-rest is protected"),
            ("DE.CM-1", "The network is monitored to detect events"),
            ("RS.RP-1", "Response plan is executed during or after an incident"),
            ("RC.RP-1", "Recovery plan is executed during or after an incident"),
        ],
    },
    "CIS Controls": {
        "short_name": "CIS",
        "description": "Center for Internet Security Critical Security Controls.",
        "controls": [
            ("CIS-1", "Inventory and Control of Enterprise Assets"),
            ("CIS-4", "Secure Configuration of Enterprise Assets and Software"),
            ("CIS-5", "Account Management"),
            ("CIS-6", "Access Control Management"),
            ("CIS-8", "Audit Log Management"),
            ("CIS-11", "Data Recovery"),
        ],
    },
    "GDPR": {
        "short_name": "GDPR",
        "description": "EU General Data Protection Regulation.",
        "controls": [
            ("Art.5", "Principles relating to processing of personal data"),
            ("Art.25", "Data protection by design and by default"),
            ("Art.30", "Records of processing activities"),
            ("Art.32", "Security of processing"),
            ("Art.33", "Notification of a personal data breach"),
            ("Art.35", "Data protection impact assessment"),
        ],
    },
}


class Command(BaseCommand):
    help = "Seed the four core compliance frameworks (ISO 27001, NIST CSF, CIS Controls, GDPR) with baseline controls."

    def handle(self, *args, **options):
        created_frameworks = 0
        created_controls = 0
        for name, data in SEED_DATA.items():
            framework, was_created = Framework.objects.get_or_create(
                name=name, defaults={"short_name": data["short_name"], "description": data["description"]}
            )
            created_frameworks += int(was_created)
            for code, title in data["controls"]:
                _, c_created = Control.objects.get_or_create(framework=framework, code=code, defaults={"title": title})
                created_controls += int(c_created)
        self.stdout.write(self.style.SUCCESS(
            f"Seed complete: {created_frameworks} frameworks created, {created_controls} controls created."
        ))

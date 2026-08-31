from django import forms

from vulnerabilities.models import Vulnerability, VulnStatus


class VulnerabilityForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = [
            "title", "description", "severity", "status", "asset",
            "assigned_to", "due_date", "remediation_notes",
        ]
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "severity": forms.Select(attrs={"class": "form-select"}),
            "status": forms.Select(attrs={"class": "form-select"}),
            "asset": forms.Select(attrs={"class": "form-select"}),
            "assigned_to": forms.Select(attrs={"class": "form-select"}),
            "due_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "remediation_notes": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
        }

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get("status")
        notes = cleaned_data.get("remediation_notes", "").strip()
        if status in (VulnStatus.RESOLVED, VulnStatus.CLOSED) and not notes:
            self.add_error("remediation_notes", "Document the remediation before resolving or closing a finding.")
        return cleaned_data

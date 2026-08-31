from django import forms

from compliance.models import ComplianceRecord, Evidence


class ComplianceRecordForm(forms.ModelForm):
    class Meta:
        model = ComplianceRecord
        fields = ["control", "asset", "status", "owner", "last_reviewed", "next_review_due", "notes"]
        widgets = {
            "control": forms.Select(attrs={"class": "form-select"}),
            "asset": forms.Select(attrs={"class": "form-select"}),
            "status": forms.Select(attrs={"class": "form-select"}),
            "owner": forms.Select(attrs={"class": "form-select"}),
            "last_reviewed": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "next_review_due": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "notes": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
        }

    def clean(self):
        cleaned_data = super().clean()
        reviewed = cleaned_data.get("last_reviewed")
        due = cleaned_data.get("next_review_due")
        if reviewed and due and due < reviewed:
            self.add_error("next_review_due", "The next review date cannot be before the last review date.")
        return cleaned_data


class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ["file", "description"]
        widgets = {
            "file": forms.ClearableFileInput(attrs={"class": "form-control"}),
            "description": forms.TextInput(attrs={"class": "form-control"}),
        }

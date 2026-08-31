from django import forms

from assets.models import CloudAsset


class CloudAssetForm(forms.ModelForm):
    tags_text = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "env=prod, team=payments"}),
        help_text="Comma-separated key=value pairs",
        label="Tags",
    )

    class Meta:
        model = CloudAsset
        fields = ["name", "provider", "resource_type", "resource_id", "region", "owner", "is_active"]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control"}),
            "provider": forms.Select(attrs={"class": "form-select"}),
            "resource_type": forms.TextInput(attrs={"class": "form-control"}),
            "resource_id": forms.TextInput(attrs={"class": "form-control"}),
            "region": forms.TextInput(attrs={"class": "form-control"}),
            "owner": forms.Select(attrs={"class": "form-select"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["tags_text"].widget.attrs["class"] = "form-control"
        if self.instance and self.instance.pk and self.instance.tags:
            self.fields["tags_text"].initial = ", ".join(f"{k}={v}" for k, v in self.instance.tags.items())

    def clean_tags_text(self):
        raw = self.cleaned_data.get("tags_text", "")
        tags = {}
        for pair in filter(None, [p.strip() for p in raw.split(",")]):
            if "=" not in pair:
                raise forms.ValidationError("Use comma-separated key=value tags (for example, environment=production).")
            k, v = pair.split("=", 1)
            if not k.strip() or not v.strip():
                raise forms.ValidationError("Each tag needs both a key and a value.")
            tags[k.strip()] = v.strip()
        return tags

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.tags = self.cleaned_data.get("tags_text", {})
        if commit:
            instance.save()
        return instance

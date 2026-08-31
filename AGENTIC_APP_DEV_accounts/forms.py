from django import forms
from django.contrib.auth.forms import UserCreationForm

from accounts.models import Role, User


class RegistrationForm(UserCreationForm):
    """Public self-registration form.

    Security note: role is intentionally NOT exposed here. Every
    self-registered account is created as an Analyst; only an Administrator
    can elevate a user's role (via the Django admin or a future user-mgmt
    view). This prevents privilege escalation through registration.
    """

    email = forms.EmailField(required=True)
    first_name = forms.CharField(required=True, max_length=150)
    last_name = forms.CharField(required=True, max_length=150)
    department = forms.CharField(required=False, max_length=100)

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name", "department", "password1", "password2"]

    def save(self, commit=True):
        user = super().save(commit=False)
        user.role = Role.ANALYST
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "department"]
        widgets = {
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "department": forms.TextInput(attrs={"class": "form-control"}),
        }

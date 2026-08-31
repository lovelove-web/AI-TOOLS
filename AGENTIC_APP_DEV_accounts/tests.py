from django.test import TestCase
from django.urls import reverse

from accounts.models import Role, User


class RegistrationTests(TestCase):
    def test_registration_creates_analyst_role(self):
        response = self.client.post(reverse("accounts:register"), {
            "username": "jdoe",
            "email": "jdoe@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
            "department": "Security",
            "password1": "S3curePass!2026",
            "password2": "S3curePass!2026",
        })
        self.assertEqual(response.status_code, 302)
        user = User.objects.get(username="jdoe")
        self.assertEqual(user.role, Role.ANALYST)


class RoleAccessTests(TestCase):
    def setUp(self):
        self.auditor = User.objects.create_user(username="auditor1", password="pw12345678", role=Role.AUDITOR)
        self.analyst = User.objects.create_user(username="analyst1", password="pw12345678", role=Role.ANALYST)

    def test_auditor_cannot_create_vulnerability(self):
        self.client.login(username="auditor1", password="pw12345678")
        response = self.client.get(reverse("vulnerabilities:create"))
        self.assertEqual(response.status_code, 403)

    def test_analyst_can_create_vulnerability_page(self):
        self.client.login(username="analyst1", password="pw12345678")
        response = self.client.get(reverse("vulnerabilities:create"))
        self.assertEqual(response.status_code, 200)

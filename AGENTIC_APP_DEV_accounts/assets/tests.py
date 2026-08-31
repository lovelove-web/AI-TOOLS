from django.test import TestCase

from accounts.models import Role, User
from assets.forms import CloudAssetForm
from assets.models import CloudAsset, CloudProvider


class CloudAssetFormTests(TestCase):
    def test_tags_must_use_key_value_format(self):
        form = CloudAssetForm(data={
            "name": "api-01", "provider": CloudProvider.AWS,
            "resource_type": "EC2 Instance", "tags_text": "production",
        })
        self.assertFalse(form.is_valid())
        self.assertIn("key=value", form.errors["tags_text"][0])

    def test_tags_are_saved_as_json(self):
        form = CloudAssetForm(data={
            "name": "api-01", "provider": CloudProvider.AWS,
            "resource_type": "EC2 Instance", "tags_text": "environment=production, team=platform",
        })
        self.assertTrue(form.is_valid())
        asset = form.save()
        self.assertEqual(asset.tags, {"environment": "production", "team": "platform"})


class AssetAccessTests(TestCase):
    def test_auditor_can_view_but_cannot_edit_asset(self):
        auditor = User.objects.create_user(username="audit", password="pw12345678", role=Role.AUDITOR)
        asset = CloudAsset.objects.create(name="data-store", provider=CloudProvider.GCP, resource_type="Cloud Storage")
        self.client.force_login(auditor)
        self.assertEqual(self.client.get(f"/assets/{asset.pk}/").status_code, 200)
        self.assertEqual(self.client.get(f"/assets/{asset.pk}/edit/").status_code, 403)

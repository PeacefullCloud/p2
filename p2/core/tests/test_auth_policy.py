"""Tests for AuthPolicy model, resolution logic, management command, and API."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase
import io

from p2.core.auth_policy import AuthPolicy, resolve_policy
from p2.core.models import Storage, Volume
from p2.core.acl import VolumeACL

User = get_user_model()


class AuthPolicyModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="password123")
        self.admin = User.objects.create_superuser(username="adminuser", password="password123")
        self.group_dev = Group.objects.create(name="developers")
        self.group_ops = Group.objects.create(name="operations")

    def test_default_resolution_none(self):
        # No policy exists -> NONE
        self.assertEqual(resolve_policy(self.user), AuthPolicy.Requirement.NONE)

    def test_global_policy_resolution(self):
        AuthPolicy.objects.create(group=None, requirement=AuthPolicy.Requirement.MFA_REQUIRED)
        self.assertEqual(resolve_policy(self.user), AuthPolicy.Requirement.MFA_REQUIRED)

    def test_group_override_resolution(self):
        AuthPolicy.objects.create(group=None, requirement=AuthPolicy.Requirement.NONE)
        AuthPolicy.objects.create(group=self.group_dev, requirement=AuthPolicy.Requirement.MFA_REQUIRED)

        # Before joining group -> NONE
        self.assertEqual(resolve_policy(self.user), AuthPolicy.Requirement.NONE)

        # After joining developers group -> MFA_REQUIRED
        self.user.groups.add(self.group_dev)
        self.assertEqual(resolve_policy(self.user), AuthPolicy.Requirement.MFA_REQUIRED)

    def test_strictest_policy_wins(self):
        AuthPolicy.objects.create(group=None, requirement=AuthPolicy.Requirement.NONE)
        AuthPolicy.objects.create(group=self.group_dev, requirement=AuthPolicy.Requirement.MFA_REQUIRED)
        AuthPolicy.objects.create(group=self.group_ops, requirement=AuthPolicy.Requirement.SSO_REQUIRED)

        self.user.groups.add(self.group_dev, self.group_ops)
        # SSO_REQUIRED (2) is stricter than MFA_REQUIRED (1)
        self.assertEqual(resolve_policy(self.user), AuthPolicy.Requirement.SSO_REQUIRED)

    def test_management_command(self):
        out = io.StringIO()
        call_command("auth_policy", "--set-global", "mfa_required", stdout=out)
        self.assertIn("mfa_required", out.getvalue())

        policy = AuthPolicy.objects.filter(group__isnull=True).first()
        self.assertIsNotNone(policy)
        self.assertEqual(policy.requirement, AuthPolicy.Requirement.MFA_REQUIRED)

        # List command
        out = io.StringIO()
        call_command("auth_policy", "--list", stdout=out)
        self.assertIn("GLOBAL DEFAULT: mfa_required", out.getvalue())

        # Set back to none
        call_command("auth_policy", "--set-global", "none", stdout=out)
        self.assertEqual(resolve_policy(self.user), AuthPolicy.Requirement.NONE)


from p2.core.tests.utils import get_test_storage

class VolumeACLTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="adminuser", password="password123")
        self.user = User.objects.create_user(username="normaluser", password="password123")
        self.storage = get_test_storage()
        self.vol = Volume.objects.create(name="testbucket", storage=self.storage)

    def test_create_and_query_acl(self):
        acl = VolumeACL.objects.create(
            volume=self.vol,
            user=self.user,
            permissions=["read", "list"],
        )
        self.assertIn("read", acl.permissions)
        self.assertIn("list", acl.permissions)
        self.assertEqual(acl.volume, self.vol)
        self.assertEqual(acl.user, self.user)


import json
from django.test import Client

class LoginPolicyEnforcementAPITests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(username="adminuser", password="adminpassword123")
        self.user = User.objects.create_user(username="standarduser", password="userpassword123")

    def test_login_policy_none(self):
        # Default policy is NONE -> direct JWT returned
        resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "standarduser", "password": "userpassword123"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access", data)
        self.assertFalse(data.get("mfa_setup_required", False))

    def test_login_policy_mfa_required_forces_enrollment(self):
        AuthPolicy.objects.create(group=None, requirement=AuthPolicy.Requirement.MFA_REQUIRED)

        resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "standarduser", "password": "userpassword123"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("mfa_setup_required"))
        self.assertIsNotNone(data.get("enrollment_token"))

    def test_login_policy_sso_required_blocks_password(self):
        AuthPolicy.objects.create(group=None, requirement=AuthPolicy.Requirement.SSO_REQUIRED)

        resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "standarduser", "password": "userpassword123"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("SSO", resp.json().get("detail", ""))

    def test_superuser_is_exempt_from_sso_and_mfa_policy(self):
        AuthPolicy.objects.create(group=None, requirement=AuthPolicy.Requirement.SSO_REQUIRED)

        # Superuser can still log in with password
        resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "adminuser", "password": "adminpassword123"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access", data)


class UserManagementAPITests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(username="adminuser", password="adminpassword123")
        # Log in admin to get JWT
        resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "adminuser", "password": "adminpassword123"}),
            content_type="application/json",
        )
        self.token = resp.json()["access"]
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}

    def test_create_update_and_delete_user(self):
        # Create user
        resp = self.client.post(
            "/api/v1/system/user/",
            data=json.dumps({
                "username": "newuser",
                "password": "newpassword123",
                "email": "newuser@example.com",
                "is_active": True,
                "is_superuser": False,
                "groups": ["ops"],
            }),
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        user_id = resp.json()["id"]
        self.assertEqual(resp.json()["username"], "newuser")
        self.assertIn("ops", resp.json()["groups"])

        # Update user
        resp = self.client.put(
            f"/api/v1/system/user/{user_id}/",
            data=json.dumps({
                "email": "updated@example.com",
                "is_active": False,
                "groups": ["ops", "devs"],
            }),
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["email"], "updated@example.com")
        self.assertFalse(resp.json()["is_active"])
        self.assertIn("devs", resp.json()["groups"])

        # Delete user
        resp = self.client.delete(f"/api/v1/system/user/{user_id}/", **self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(User.objects.filter(id=user_id).exists())


class VolumeACLAPITests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(username="adminuser", password="adminpassword123")
        self.member = User.objects.create_user(username="memberuser", password="password123")
        self.storage = get_test_storage()
        self.vol = Volume.objects.create(name="acl-test-bucket", storage=self.storage)

        resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "adminuser", "password": "adminpassword123"}),
            content_type="application/json",
        )
        self.token = resp.json()["access"]
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}

    def test_grant_list_and_revoke_acl(self):
        # Grant ACL
        resp = self.client.post(
            f"/api/v1/core/volumes/{self.vol.uuid}/acl/",
            data=json.dumps({
                "user_id": self.member.id,
                "permissions": ["read", "write", "list"],
            }),
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        acl_id = resp.json()["id"]
        self.assertEqual(resp.json()["username"], "memberuser")
        self.assertEqual(set(resp.json()["permissions"]), {"read", "write", "list"})

        # List ACL
        resp = self.client.get(f"/api/v1/core/volumes/{self.vol.uuid}/acl/", **self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 1)

        # Revoke ACL
        resp = self.client.delete(f"/api/v1/core/volumes/{self.vol.uuid}/acl/{acl_id}/", **self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(VolumeACL.objects.filter(id=acl_id).count(), 0)


class AuthPolicyAndSSOEndpointsTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(username="adminuser", password="adminpassword123")
        self.group = Group.objects.create(name="engineering")
        resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "adminuser", "password": "adminpassword123"}),
            content_type="application/json",
        )
        self.token = resp.json()["access"]
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}

    def test_auth_policy_groups_endpoint(self):
        resp = self.client.get("/api/v1/system/auth-policy/groups/", **self.headers)
        self.assertEqual(resp.status_code, 200)
        group_names = [g["name"] for g in resp.json()]
        self.assertIn("engineering", group_names)

    def test_auth_policy_affected_count_endpoint(self):
        resp = self.client.get(
            "/api/v1/system/auth-policy/affected-count/?requirement=mfa_required",
            **self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("count", resp.json())

    def test_sso_providers_available_endpoint(self):
        resp = self.client.get("/api/v1/system/sso-providers/available/", **self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        provider_ids = [p["id"] for p in data]
        self.assertIn("google", provider_ids)

    def test_auth_me_superuser(self):
        resp = self.client.get("/api/v1/auth/me", **self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["username"], "adminuser")
        self.assertTrue(data["is_superuser"])

    def test_auth_me_standard_user(self):
        standard_user = User.objects.create_user(username="standardtester", password="testerpassword123")
        login_resp = self.client.post(
            "/api/v1/auth/login",
            data=json.dumps({"username": "standardtester", "password": "testerpassword123"}),
            content_type="application/json",
        )
        self.assertEqual(login_resp.status_code, 200)
        user_token = login_resp.json()["access"]
        
        resp = self.client.get("/api/v1/auth/me", HTTP_AUTHORIZATION=f"Bearer {user_token}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["username"], "standardtester")
        self.assertFalse(data["is_superuser"])


def _login(client, username, password):
    resp = client.post(
        "/api/v1/auth/login",
        data=json.dumps({"username": username, "password": password}),
        content_type="application/json",
    )
    assert resp.status_code == 200, resp.content
    return {"HTTP_AUTHORIZATION": f"Bearer {resp.json()['access']}"}


class VolumeVisibilityTests(TestCase):
    """A user must only see buckets they own or were granted access to."""

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(username="adminuser", password="adminpassword123")
        self.member = User.objects.create_user(username="tester", password="testerpassword123")
        self.storage = get_test_storage()
        self.vol = Volume.objects.create(name="private-bucket", storage=self.storage)
        self.admin_headers = _login(self.client, "adminuser", "adminpassword123")
        self.member_headers = _login(self.client, "tester", "testerpassword123")

    def test_unassigned_user_cannot_see_or_open_bucket(self):
        resp = self.client.get("/api/v1/core/volume/", **self.member_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

        resp = self.client.get(f"/api/v1/core/volume/{self.vol.uuid}/", **self.member_headers)
        self.assertEqual(resp.status_code, 404)

    def test_granted_user_can_see_bucket(self):
        VolumeACL.objects.create(volume=self.vol, user=self.member, permissions=["read", "list"])

        resp = self.client.get("/api/v1/core/volume/", **self.member_headers)
        self.assertEqual(resp.status_code, 200)
        names = [v["name"] for v in resp.json()]
        self.assertIn("private-bucket", names)

    def test_superuser_sees_all_buckets(self):
        resp = self.client.get("/api/v1/core/volume/", **self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        names = [v["name"] for v in resp.json()]
        self.assertIn("private-bucket", names)

    def test_non_superuser_cannot_create_bucket(self):
        resp = self.client.post(
            "/api/v1/core/volume/",
            data=json.dumps({"name": "nope-bucket"}),
            content_type="application/json",
            **self.member_headers,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(Volume.objects.filter(name="nope-bucket").exists())

    def test_superuser_can_create_bucket(self):
        resp = self.client.post(
            "/api/v1/core/volume/",
            data=json.dumps({"name": "admin-bucket"}),
            content_type="application/json",
            **self.admin_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(Volume.objects.filter(name="admin-bucket").exists())

    def test_permissions_are_reported(self):
        VolumeACL.objects.create(volume=self.vol, user=self.member, permissions=["read", "list"])
        resp = self.client.get("/api/v1/core/volume/", **self.member_headers)
        self.assertEqual(resp.status_code, 200)
        vol = next(v for v in resp.json() if v["name"] == "private-bucket")
        self.assertEqual(set(vol["permissions"]), {"read", "list"})
        self.assertFalse(vol["permissions"] == ["admin"])

    def test_superuser_gets_admin_permission(self):
        resp = self.client.get(f"/api/v1/core/volume/{self.vol.uuid}/", **self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("admin", resp.json()["permissions"])


class BucketAdminGranteesTests(TestCase):
    """A non-superuser bucket owner can populate the access-assignment list."""

    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(username="bucketowner", password="ownerpassword123")
        self.other = User.objects.create_user(username="tester", password="testerpassword123")
        self.storage = get_test_storage()
        self.vol = Volume.objects.create(name="owner-bucket", storage=self.storage)
        VolumeACL.objects.create(
            volume=self.vol, user=self.owner,
            permissions=["read", "write", "delete", "list", "admin"],
        )
        self.owner_headers = _login(self.client, "bucketowner", "ownerpassword123")

    def test_bucket_admin_lists_grantables(self):
        resp = self.client.get(
            f"/api/v1/core/volumes/{self.vol.uuid}/acl/grantables/",
            **self.owner_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        usernames = [u["username"] for u in data["users"]]
        self.assertIn("tester", usernames)

    def test_non_admin_cannot_list_grantables(self):
        other_headers = _login(self.client, "tester", "testerpassword123")
        resp = self.client.get(
            f"/api/v1/core/volumes/{self.vol.uuid}/acl/grantables/",
            **other_headers,
        )
        self.assertEqual(resp.status_code, 403)


class PublicSsoProviderTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_public_providers_requires_no_auth(self):
        resp = self.client.get("/api/v1/system/sso-providers/public/")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)


class ServeRuleAuthorizationTests(TestCase):
    """Serve rules are system-level routing config and must be admin-only."""

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(username="adminuser", password="adminpassword123")
        self.member = User.objects.create_user(username="memberuser", password="memberpassword123")
        self.admin_headers = _login(self.client, "adminuser", "adminpassword123")
        self.member_headers = _login(self.client, "memberuser", "memberpassword123")

    def test_member_cannot_list_serve_rules(self):
        resp = self.client.get("/api/v1/tier0/policy/", **self.member_headers)
        self.assertEqual(resp.status_code, 403)

    def test_member_cannot_create_serve_rule(self):
        resp = self.client.post(
            "/api/v1/tier0/policy/",
            data=json.dumps({"name": "evil", "blob_query": "SELECT 1"}),
            content_type="application/json",
            **self.member_headers,
        )
        self.assertEqual(resp.status_code, 403)

    def test_superuser_can_list_serve_rules(self):
        resp = self.client.get("/api/v1/tier0/policy/", **self.admin_headers)
        self.assertEqual(resp.status_code, 200)


class PresignAuthorizationTests(TestCase):
    """Generating a presigned URL must respect the bucket ACL."""

    def setUp(self):
        self.client = Client()
        self.member = User.objects.create_user(username="reader", password="readerpassword123")
        self.outsider = User.objects.create_user(username="outsider", password="outsiderpassword123")
        self.storage = get_test_storage()
        self.vol = Volume.objects.create(name="presign-bucket", storage=self.storage)
        VolumeACL.objects.create(volume=self.vol, user=self.member, permissions=["read", "list"])
        self.reader_headers = _login(self.client, "reader", "readerpassword123")
        self.outsider_headers = _login(self.client, "outsider", "outsiderpassword123")

    def _presign(self, headers, method):
        return self.client.post(
            "/api/v1/s3/presign/",
            data=json.dumps({"bucket": "presign-bucket", "key": "file.txt", "method": method}),
            content_type="application/json",
            **headers,
        )

    def test_readonly_member_cannot_presign_put(self):
        resp = self._presign(self.reader_headers, "PUT")
        self.assertEqual(resp.status_code, 403)

    def test_non_member_cannot_presign_get(self):
        resp = self._presign(self.outsider_headers, "GET")
        self.assertEqual(resp.status_code, 403)

    def test_missing_bucket_returns_404(self):
        resp = self.client.post(
            "/api/v1/s3/presign/",
            data=json.dumps({"bucket": "does-not-exist", "key": "file.txt", "method": "GET"}),
            content_type="application/json",
            **self.reader_headers,
        )
        self.assertEqual(resp.status_code, 404)


class BucketCorsApiTests(TestCase):
    """Volume update endpoint persists and clears S3 CORS rules for bucket admins."""

    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(username="corsowner", password="ownerpassword123")
        self.reader = User.objects.create_user(username="corsreader", password="readerpassword123")
        self.storage = get_test_storage()
        self.vol = Volume.objects.create(name="cors-ui-bucket", storage=self.storage)
        VolumeACL.objects.create(
            volume=self.vol, user=self.owner,
            permissions=["read", "write", "delete", "list", "admin"],
        )
        VolumeACL.objects.create(
            volume=self.vol, user=self.reader,
            permissions=["read", "list"],
        )
        self.owner_headers = _login(self.client, "corsowner", "ownerpassword123")
        self.reader_headers = _login(self.client, "corsreader", "readerpassword123")

    def test_admin_can_set_and_clear_cors_rules(self):
        rules = [
            {
                "AllowedOrigins": ["https://app.example.com"],
                "AllowedMethods": ["GET", "PUT"],
                "AllowedHeaders": ["*"],
                "ExposeHeaders": ["ETag"],
                "MaxAgeSeconds": 3600,
            }
        ]
        resp = self.client.put(
            f"/api/v1/core/volume/{self.vol.uuid}/",
            data=json.dumps({"cors_rules": rules}),
            content_type="application/json",
            **self.owner_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.vol.refresh_from_db()
        self.assertEqual(self.vol.tags.get("s3.p2.io/cors/rules"), rules)

        # Clear rules
        resp = self.client.put(
            f"/api/v1/core/volume/{self.vol.uuid}/",
            data=json.dumps({"cors_rules": []}),
            content_type="application/json",
            **self.owner_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.vol.refresh_from_db()
        self.assertNotIn("s3.p2.io/cors/rules", self.vol.tags)

    def test_non_admin_cannot_update_cors_rules(self):
        resp = self.client.put(
            f"/api/v1/core/volume/{self.vol.uuid}/",
            data=json.dumps({
                "cors_rules": [
                    {"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}
                ]
            }),
            content_type="application/json",
            **self.reader_headers,
        )
        self.assertEqual(resp.status_code, 403)



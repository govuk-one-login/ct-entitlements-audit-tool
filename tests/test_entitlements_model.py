import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from entitlements import EntitlementsModel


@pytest.fixture
def model(base_path):
    return EntitlementsModel(str(base_path))


class TestLoadUsers:
    def test_loads_users_from_csv(self, model):
        assert "alice" in model.users
        assert "bob" in model.users
        assert "charlie" not in model.users

    def test_user_data_fields(self, model):
        assert model.users["alice"]["display_name"] == "Alice Smith"
        assert model.users["alice"]["email"] == "alice@example.com"
        assert model.users["alice"]["pod"] == "alpha"
        assert model.users["alice"]["team"] == "alpha-team-one"

    def test_skips_role_csv(self, model):
        assert "ignored" not in model.users

    def test_maps_user_to_team_group(self, model):
        assert "alpha-team-one" in model.user_to_groups["alice"]


class TestLoadGroups:
    def test_loads_groups(self, model):
        assert "alpha-team-one" in model.groups
        assert "alpha-team-two" in model.groups

    def test_group_to_roles_mapping(self, model):
        assert model.group_to_roles["alpha-team-one"] == ["team-one-engineers", "team-two-engineers"]
        assert model.group_to_roles["alpha-team-two"] == ["team-two-engineers"]
        assert model.group_to_roles["beta-team-one"] == ["dev-only-engineers"]

    def test_collaborators_added_to_user_groups(self, model):
        assert "alpha-team-one" in model.user_to_groups["charlie"]

    def test_permanent_members_added_to_user_groups(self, model):
        assert "alpha-team-two" in model.user_to_groups["danielle"]


class TestLoadEntitlements:
    def test_loads_dev_permissions(self, model):
        team_one_entitlements = model.role_entitlements["team-one-engineers"]
        dev_assignments = [e for e in team_one_entitlements if e.assignment_set == "development"]
        standing = [e for e in dev_assignments if e.entitlement_type == "STANDING"]
        eligible = [e for e in dev_assignments if e.entitlement_type == "ELIGIBLE"]
        assert all(e.permission_set == "Admin" for e in standing)
        assert not eligible
        assert standing[0].accounts == ["dev-account-a", "dev-account-b"]
        assert standing[0].org_units == ["dev-ou"]

    def test_loads_non_prod_permissions(self, model):
        team_one_entitlements = model.role_entitlements["team-one-engineers"]
        non_prod_assignments = [e for e in team_one_entitlements if e.assignment_set == "non-production"]
        standing = [e for e in non_prod_assignments if e.entitlement_type == "STANDING"]
        eligible = [e for e in non_prod_assignments if e.entitlement_type == "ELIGIBLE"]
        assert all(e.permission_set == "ReadOnly" for e in standing)
        assert all(e.permission_set == "Admin" for e in eligible)
        assert standing[0].accounts == ["staging-account"]
        assert eligible[0].accounts == ["staging-account"]
        assert standing[0].org_units == ["staging-ou"]

    def test_loads_prod_permissions(self, model):
        team_one_entitlements = model.role_entitlements["team-one-engineers"]
        prod_assignments = [e for e in team_one_entitlements if e.assignment_set == "production"]
        standing = [e for e in prod_assignments if e.entitlement_type == "STANDING"]
        eligible = [e for e in prod_assignments if e.entitlement_type == "ELIGIBLE"]
        assert all(e.permission_set == "ViewOnly" for e in standing)
        assert all(e.permission_set == "PowerUser" for e in eligible)
        assert standing[0].accounts == ["prod-account-a"]
        assert eligible[0].accounts == ["prod-account-a"]

    def test_skips_emergency_access(self, model):
        team_one_entitlements = model.role_entitlements["team-one-engineers"]
        assert not any(e.permission_set == "EmergencyAdmin" for e in team_one_entitlements)


class TestLoadPermissions:
    def test_loads_permission_sets(self, model):
        assert "ViewOnly" in model.permissions
        assert "PowerUser" in model.permissions

    def test_permission_description(self, model):
        assert model.permissions["ViewOnly"].description == "View only access"

    def test_permission_managed_policies(self, model):
        assert "arn:aws:iam::aws:policy/ViewOnlyAccess" in model.permissions["ViewOnly"].managed_policies

    def test_permission_multiple_policies(self, model):
        assert len(model.permissions["PowerUser"].managed_policies) == 2

    def test_skips_missing_files(self, model):
        # permissions_pod_eligible.auto.tfvars doesn't exist - should not error
        assert model.permissions  # still loaded from the file that exists


class TestParsePermissionsHcl:
    def test_parses_single_block(self, model):
        content = '''
TestPerm = {
  description = "Test permission"
  managed_policies = ["arn:aws:iam::aws:policy/TestPolicy"]
}
'''
        model._parse_permissions_hcl(content)
        assert "TestPerm" in model.permissions
        assert model.permissions["TestPerm"].managed_policies == ["arn:aws:iam::aws:policy/TestPolicy"]

    def test_parses_empty_policies(self, model):
        content = '''
EmptyPerm = {
  description = "No policies"
  managed_policies = []
}
'''
        model._parse_permissions_hcl(content)
        assert "EmptyPerm" in model.permissions
        assert model.permissions["EmptyPerm"].managed_policies == []

    def test_parses_inline_policies(self, model):
        content = '''
TestInlinePerm = {
  description = "Test permission"
  managed_policies = []
  inline_policy = [
    "TestInlinePolicy"
  ]
}
'''
        model._parse_permissions_hcl(content)
        assert "TestInlinePerm" in model.permissions
        assert model.permissions["TestInlinePerm"].inline_policies == ["TestInlinePolicy"]

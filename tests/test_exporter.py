"""Tests for entitlements.exporter module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from entitlements import EntitlementsModel, export_data
from entitlements.exporter import _sort_value


@pytest.fixture
def model(base_path):
    """Create an EntitlementsModel from the test fixture base_path."""
    return EntitlementsModel(str(base_path))


class TestSortValue:
    """Tests for the _sort_value helper function."""

    def test_sorts_dict_keys(self):
        """Verify dict keys are sorted alphabetically."""
        result = _sort_value({"b": 1, "a": 2})
        assert list(result.keys()) == ["a", "b"]

    def test_sorts_list_of_strings(self):
        """Verify lists of strings are sorted."""
        result = _sort_value(["cherry", "apple", "banana"])
        assert result == ["apple", "banana", "cherry"]

    def test_sorts_nested_dicts(self):
        """Verify nested dicts are recursively sorted."""
        result = _sort_value({"z": {"b": 1, "a": 2}, "a": 3})
        assert list(result.keys()) == ["a", "z"]
        assert list(result["z"].keys()) == ["a", "b"]

    def test_returns_primitives_unchanged(self):
        """Verify primitives pass through unchanged."""
        assert _sort_value(42) == 42
        assert _sort_value("hello") == "hello"
        assert _sort_value(None) is None


class TestExportDataFilters:
    """Tests for export_data with various filter strings."""

    def test_export_all_returns_all_sections(self, model):
        """Verify 'all' filter returns users, groups, roles, permission_sets, accounts."""
        result = export_data(model, "all")
        assert "accounts" in result
        assert "groups" in result
        assert "permission_sets" in result
        assert "roles" in result
        assert "users" in result

    def test_export_users_returns_list(self, model):
        """Verify 'users' filter returns a list of user dicts."""
        result = export_data(model, "users")
        assert isinstance(result, list)
        aliases = [user["alias"] for user in result]
        assert "alice" in aliases
        assert "bob" in aliases

    def test_export_groups_returns_list(self, model):
        """Verify 'groups' filter returns a list of group dicts."""
        result = export_data(model, "groups")
        assert isinstance(result, list)
        names = [group["name"] for group in result]
        assert "alpha-team-one" in names

    def test_export_roles_returns_list(self, model):
        """Verify 'roles' filter returns a list of role dicts."""
        result = export_data(model, "roles")
        assert isinstance(result, list)
        names = [role["name"] for role in result]
        assert "team-one" in names

    def test_export_permissionsets_returns_list(self, model):
        """Verify 'permissionsets' filter returns a list of permission set dicts."""
        result = export_data(model, "permissionsets")
        assert isinstance(result, list)
        names = [perm["name"] for perm in result]
        assert "ViewOnly" in names

    def test_export_accounts_returns_list(self, model):
        """Verify 'accounts' filter returns a list of account dicts."""
        result = export_data(model, "accounts")
        assert isinstance(result, list)
        accounts = [acc["account"] for acc in result]
        assert "dev-account-a" in accounts

    def test_unknown_filter_returns_none(self, model):
        """Verify unknown filter returns None."""
        result = export_data(model, "nonexistent")
        assert result is None


class TestExportUser:
    """Tests for export_data with user= prefix."""

    def test_export_existing_user(self, model):
        """Verify exporting a known user returns correct fields."""
        result = export_data(model, "user=alice")
        assert result["alias"] == "alice"
        assert result["display_name"] == "Alice Smith"
        assert result["email"] == "alice@example.com"
        assert result["pod"] == "alpha"
        assert result["team"] == "alpha-team-one"
        assert "groups" in result
        assert "roles" in result
        assert "standing_permissions" in result
        assert "eligible_permissions" in result

    def test_export_nonexistent_user_returns_none(self, model):
        """Verify exporting an unknown user returns None."""
        result = export_data(model, "user=nobody")
        assert result is None

    def test_user_has_standing_permissions(self, model):
        """Verify user's standing permissions contain expected accounts."""
        result = export_data(model, "user=alice")
        assert "dev-account-a" in result["standing_permissions"]

    def test_user_has_eligible_permissions(self, model):
        """Verify user's eligible permissions contain expected accounts."""
        result = export_data(model, "user=alice")
        assert "prod-account-a" in result["eligible_permissions"]


class TestExportGroup:
    """Tests for export_data with group= prefix."""

    def test_export_existing_group(self, model):
        """Verify exporting a known group returns correct fields."""
        result = export_data(model, "group=alpha-team-one")
        assert result["name"] == "alpha-team-one"
        assert "roles" in result
        assert "collaborators" in result
        assert "members" in result

    def test_export_group_contains_members(self, model):
        """Verify group export lists its members."""
        result = export_data(model, "group=alpha-team-one")
        assert "alice" in result["members"]
        assert "bob" in result["members"]
        assert "charlie" in result["members"]

    def test_export_group_contains_roles(self, model):
        """Verify group export lists its roles."""
        result = export_data(model, "group=alpha-team-one")
        assert "team-one" in result["roles"]
        assert "team-two" in result["roles"]

    def test_export_nonexistent_group_returns_none(self, model):
        """Verify exporting an unknown group returns None."""
        result = export_data(model, "group=nonexistent")
        assert result is None


class TestExportRole:
    """Tests for export_data with role= prefix."""

    def test_export_existing_role(self, model):
        """Verify exporting a known role returns correct fields."""
        result = export_data(model, "role=team-one")
        assert result["name"] == "team-one"
        assert "groups" in result
        assert "entitlements" in result

    def test_export_role_has_entitlements(self, model):
        """Verify role export contains entitlement entries."""
        result = export_data(model, "role=team-one")
        assert len(result["entitlements"]) > 0
        perm_sets = [ent["permission_set"] for ent in result["entitlements"]]
        assert "Admin" in perm_sets

    def test_export_role_lists_groups(self, model):
        """Verify role export lists groups that include it."""
        result = export_data(model, "role=team-one")
        assert "alpha-team-one" in result["groups"]

    def test_export_nonexistent_role_returns_none(self, model):
        """Verify exporting an unknown role returns None."""
        result = export_data(model, "role=nonexistent")
        assert result is None


class TestExportPermissionSet:
    """Tests for export_data with permissionset= prefix."""

    def test_export_existing_permissionset(self, model):
        """Verify exporting a known permission set returns correct fields."""
        result = export_data(model, "permissionset=ViewOnly")
        assert result["name"] == "ViewOnly"
        assert result["description"] == "View only access"
        assert "managed_policies" in result
        assert "inline_policies" in result
        assert "used_by_roles" in result

    def test_export_permissionset_used_by_roles(self, model):
        """Verify permission set lists roles that use it."""
        result = export_data(model, "permissionset=ViewOnly")
        assert "team-one" in result["used_by_roles"]

    def test_export_nonexistent_permissionset_returns_none(self, model):
        """Verify exporting an unknown permission set returns None."""
        result = export_data(model, "permissionset=NonExistent")
        assert result is None


class TestExportAccount:
    """Tests for export_data with account= prefix."""

    def test_export_existing_account(self, model):
        """Verify exporting a known account returns correct fields."""
        result = export_data(model, "account=dev-account-a")
        assert result["account"] == "dev-account-a"
        assert "standing_access" in result
        assert "eligible_access" in result

    def test_export_account_standing_access(self, model):
        """Verify account export lists users with standing access."""
        result = export_data(model, "account=dev-account-a")
        standing_users = [entry["user"] for entry in result["standing_access"]]
        assert "alice" in standing_users

    def test_export_account_eligible_access(self, model):
        """Verify account export lists users with eligible access."""
        result = export_data(model, "account=prod-account-a")
        eligible_users = [entry["user"] for entry in result["eligible_access"]]
        assert "alice" in eligible_users

    def test_export_nonexistent_account_returns_none(self, model):
        """Verify exporting an unknown account returns None."""
        result = export_data(model, "account=nonexistent")
        assert result is None

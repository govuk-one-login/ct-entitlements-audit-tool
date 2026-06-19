import sys
import importlib.util
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from entitlements import EntitlementsModel

# Load entitlements.py entry point as a module without conflicting with the package
_spec = importlib.util.spec_from_file_location(
    "entitlements_cli",
    str(Path(__file__).parent.parent / "entitlements.py"),
)
_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cli)
resolve_user = _cli.resolve_user
cmd_account = _cli.cmd_account
cmd_list_roles = _cli.cmd_list_roles
cmd_list_users = _cli.cmd_list_users
cmd_permission = _cli.cmd_permission
cmd_user = _cli.cmd_user


@pytest.fixture
def model(base_path):
    return EntitlementsModel(str(base_path))


class TestResolveUser:
    def test_resolves_by_alias(self, model):
        assert resolve_user(model, "alice") == "alice"

    def test_resolves_by_email(self, model):
        assert resolve_user(model, "alice@example.com") == "alice"

    def test_resolves_by_email_case_insensitive(self, model):
        assert resolve_user(model, "Alice@Example.com") == "alice"

    def test_returns_none_for_unknown_alias(self, model):
        assert resolve_user(model, "nonexistent") is None

    def test_returns_none_for_unknown_email(self, model):
        assert resolve_user(model, "nobody@example.com") is None


class TestCmdListRoles:
    def test_prints_header_with_role_count(self, model, capsys):
        cmd_list_roles(model)
        output = capsys.readouterr().out
        assert "All Roles (3)" in output

    def test_lists_roles_alphabetically(self, model, capsys):
        cmd_list_roles(model)
        output = capsys.readouterr().out
        team_one_pos = output.index("team-one-engineers")
        team_two_pos = output.index("team-two-engineers")
        assert team_one_pos < team_two_pos

    def test_shows_group_count_for_role(self, model, capsys):
        cmd_list_roles(model)
        output = capsys.readouterr().out
        assert "team-one-engineers" in output
        assert "(used by 1 group(s))" in output
        # team-two-engineers is used by alpha-team-one and alpha-team-two (2 groups)
        assert "(used by 2 group(s))" in output

    def test_lists_all_roles(self, model, capsys):
        cmd_list_roles(model)
        output = capsys.readouterr().out
        assert "team-one-engineers" in output
        assert "team-two-engineers" in output


class TestCmdListUsers:
    def test_prints_header_with_user_count(self, model, capsys):
        cmd_list_users(model)
        output = capsys.readouterr().out
        assert "All Users (3)" in output

    def test_groups_users_by_pod(self, model, capsys):
        cmd_list_users(model)
        output = capsys.readouterr().out
        assert "ALPHA:" in output

    def test_lists_users_alphabetically_within_pod(self, model, capsys):
        cmd_list_users(model)
        output = capsys.readouterr().out
        alice_pos = output.index("Alice Smith")
        bob_pos = output.index("Bob Jones")
        assert alice_pos < bob_pos

    def test_shows_user_alias(self, model, capsys):
        cmd_list_users(model)
        output = capsys.readouterr().out
        assert "alice" in output
        assert "bob" in output

    def test_shows_user_team(self, model, capsys):
        cmd_list_users(model)
        output = capsys.readouterr().out
        assert "alpha-team-one" in output


class TestCmdPermission:
    def test_prints_header_with_permission_name(self, model, capsys):
        cmd_permission(model, "ViewOnly")
        output = capsys.readouterr().out
        assert "Permission Set: ViewOnly" in output

    def test_shows_description(self, model, capsys):
        cmd_permission(model, "ViewOnly")
        output = capsys.readouterr().out
        assert "View only access" in output

    def test_shows_managed_policies(self, model, capsys):
        cmd_permission(model, "ViewOnly")
        output = capsys.readouterr().out
        assert "arn:aws:iam::aws:policy/ViewOnlyAccess" in output

    def test_shows_multiple_managed_policies(self, model, capsys):
        cmd_permission(model, "PowerUser")
        output = capsys.readouterr().out
        assert "arn:aws:iam::aws:policy/PowerUserAccess" in output
        assert "arn:aws:iam::aws:policy/IAMReadOnlyAccess" in output

    def test_shows_roles_using_permission(self, model, capsys):
        cmd_permission(model, "ViewOnly")
        output = capsys.readouterr().out
        assert "Used by roles:" in output
        assert "team-one-engineers" in output

    def test_returns_true_for_known_permission(self, model):
        assert cmd_permission(model, "ViewOnly")

    def test_returns_false_for_unknown_permission(self, model, capsys):
        assert not cmd_permission(model, "NonExistent")

    def test_prints_not_found_for_unknown_permission(self, model, capsys):
        cmd_permission(model, "NonExistent")
        output = capsys.readouterr().out
        assert "not found" in output


class TestCmdListUsersProductionOnly:
    def test_production_only_shows_users_with_production_access(self, model, capsys):
        cmd_list_users(model, production_only=True)
        output = capsys.readouterr().out
        # alice and bob both have production access via team-one and team-two roles
        assert "alice" in output
        assert "bob" in output

    def test_production_only_header_shows_filtered_count(self, model, capsys):
        cmd_list_users(model, production_only=True)
        output = capsys.readouterr().out
        assert "Users with Production Access" in output

    def test_production_only_excludes_users_without_production(self, model, capsys):
        cmd_list_users(model, production_only=True)
        output = capsys.readouterr().out
        # nopr only has dev-only-role with development assignment_set
        assert "nopr" not in output
        assert "alice" in output


class TestCmdUserProductionOnly:
    def test_without_flag_shows_all_accounts(self, model, capsys):
        cmd_user(model, "alice")
        output = capsys.readouterr().out
        assert "dev-account-a" in output
        assert "staging-account" in output
        assert "prod-account-a" in output

    def test_production_only_excludes_non_production_accounts(self, model, capsys):
        cmd_user(model, "alice", production_only=True)
        output = capsys.readouterr().out
        assert "dev-account-a" not in output
        assert "staging-account" not in output
        assert "prod-account-a" in output

    def test_production_only_shows_production_standing(self, model, capsys):
        cmd_user(model, "alice", production_only=True)
        output = capsys.readouterr().out
        assert "ViewOnly" in output

    def test_production_only_shows_production_eligible(self, model, capsys):
        cmd_user(model, "alice", production_only=True)
        output = capsys.readouterr().out
        assert "PowerUser" in output

    def test_production_only_with_account_filter(self, model, capsys):
        cmd_user(model, "alice", account="prod-account-a", production_only=True)
        output = capsys.readouterr().out
        assert "ViewOnly" in output
        assert "PowerUser" in output

    def test_production_only_with_account_excludes_non_prod_assignments(self, model, capsys):
        # dev-account-a only has 'development' assignment_set, should show nothing
        cmd_user(model, "alice", account="dev-account-a", production_only=True)
        output = capsys.readouterr().out
        assert "Admin" not in output

    def test_production_only_with_prod_account_b(self, model, capsys):
        # prod-account-b is in team-two's production assignment_set
        cmd_user(model, "alice", account="prod-account-b", production_only=True)
        output = capsys.readouterr().out
        assert "ViewOnly" in output


class TestCmdUserEntitlementType:
    def test_standing_only_shows_standing_permissions(self, model, capsys):
        cmd_user(model, "alice", entitlement_type="STANDING")
        output = capsys.readouterr().out
        assert "Standing Permissions" in output
        assert "Eligible Permissions" not in output

    def test_eligible_only_shows_eligible_permissions(self, model, capsys):
        cmd_user(model, "alice", entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "Eligible Permissions" in output
        assert "Standing Permissions" not in output

    def test_standing_only_includes_standing_accounts(self, model, capsys):
        cmd_user(model, "alice", entitlement_type="STANDING")
        output = capsys.readouterr().out
        assert "dev-account-a" in output
        assert "Admin" in output

    def test_eligible_only_includes_eligible_accounts(self, model, capsys):
        cmd_user(model, "alice", entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "prod-account-a" in output
        assert "PowerUser" in output

    def test_standing_with_account_filter(self, model, capsys):
        cmd_user(model, "alice", account="prod-account-a", entitlement_type="STANDING")
        output = capsys.readouterr().out
        assert "Standing" in output
        assert "ViewOnly" in output
        assert "Eligible" not in output

    def test_eligible_with_account_filter(self, model, capsys):
        cmd_user(model, "alice", account="prod-account-a", entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "Eligible" in output
        assert "PowerUser" in output
        assert "Standing" not in output

    def test_no_filter_shows_both(self, model, capsys):
        cmd_user(model, "alice")
        output = capsys.readouterr().out
        assert "Standing Permissions" in output
        assert "Eligible Permissions" in output


class TestCmdAccountEntitlementType:
    def test_standing_only_shows_standing_access(self, model, capsys):
        cmd_account(model, "dev-account-a", entitlement_type="STANDING")
        output = capsys.readouterr().out
        assert "Standing Access" in output
        assert "Eligible Access" not in output

    def test_eligible_only_shows_eligible_access(self, model, capsys):
        cmd_account(model, "prod-account-a", entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "Eligible Access" in output
        assert "Standing Access" not in output

    def test_standing_only_lists_users_with_standing(self, model, capsys):
        cmd_account(model, "dev-account-a", entitlement_type="STANDING")
        output = capsys.readouterr().out
        assert "alice" in output

    def test_eligible_only_lists_users_with_eligible(self, model, capsys):
        cmd_account(model, "prod-account-a", entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "alice" in output
        assert "PowerUser" in output

    def test_no_filter_shows_both(self, model, capsys):
        cmd_account(model, "prod-account-a")
        output = capsys.readouterr().out
        assert "Standing Access" in output
        assert "Eligible Access" in output


class TestCmdListUsersEntitlementType:
    def test_standing_only_shows_users_with_standing(self, model, capsys):
        cmd_list_users(model, entitlement_type="STANDING")
        output = capsys.readouterr().out
        # alice and bob have standing permissions via team-one-engineers and team-two-engineers
        assert "alice" in output
        assert "bob" in output

    def test_standing_only_includes_user_with_only_standing(self, model, capsys):
        # nopr has dev-only-engineers which only has standing_permissions
        cmd_list_users(model, entitlement_type="STANDING")
        output = capsys.readouterr().out
        assert "nopr" in output

    def test_eligible_only_excludes_standing_only_user(self, model, capsys):
        # nopr's dev-only-engineers role has no eligible_permissions
        cmd_list_users(model, entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "nopr" not in output

    def test_eligible_only_shows_users_with_eligible(self, model, capsys):
        cmd_list_users(model, entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "alice" in output
        assert "bob" in output

    def test_standing_header_shows_filtered_label(self, model, capsys):
        cmd_list_users(model, entitlement_type="STANDING")
        output = capsys.readouterr().out
        assert "Standing" in output

    def test_eligible_header_shows_filtered_label(self, model, capsys):
        cmd_list_users(model, entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        assert "Eligible" in output

    def test_combined_production_only_and_eligible(self, model, capsys):
        cmd_list_users(model, production_only=True, entitlement_type="ELIGIBLE")
        output = capsys.readouterr().out
        # alice and bob have eligible production permissions, nopr does not
        assert "alice" in output
        assert "bob" in output
        assert "nopr" not in output

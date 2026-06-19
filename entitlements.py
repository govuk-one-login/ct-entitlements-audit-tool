#!/usr/bin/env python3
"""
Entitlements Query Interface

Queries user permissions across AWS accounts based on the Terraform
Identity Center entitlements configuration.

Usage:
    python entitlements.py                              # Interactive mode
    python entitlements.py user <alias|email> [account] # User permissions
    python entitlements.py account <account_name>       # Account access audit
    python entitlements.py role <role_name>             # Role details
    python entitlements.py permission <permission_name> # Permission set details
    python entitlements.py list-users                   # List all users
    python entitlements.py list-roles                   # List all roles
    python entitlements.py export <filter>              # Export as JSON

Exit codes:
    0 - Success
    2 - Invalid or no command line arguments
    3 - Base path (terraform/) does not exist
    5 - User/Account/Role not found
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from entitlements import EntitlementsModel, export_data

logger = logging.getLogger(__name__)

RED = "\033[31m"
RESET = "\033[0m"


def print_header(title: str):
    """Print a formatted section header.

    Args:
        title: str header text to display
    """
    print(f"\n{'='*80}")
    print(title)
    print(f"{'='*80}\n")


def resolve_user(model: EntitlementsModel, identifier: str) -> str | None:
    """Resolve a user alias or email address to a user alias."""
    if identifier in model.users:
        return identifier
    resolved = model.find_user_by_email(identifier)
    if resolved:
        return resolved
    return None


def print_permissions(title: str, permissions: Dict[str, List[str]],
                    model: EntitlementsModel = None, show_policies: bool = False):
    """Print a permissions section (standing or eligible).

    Args:
        title: str section title to display
        permissions: Dict[str, List[str]] mapping account names to permission lists
        model: EntitlementsModel optional, used to resolve policy details
        show_policies: bool whether to expand managed policies for each permission
    """
    print(f"{title}:")
    for account, perms_list in sorted(permissions.items()):
        print(f"\n  {account}:")
        for perm in perms_list:
            print(f"    - {perm}")
            if show_policies and model:
                details = model.get_permission_details(perm)
                if details:
                    for policy in details.managed_policies:
                        print(f"        -> {policy}")


def cmd_user(model: EntitlementsModel, identifier: str, account: str = None,
             detailed: bool = False, production_only: bool = False) -> bool:
    user_alias = resolve_user(model, identifier)
    if not user_alias:
        print(f"User '{identifier}' not found")
        return False

    perms = model.get_user_permissions(user_alias)

    user_data = model.users[user_alias]
    print_header(f"User: {user_data['display_name']} ({user_alias})")
    print(f"Email: {user_data['email']}")
    print(f"Pod: {user_data['pod']}")
    print(f"\nGroups: {', '.join(perms.groups)}")
    print(f"Roles: {', '.join(perms.roles)}\n")

    if account:
        print(f"Permissions in account '{account}':\n")

        # Build the access chain: group -> role -> entitlement for this account
        # Deduplicate by permission set, collecting all granting paths
        groups = model.user_to_groups.get(user_alias, [])
        by_type = {'STANDING': defaultdict(list), 'ELIGIBLE': defaultdict(list)}

        for group in groups:
            for role in model.group_to_roles.get(group, []):
                for ent in model.role_entitlements.get(role, []):
                    if account in ent.accounts:
                        if production_only and ent.assignment_set != 'production':
                            continue
                        by_type[ent.entitlement_type][ent.permission_set].append(
                            (group, role, ent.assignment_set)
                        )

        if by_type['STANDING']:
            print("  Standing (Always Active):")
            for perm_set, paths in sorted(by_type['STANDING'].items()):
                print(f"\n    - {perm_set}")
                if detailed:
                    for group, role, assignment_set in paths:
                        print(f"        User '{user_alias}' → Group '{group}' → Role '{role}' → Assignment '{assignment_set}' → Account '{account}'")
                details = model.get_permission_details(perm_set)
                if details:
                    for policy in details.managed_policies:
                        print(f"        → {policy}")
                    for policy in details.inline_policies:
                        print(f"        → [inline] {policy}")

        if by_type['ELIGIBLE']:
            print("\n  Eligible (Request Required):")
            for perm_set, paths in sorted(by_type['ELIGIBLE'].items()):
                print(f"    - {perm_set}")
                if detailed:
                    for group, role, assignment_set in paths:
                        print(f"        User '{user_alias}' → Group '{group}' → Role '{role}' → Assignment '{assignment_set}' → Account '{account}'")
                details = model.get_permission_details(perm_set)
                if details:
                    for policy in details.managed_policies:
                        print(f"        → {policy}")
                    for policy in details.inline_policies:
                        print(f"        → [inline] {policy}")
    else:
        # When production_only, filter to only production assignment_set entitlements
        if production_only:
            standing = defaultdict(list)
            eligible = defaultdict(list)
            groups = model.user_to_groups.get(user_alias, [])
            for group in groups:
                for role in model.group_to_roles.get(group, []):
                    for ent in model.role_entitlements.get(role, []):
                        if ent.assignment_set != 'production':
                            continue
                        for acct in ent.accounts:
                            if ent.entitlement_type == 'STANDING':
                                standing[acct].append(ent.permission_set)
                            else:
                                eligible[acct].append(ent.permission_set)
            standing_permissions = dict(standing)
            eligible_permissions = dict(eligible)
        else:
            standing_permissions = perms.standing_permissions
            eligible_permissions = perms.eligible_permissions

        print("Standing Permissions (Always Active):")
        for acct, perms_list in sorted(standing_permissions.items()):
            print(f"\n  {acct}:")
            for perm in set(perms_list):
                print(f"    - {perm}")

        print("\n\nEligible Permissions (Request Required):")
        for acct, perms_list in sorted(eligible_permissions.items()):
            print(f"\n  {acct}:")
            for perm in set(perms_list):
                print(f"    - {perm}")

    return True



def cmd_account(model: EntitlementsModel, account_name: str) -> bool:
    """Audit access for an account.

    Args:
        model: EntitlementsModel instance
        account_name: str name of the account to audit

    Returns:
        bool: True if account has users, False otherwise
    """
    logger.info("Auditing account '%s'", account_name)
    print_header(f"Access Audit for Account: {account_name}")

    users = model.get_users_with_access_to_account(account_name)
    if not users:
        logger.warning("No users found with access to '%s'", account_name)
        print(f"No users found with access to '{account_name}'")
        return False
    logger.info("Found %d user(s) with access to '%s'", len(users), account_name)

    standing_users = []
    eligible_users = []

    for user_alias in users:
        perms = model.get_user_permissions(user_alias)
        user_data = model.users[user_alias]

        if account_name in perms.standing_permissions:
            standing_users.append((user_data['display_name'], user_alias, perms.standing_permissions[account_name]))
        if account_name in perms.eligible_permissions:
            eligible_users.append((user_data['display_name'], user_alias, perms.eligible_permissions[account_name]))

    print(f"Standing Access ({len(standing_users)} users):")
    for name, alias, permissions in standing_users:
        print(f"\n  {name} ({alias})")
        for perm in set(permissions):
            print(f"    - {perm}")

    print(f"\n\nEligible Access ({len(eligible_users)} users):")
    for name, alias, permissions in eligible_users:
        print(f"\n  {name} ({alias})")
        for perm in set(permissions):
            print(f"    - {perm}")

    return True


def cmd_role(model: EntitlementsModel, role_name: str) -> bool:
    """Display details for a role.

    Args:
        model: EntitlementsModel instance
        role_name: str name of the role to query

    Returns:
        bool: True if role found, False otherwise
    """
    logger.info("Querying role '%s'", role_name)
    print_header(f"Role: {role_name}")

    if role_name not in model.role_entitlements:
        logger.warning("Role '%s' not found", role_name)
        print(f"Role '{role_name}' not found")
        return False

    groups = model.get_groups_for_role(role_name)
    print(f"Assigned to groups: {', '.join(groups)}\n")

    by_assignment = defaultdict(lambda: {'standing': [], 'eligible': []})
    for ent in model.role_entitlements[role_name]:
        key = 'standing' if ent.entitlement_type == 'STANDING' else 'eligible'
        by_assignment[ent.assignment_set][key].append(ent)

    for assignment_set, entitlements in sorted(by_assignment.items()):
        print(f"\n{assignment_set.upper()}:")
        if entitlements['standing']:
            print("\n  Standing Permissions:")
            for ent in entitlements['standing']:
                print(f"    {ent.permission_set}")
                print(f"      Accounts: {', '.join(ent.accounts) if ent.accounts else 'None'}")
                print(f"      OUs: {', '.join(ent.org_units) if ent.org_units else 'None'}")
        if entitlements['eligible']:
            print("\n  Eligible Permissions:")
            for ent in entitlements['eligible']:
                print(f"    {ent.permission_set}")
                print(f"      Accounts: {', '.join(ent.accounts) if ent.accounts else 'None'}")
                print(f"      OUs: {', '.join(ent.org_units) if ent.org_units else 'None'}")

    return True


def cmd_permission(model: EntitlementsModel, permission_name: str) -> bool:
    """Display details for a permission set.

    Args:
        model: EntitlementsModel instance
        permission_name: str name of the permission set to query

    Returns:
        bool: True if permission set found, False otherwise
    """
    logger.info("Querying permission set '%s'", permission_name)
    print_header(f"Permission Set: {permission_name}")

    perm = model.get_permission_details(permission_name)
    if not perm:
        logger.warning("Permission set '%s' not found", permission_name)
        print(f"Permission set '{permission_name}' not found in loaded configurations")
        return False

    print(f"Description: {perm.description}\n")

    if perm.managed_policies:
        print("Managed Policies:")
        for policy in perm.managed_policies:
            print(f"  - {policy}")

    if perm.inline_policies:
        print("\nInline Policies:")
        for policy in perm.inline_policies:
            print(f"  - {policy}")

    roles_using = model.get_roles_using_permission(permission_name)
    if roles_using:
        print(f"\n\nUsed by roles: {', '.join(roles_using)}")

    return True


def cmd_export(model: EntitlementsModel, export_filter: str) -> bool:
    """Export entitlements data as JSON based on a filter.

    Args:
        model: EntitlementsModel instance with loaded data
        export_filter: str filter specification (e.g. 'all', 'user=alias', 'roles')

    Returns:
        bool: True on success, False if the requested entity is not found
    """
    logger.info("Exporting with filter '%s'", export_filter)
    data = export_data(model, export_filter)
    if data is None:
        logger.warning("Export returned no data for filter '%s'", export_filter)
        print(f"Export failed: nothing found for filter '{export_filter}'")
        return False
    logger.info("Export successful for filter '%s'", export_filter)
    print(json.dumps(data, indent=2, sort_keys=True, default=str))
    return True


def cmd_list_users(model: EntitlementsModel, production_only: bool = False):
    """List all users grouped by pod.

    Args:
        model: EntitlementsModel instance
        production_only: bool if True, only show users with production assignment access
    """
    if production_only:
        production_users = set()
        for user_alias in model.users:
            groups = model.user_to_groups.get(user_alias, [])
            for group in groups:
                for role in model.group_to_roles.get(group, []):
                    for ent in model.role_entitlements.get(role, []):
                        if ent.assignment_set == 'production' or ent.assignment_set == 'organization':
                            production_users.add(user_alias)
                            break
                    if user_alias in production_users:
                        break
                if user_alias in production_users:
                    break

        print_header(f"Users with Production Access ({len(production_users)})")
        by_pod = defaultdict(list)
        for user_alias in production_users:
            user_data = model.users[user_alias]
            by_pod[user_data['pod']].append((user_data['display_name'], user_alias, user_data['team']))
    else:
        print_header(f"All Users ({len(model.users)})")
        by_pod = defaultdict(list)
        for user_alias, user_data in model.users.items():
            by_pod[user_data['pod']].append((user_data['display_name'], user_alias, user_data['team']))

    for pod, users in sorted(by_pod.items()):
        print(f"\n{pod.upper()}:")
        for name, alias, team in sorted(users):
            print(f"  {name:30} ({alias:20}) - {team}")


def cmd_list_roles(model: EntitlementsModel):
    """List all roles with group counts.

    Args:
        model: EntitlementsModel instance
    """
    print_header(f"All Roles ({len(model.role_entitlements)})")

    for role_name in sorted(model.role_entitlements):
        groups = model.get_groups_for_role(role_name)
        print(f"  {role_name:50} (used by {len(groups)} group(s))")


def interactive_mode(model: EntitlementsModel):
    """Run the interactive query menu.

    Args:
        model: EntitlementsModel instance
    """
    print_header("Entitlements Query Interface - Interactive Mode")

    while True:
        print("\nAvailable queries:")
        print("  1. User permissions (by alias or email)")
        print("  2. Account access audit")
        print("  3. Role details")
        print("  4. Permission set details")
        print("  5. List all users")
        print("  6. List all roles")
        print("  0. Exit")

        choice = input("\nSelect query type (0-6): ").strip()

        if choice == '0':
            break
        elif choice == '1':
            identifier = input("Enter user alias or email: ").strip()
            account = input("Enter account name (or press Enter for all): ").strip()
            cmd_user(model, identifier, account or None)
        elif choice == '2':
            cmd_account(model, input("Enter account name: ").strip())
        elif choice == '3':
            cmd_role(model, input("Enter role name: ").strip())
        elif choice == '4':
            cmd_permission(model, input("Enter permission set name: ").strip())
        elif choice == '5':
            cmd_list_users(model)
        elif choice == '6':
            cmd_list_roles(model)
        else:
            print("Invalid choice")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        argparse.ArgumentParser: configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Query user permissions across AWS accounts"
    )
    parser.add_argument(
        "--base-path", type=str, default=None,
        help="Path to the terraform directory (default: auto-detect)"
    )
    parser.add_argument(
        "--environment", type=str, default="production",
        help="Environment to query (default: production)"
    )

    sub = parser.add_subparsers(dest="command")

    user_p = sub.add_parser("user", help="Query user permissions by alias or email")
    user_p.add_argument("identifier", help="User alias or email address")
    user_p.add_argument("account", nargs="?", default=None, help="Optional account filter")
    user_p.add_argument("--detailed", action="store_true", help="Show access chain trace for account permissions")
    user_p.add_argument("--production-only", action="store_true", help="Only show production assignment permissions")

    account_p = sub.add_parser("account", help="Audit account access")
    account_p.add_argument("name", help="Account name")

    role_p = sub.add_parser("role", help="Show role details")
    role_p.add_argument("name", help="Role name")

    perm_p = sub.add_parser("permission", help="Show permission set details")
    perm_p.add_argument("name", help="Permission set name")

    list_users_p = sub.add_parser("list-users", help="List all users")
    list_users_p.add_argument("--production-only", action="store_true", help="Only show users with production assignment access")
    sub.add_parser("list-roles", help="List all roles")
    sub.add_parser("interactive", help="Interactive mode")

    export_p = sub.add_parser("export", help="Export data as JSON")
    export_p.add_argument(
        "filter",
        help="Filter: all, users, user=<alias>, groups, group=<name>, "
            "roles, role=<name>, permissionsets, permissionset=<name>, "
            "accounts, account=<name>"
    )

    return parser


def _dispatch_command(args: argparse.Namespace, model: EntitlementsModel) -> bool | None:
    """Dispatch CLI command to the appropriate handler.

    Args:
        args: argparse.Namespace parsed CLI arguments
        model: EntitlementsModel instance with loaded data

    Returns:
        bool or None: handler result, or None for commands without a return value
    """
    dispatch = {
        "user": lambda: cmd_user(model, args.identifier, args.account, args.detailed, args.production_only),
        "account": lambda: cmd_account(model, args.name),
        "role": lambda: cmd_role(model, args.name),
        "permission": lambda: cmd_permission(model, args.name),
        "list-users": lambda: cmd_list_users(model, args.production_only),
        "list-roles": lambda: cmd_list_roles(model),
        "interactive": lambda: interactive_mode(model),
        "export": lambda: cmd_export(model, args.filter),
    }
    handler = dispatch.get(args.command)
    if handler:
        return handler()
    return None


def main():
    """Entry point for the entitlements CLI."""
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
        format="# %(levelname)s: %(name)s: %(message)s",
    )

    # In practice disable logging....
    logging.getLogger().setLevel(logging.CRITICAL)

    if args.command is None:
        print(f"\n{RED}ERROR{RESET}: No command specified\n")
        parser.print_help()
        sys.exit(2)

    base_path = args.base_path or os.environ.get("ENTITLEMENTS_BASE_PATH")
    if not base_path:
        logger.error("No base path provided")
        print(f"\n{RED}ERROR{RESET}: No base path provided\n", file=sys.stderr)
        print("Set ENTITLEMENTS_BASE_PATH=... or use --base-path ...\n", file=sys.stderr)
        print("To give path to checked-out repo terraform-aws-identitystore\n", file=sys.stderr)
        parser.print_help()
        sys.exit(3)

    if not Path(base_path).exists():
        logger.error("Base path does not exist: %s", base_path)
        print(f"\n{RED}ERROR{RESET}: Base path does not exist: {base_path}\n", file=sys.stderr)
        parser.print_help()
        sys.exit(3)

    logger.info("Loading entitlements from %s, environment=%s", base_path, args.environment)
    model = EntitlementsModel(base_path, environment=args.environment)
    logger.info("Loaded %d users, %d groups, %d roles, %d permission sets",
                len(model.users), len(model.groups),
                len(model.role_entitlements), len(model.permissions))

    result = _dispatch_command(args, model)

    if result is False:
        sys.exit(5)


if __name__ == "__main__":
    main()

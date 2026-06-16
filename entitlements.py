#!/usr/bin/env python3
"""
Entitlements Query Interface

Queries user permissions across AWS accounts based on the Terraform
Identity Center entitlements configuration.

Usage:
  python entitlements.py                              # Interactive mode
  python entitlements.py user <alias> [account]       # User permissions
  python entitlements.py email <email>                # Lookup by email
  python entitlements.py account <account_name>       # Account access audit
  python entitlements.py role <role_name>             # Role details
  python entitlements.py permission <permission_name> # Permission set details
  python entitlements.py list-users                   # List all users
  python entitlements.py list-roles                   # List all roles
"""

import argparse
import csv
import sys
from collections import defaultdict
from io import StringIO
from pathlib import Path

from entitlements import EntitlementsModel


def print_header(title: str):
    print(f"\n{'='*80}")
    print(title)
    print(f"{'='*80}\n")


def cmd_user(model: EntitlementsModel, user_alias: str, account: str = None):
    perms = model.get_user_permissions(user_alias)
    if not perms:
        print(f"User '{user_alias}' not found")
        return

    user_data = model.users[user_alias]
    print_header(f"User: {user_data['display_name']} ({user_alias})")
    print(f"Email: {user_data['email']}")
    print(f"Pod: {user_data['pod']}")
    print(f"\nGroups: {', '.join(perms.groups)}")
    print(f"Roles: {', '.join(perms.roles)}\n")

    if account:
        print(f"Permissions in account '{account}':\n")
        if account in perms.standing_permissions:
            print("  Standing (Always Active):")
            for perm in perms.standing_permissions[account]:
                print(f"    - {perm}")
                details = model.get_permission_details(perm)
                if details:
                    for policy in details.managed_policies:
                        print(f"        → {policy}")

        if account in perms.eligible_permissions:
            print("\n  Eligible (Request Required):")
            for perm in perms.eligible_permissions[account]:
                print(f"    - {perm}")
                details = model.get_permission_details(perm)
                if details:
                    for policy in details.managed_policies:
                        print(f"        → {policy}")
    else:
        print("Standing Permissions (Always Active):")
        for acct, perms_list in sorted(perms.standing_permissions.items()):
            print(f"\n  {acct}:")
            for perm in perms_list:
                print(f"    - {perm}")

        print("\n\nEligible Permissions (Request Required):")
        for acct, perms_list in sorted(perms.eligible_permissions.items()):
            print(f"\n  {acct}:")
            for perm in perms_list:
                print(f"    - {perm}")


def cmd_email(model: EntitlementsModel, email: str):
    user_alias = model.find_user_by_email(email)
    if not user_alias:
        print(f"No user found with email: {email}")
        return
    cmd_user(model, user_alias)


def cmd_account(model: EntitlementsModel, account_name: str):
    print_header(f"Access Audit for Account: {account_name}")

    users = model.get_users_with_access_to_account(account_name)
    if not users:
        print(f"No users found with access to '{account_name}'")
        return

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
        for perm in permissions:
            print(f"    - {perm}")

    print(f"\n\nEligible Access ({len(eligible_users)} users):")
    for name, alias, permissions in eligible_users:
        print(f"\n  {name} ({alias})")
        for perm in permissions:
            print(f"    - {perm}")


def cmd_role(model: EntitlementsModel, role_name: str):
    print_header(f"Role: {role_name}")

    if role_name not in model.role_entitlements:
        print(f"Role '{role_name}' not found")
        return

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


def cmd_permission(model: EntitlementsModel, permission_name: str):
    print_header(f"Permission Set: {permission_name}")

    perm = model.get_permission_details(permission_name)
    if not perm:
        print(f"Permission set '{permission_name}' not found in loaded configurations")
        return

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


def cmd_list_users(model: EntitlementsModel):
    print_header(f"All Users ({len(model.users)})")

    by_pod = defaultdict(list)
    for user_alias, user_data in model.users.items():
        by_pod[user_data['pod']].append((user_data['display_name'], user_alias, user_data['team']))

    for pod, users in sorted(by_pod.items()):
        print(f"\n{pod.upper()}:")
        for name, alias, team in sorted(users):
            print(f"  {name:30} ({alias:20}) - {team}")


def cmd_list_roles(model: EntitlementsModel):
    print_header(f"All Roles ({len(model.role_entitlements)})")

    for role_name in sorted(model.role_entitlements):
        groups = model.get_groups_for_role(role_name)
        print(f"  {role_name:50} (used by {len(groups)} group(s))")


def interactive_mode(model: EntitlementsModel):
    print_header("Entitlements Query Interface - Interactive Mode")

    while True:
        print("\nAvailable queries:")
        print("  1. User permissions (by alias)")
        print("  2. User permissions (by email)")
        print("  3. Account access audit")
        print("  4. Role details")
        print("  5. Permission set details")
        print("  6. List all users")
        print("  7. List all roles")
        print("  0. Exit")

        choice = input("\nSelect query type (0-7): ").strip()

        if choice == '0':
            break
        elif choice == '1':
            alias = input("Enter user alias: ").strip()
            account = input("Enter account name (or press Enter for all): ").strip()
            cmd_user(model, alias, account or None)
        elif choice == '2':
            cmd_email(model, input("Enter email: ").strip())
        elif choice == '3':
            cmd_account(model, input("Enter account name: ").strip())
        elif choice == '4':
            cmd_role(model, input("Enter role name: ").strip())
        elif choice == '5':
            cmd_permission(model, input("Enter permission set name: ").strip())
        elif choice == '6':
            cmd_list_users(model)
        elif choice == '7':
            cmd_list_roles(model)
        else:
            print("Invalid choice")


def csv_user(model: EntitlementsModel, user_alias: str, account: str = None):
    perms = model.get_user_permissions(user_alias)
    if not perms:
        return
    writer = csv.writer(sys.stdout)
    writer.writerow(["user", "account", "permission_set", "type"])
    for acct, perms_list in perms.standing_permissions.items():
        if account and acct != account:
            continue
        for perm in perms_list:
            writer.writerow([user_alias, acct, perm, "standing"])
    for acct, perms_list in perms.eligible_permissions.items():
        if account and acct != account:
            continue
        for perm in perms_list:
            writer.writerow([user_alias, acct, perm, "eligible"])


def csv_account(model: EntitlementsModel, account_name: str):
    users = model.get_users_with_access_to_account(account_name)
    if not users:
        return
    writer = csv.writer(sys.stdout)
    writer.writerow(["user", "display_name", "account", "permission_set", "type"])
    for user_alias in users:
        perms = model.get_user_permissions(user_alias)
        user_data = model.users[user_alias]
        if account_name in perms.standing_permissions:
            for perm in perms.standing_permissions[account_name]:
                writer.writerow([user_alias, user_data['display_name'], account_name, perm, "standing"])
        if account_name in perms.eligible_permissions:
            for perm in perms.eligible_permissions[account_name]:
                writer.writerow([user_alias, user_data['display_name'], account_name, perm, "eligible"])


def csv_list_users(model: EntitlementsModel):
    writer = csv.writer(sys.stdout)
    writer.writerow(["alias", "display_name", "email", "pod", "team"])
    for user_alias, user_data in sorted(model.users.items()):
        writer.writerow([user_alias, user_data['display_name'], user_data['email'], user_data['pod'], user_data['team']])


def csv_list_roles(model: EntitlementsModel):
    writer = csv.writer(sys.stdout)
    writer.writerow(["role", "groups_count"])
    for role_name in sorted(model.role_entitlements):
        groups = model.get_groups_for_role(role_name)
        writer.writerow([role_name, len(groups)])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Query user permissions across AWS accounts"
    )
    parser.add_argument(
        "--base-path", type=str, default=None,
        help="Path to the terraform directory (default: auto-detect)"
    )
    parser.add_argument(
        "--format", type=str, choices=["text", "csv"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--environment", type=str, default="production",
        help="Environment to query (default: production)"
    )

    sub = parser.add_subparsers(dest="command")

    user_p = sub.add_parser("user", help="Query user permissions by alias")
    user_p.add_argument("alias", help="User alias")
    user_p.add_argument("account", nargs="?", default=None, help="Optional account filter")

    email_p = sub.add_parser("email", help="Query user permissions by email")
    email_p.add_argument("address", help="User email address")

    account_p = sub.add_parser("account", help="Audit account access")
    account_p.add_argument("name", help="Account name")

    role_p = sub.add_parser("role", help="Show role details")
    role_p.add_argument("name", help="Role name")

    perm_p = sub.add_parser("permission", help="Show permission set details")
    perm_p.add_argument("name", help="Permission set name")

    sub.add_parser("list-users", help="List all users")
    sub.add_parser("list-roles", help="List all roles")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    base_path = args.base_path or str(Path(__file__).parent.parent.parent / "terraform")
    model = EntitlementsModel(base_path, environment=args.environment)

    if args.format == "csv":
        if args.command == "user":
            csv_user(model, args.alias, args.account)
        elif args.command == "email":
            user_alias = model.find_user_by_email(args.address)
            if user_alias:
                csv_user(model, user_alias)
        elif args.command == "account":
            csv_account(model, args.name)
        elif args.command == "list-users":
            csv_list_users(model)
        elif args.command == "list-roles":
            csv_list_roles(model)
        else:
            print("CSV format not supported for this query type", file=sys.stderr)
        return

    if args.command is None:
        interactive_mode(model)
    elif args.command == "user":
        cmd_user(model, args.alias, args.account)
    elif args.command == "email":
        cmd_email(model, args.address)
    elif args.command == "account":
        cmd_account(model, args.name)
    elif args.command == "role":
        cmd_role(model, args.name)
    elif args.command == "permission":
        cmd_permission(model, args.name)
    elif args.command == "list-users":
        cmd_list_users(model)
    elif args.command == "list-roles":
        cmd_list_roles(model)


if __name__ == "__main__":
    main()

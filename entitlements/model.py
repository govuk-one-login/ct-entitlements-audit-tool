"""Entitlements data model for AWS Identity Center configuration."""

import csv
import io
import hcl2
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class Permission:
    """Represents a permission set with its policies"""
    name: str
    description: str
    managed_policies: List[str] = field(default_factory=list)
    inline_policies: List[str] = field(default_factory=list)


@dataclass
class Entitlement:
    """Represents an entitlement (permission + accounts)"""
    role: str
    assignment_set: str
    permission_set: str
    accounts: List[str]
    org_units: List[str]
    entitlement_type: str  # 'STANDING' or 'ELIGIBLE'


@dataclass
class UserPermissions:
    """Aggregated permissions for a user"""
    user: str
    groups: List[str]
    roles: List[str]
    standing_permissions: Dict[str, List[str]]  # account -> [permissions]
    eligible_permissions: Dict[str, List[str]]  # account -> [permissions]


class EntitlementsModel:
    """Models the entitlements configuration"""

    def __init__(self, base_path: str, environment: str = "production"):
        self.base_path = Path(base_path)
        self.environment = environment
        self.env_path = self.base_path / "env" / environment / "pods"

        self.users: Dict[str, Dict] = {}
        self.groups: Dict[str, Dict] = {}
        self.user_to_groups: Dict[str, List[str]] = defaultdict(list)
        self.user_to_teams: Dict[str, List[tuple]] = defaultdict(list)  # alias -> [(pod, team)]
        self.group_to_roles: Dict[str, List[str]] = {}
        self.role_entitlements: Dict[str, List[Entitlement]] = defaultdict(list)
        self.permissions: Dict[str, Permission] = {}

        self._load_data()

    def _load_data(self):
        self._load_users()
        self._load_groups()
        self._load_entitlements()
        self._load_permissions()

    def _load_users(self):
        for csv_file in self.env_path.rglob("*.csv"):
            if csv_file.name in ["role.csv", "root_users.csv"]:
                continue

            pod_name = csv_file.parent.name
            team_name = csv_file.stem

            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    user_alias = row['user_alias']
                    if user_alias not in self.users:
                        self.users[user_alias] = {
                            'display_name': row['display_name'],
                            'email': row['email'],
                            'pod': pod_name,
                            'team': team_name
                        }
                    self.user_to_groups[user_alias].append(team_name)
                    self.user_to_teams[user_alias].append((pod_name, team_name))

    def _load_groups(self):
        for groups_file in self.env_path.rglob("groups.yaml"):
            with open(groups_file, 'r') as f:
                groups_data = yaml.safe_load(f)
                for group_name, group_config in groups_data.items():
                    self.groups[group_name] = group_config
                    self.group_to_roles[group_name] = group_config.get('roles', [])
                    for mtype in ['collaborators', 'permanent_members']:
                        for member in group_config.get(mtype, []):
                            self.user_to_groups[member].append(group_name)

    def _load_entitlements(self):
        for entitlements_file in self.env_path.rglob("entitlements*.yaml"):
            with open(entitlements_file, 'r') as f:
                entitlements_data = yaml.safe_load(f)
                for role_name, role_config in entitlements_data.items():
                    for assignment_set, config in role_config.items():
                        if assignment_set == 'emergency_access':
                            continue

                        accounts = config.get('accounts', [])
                        org_units = config.get('org_units', [])

                        for perm in config.get('standing_permissions', []):
                            self.role_entitlements[role_name].append(
                                Entitlement(
                                    role=role_name,
                                    assignment_set=assignment_set,
                                    permission_set=perm,
                                    accounts=accounts,
                                    org_units=org_units,
                                    entitlement_type='STANDING'
                                )
                            )

                        for perm in config.get('eligible_permissions', []):
                            self.role_entitlements[role_name].append(
                                Entitlement(
                                    role=role_name,
                                    assignment_set=assignment_set,
                                    permission_set=perm,
                                    accounts=accounts,
                                    org_units=org_units,
                                    entitlement_type='ELIGIBLE'
                                )
                            )

    def _load_permissions(self):
        permissions_files = [
            self.base_path / "permissions_pod_standing.auto.tfvars",
            self.base_path / "permissions_pod_eligible.auto.tfvars",
            self.base_path / "permissions_special.auto.tfvars",
            self.base_path / "permissions_service_specific.auto.tfvars",
            self.base_path / "permissions_support.auto.tfvars",
        ]

        for perm_file in permissions_files:
            if not perm_file.exists():
                continue
            with open(perm_file, 'r') as f:
                self._parse_permissions_hcl(f.read())

    @staticmethod
    def _strip_hcl_quotes(value: str) -> str:
        """Strip the extra surrounding quotes that hcl2 leaves on string values."""
        s = value.strip()
        if s.startswith('"') and s.endswith('"'):
            s = s[1:-1]
        if s.startswith('<<EOT'):
            s = s[5:].removesuffix('EOT').strip()
        return s

    def _parse_permissions_hcl(self, content: str):
        parsed = hcl2.load(io.StringIO(content))

        for key, value in parsed.items():
            if key.startswith('__') or not isinstance(value, dict):
                continue

            # Determine if this is a permission set directly or a wrapper
            if 'managed_policies' in value or 'description' in value:
                self._store_permission(key, value)
            else:
                for name, config in value.items():
                    if isinstance(config, dict):
                        self._store_permission(name, config)

    def _store_permission(self, name: str, config: dict):
        description = self._strip_hcl_quotes(config.get('description', ''))
        managed_policies = [
            self._strip_hcl_quotes(p)
            for p in config.get('managed_policies', [])
        ]
        inline_policies = [
            self._strip_hcl_quotes(p)
            for p in config.get('inline_policy', [])
        ]
        self.permissions[name] = Permission(
            name=name,
            description=description,
            managed_policies=managed_policies,
            inline_policies=inline_policies
        )

    def get_user_permissions(self, user_alias: str) -> Optional[UserPermissions]:
        if user_alias not in self.users:
            return None

        groups = list(set(self.user_to_groups.get(user_alias, [])))
        roles = []
        for group in groups:
            roles.extend(self.group_to_roles.get(group, []))
        roles = list(set(roles))

        standing = defaultdict(set)
        eligible = defaultdict(set)

        for role in roles:
            for entitlement in self.role_entitlements.get(role, []):
                for account in entitlement.accounts:
                    if entitlement.entitlement_type == 'STANDING':
                        standing[account].add(entitlement.permission_set)
                    else:
                        eligible[account].add(entitlement.permission_set)

        return UserPermissions(
            user=user_alias,
            groups=groups,
            roles=roles,
            standing_permissions={k: sorted(v) for k, v in standing.items()},
            eligible_permissions={k: sorted(v) for k, v in eligible.items()}
        )

    def get_users_with_access_to_account(self, account_name: str) -> List[str]:
        users_with_access = []
        for user_alias in self.users:
            perms = self.get_user_permissions(user_alias)
            if perms and (account_name in perms.standing_permissions or
                         account_name in perms.eligible_permissions):
                users_with_access.append(user_alias)
        return users_with_access

    def get_permission_details(self, permission_name: str) -> Optional[Permission]:
        return self.permissions.get(permission_name)

    def find_user_by_email(self, email: str) -> Optional[str]:
        for user_alias, user_data in self.users.items():
            if user_data['email'].lower() == email.lower():
                return user_alias
        return None

    def get_groups_for_role(self, role_name: str) -> List[str]:
        return [g for g, roles in self.group_to_roles.items() if role_name in roles]

    def get_roles_using_permission(self, permission_name: str) -> List[str]:
        return [
            role for role, ents in self.role_entitlements.items()
            if any(e.permission_set == permission_name for e in ents)
        ]

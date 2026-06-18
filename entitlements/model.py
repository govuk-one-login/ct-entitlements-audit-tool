"""Entitlements data model for AWS Identity Center configuration."""

import csv
import io
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

import hcl2
import yaml

logger = logging.getLogger(__name__)


@dataclass
class Permission:
    """Represents a permission set with its policies."""

    name: str
    description: str
    managed_policies: List[str] = field(default_factory=list)
    inline_policies: List[str] = field(default_factory=list)


@dataclass
class Entitlement:
    """Represents an entitlement (permission + accounts)."""

    role: str
    assignment_set: str
    permission_set: str
    accounts: List[str]
    org_units: List[str]
    entitlement_type: str  # 'STANDING' or 'ELIGIBLE'


@dataclass
class UserPermissions:
    """Aggregated permissions for a user."""

    user: str
    groups: List[str]
    roles: List[str]
    standing_permissions: Dict[str, List[str]]  # account -> [permissions]
    eligible_permissions: Dict[str, List[str]]  # account -> [permissions]


class EntitlementsModel:
    """Models the entitlements configuration."""

    def __init__(self, base_path: str, environment: str = "production"):
        """Initialize the entitlements model and load data.

        Args:
            base_path: str path to the terraform directory
            environment: str environment name (default: production)
        """
        self.base_path = Path(base_path)
        self.environment = environment
        self.env_path = self.base_path / "env" / environment / "pods"

        self.users: Dict[str, Dict] = {}
        self.groups: Dict[str, Dict] = {}
        self.user_to_groups: Dict[str, List[str]] = defaultdict(list)
        self.group_to_roles: Dict[str, List[str]] = {}
        self.role_entitlements: Dict[str, List[Entitlement]] = defaultdict(list)
        self.permissions: Dict[str, Permission] = {}
        self.email_to_alias: Dict[str, str] = {}
        self.account_to_users: Dict[str, List[str]] = defaultdict(list)

        self._load_data()

    def _load_data(self):
        """Load all entitlements data from disk."""
        logger.info("Loading data from %s", self.env_path)
        self._load_users()
        self._load_groups()
        self._load_entitlements()
        self._load_permissions()
        self._build_account_index()
        logger.info("Data loading complete")

    def _build_account_index(self):
        """Build an inverted index from account name to user aliases with access."""
        for user_alias in self.users:
            perms = self.get_user_permissions(user_alias)
            if not perms:
                continue
            for account in perms.standing_permissions:
                self.account_to_users[account].append(user_alias)
            for account in perms.eligible_permissions:
                if user_alias not in self.account_to_users[account]:
                    self.account_to_users[account].append(user_alias)

    @staticmethod
    def _read_file(file_path: Path) -> str:
        """Read and return the text content of a file.

        Args:
            file_path: Path to the file to read

        Returns:
            str: the file content as a string
        """
        with open(file_path, 'r') as file_handle:
            return file_handle.read()

    def _load_users(self):
        """Load users from CSV files in the pods directory."""
        user_count = 0
        for csv_file in self.env_path.rglob("*.csv"):
            if csv_file.name in ["role.csv", "root_users.csv"]:
                continue

            pod_name = csv_file.parent.name
            team_name = csv_file.stem
            logger.debug("Loading users from %s", csv_file)

            content = self._read_file(csv_file)
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                user_alias = row['user_alias']
                self.users[user_alias] = {
                    'display_name': row['display_name'],
                    'email': row['email'],
                    'pod': pod_name,
                    'team': team_name
                }
                self.user_to_groups[user_alias].append(team_name)
                self.email_to_alias[row['email'].lower()] = user_alias
                user_count += 1

        logger.info("Loaded %d users", user_count)

    def _load_groups(self):
        """Load groups from groups.yaml files."""
        for groups_file in self.env_path.rglob("groups.yaml"):
            with open(groups_file, 'r') as f:
                groups_data = yaml.safe_load(f)
                for group_name, group_config in groups_data.items():
                    self.groups[group_name] = group_config
                    self.group_to_roles[group_name] = group_config.get('roles', [])
                    member_types = ['collaborators', 'permanent_members']
                    extra_members = []
                    for mtype in member_types:
                        for member in group_config.get(mtype, []):
                            extra_members.append(member)
                    for extra_member in extra_members:
                        self.user_to_groups[extra_member].append(group_name)

    def _load_entitlements(self):
        """Load entitlements from entitlements YAML files."""
        entitlement_count = 0
        for entitlements_file in self.env_path.rglob("entitlements*.yaml"):
            logger.debug("Loading entitlements from %s", entitlements_file)
            content = self._read_file(entitlements_file)
            entitlements_data = yaml.safe_load(content)
            for role_name, role_config in entitlements_data.items():
                for assignment_set, config in role_config.items():
                    if assignment_set == 'emergency_access':
                        continue

                    accounts = config.get('accounts', [])
                    org_units = config.get('org_units', [])

                    for entitlement_type in ('STANDING', 'ELIGIBLE'):
                        key = f"{entitlement_type.lower()}_permissions"
                        for perm in config.get(key, []):
                            self._add_entitlement(
                                role_name, assignment_set, perm,
                                accounts, org_units, entitlement_type
                            )
                            entitlement_count += 1

        logger.info("Loaded %d entitlements across %d roles",
                    entitlement_count, len(self.role_entitlements))

    def _add_entitlement(self, role_name: str, assignment_set: str,
                         permission_set: str, accounts: List[str],
                         org_units: List[str], entitlement_type: str):
        """Create and store an Entitlement object.

        Args:
            role_name: str name of the role
            assignment_set: str name of the assignment set
            permission_set: str name of the permission set
            accounts: List[str] list of account names
            org_units: List[str] list of org unit names
            entitlement_type: str 'STANDING' or 'ELIGIBLE'
        """
        self.role_entitlements[role_name].append(
            Entitlement(
                role=role_name,
                assignment_set=assignment_set,
                permission_set=permission_set,
                accounts=accounts,
                org_units=org_units,
                entitlement_type=entitlement_type
            )
        )

    def _load_permissions(self):
        """Load permission sets from HCL tfvars files."""
        permissions_files = [
            self.base_path / "permissions_pod_standing.auto.tfvars",
            self.base_path / "permissions_pod_eligible.auto.tfvars",
            self.base_path / "permissions_special.auto.tfvars",
            self.base_path / "permissions_service_specific.auto.tfvars",
            self.base_path / "permissions_support.auto.tfvars",
        ]

        for perm_file in permissions_files:
            if not perm_file.exists():
                logger.debug("Permission file not found, skipping: %s", perm_file)
                continue
            logger.debug("Loading permissions from %s", perm_file)
            content = self._read_file(perm_file)
            self._parse_permissions_hcl(content)

        logger.info("Loaded %d permission sets", len(self.permissions))

    @staticmethod
    def _strip_hcl_quotes(value: str) -> str:
        """Strip the extra surrounding quotes that hcl2 leaves on string values.

        Args:
            value: str raw HCL string value

        Returns:
            str: cleaned string value
        """
        stripped = value.strip()
        if stripped.startswith('"') and stripped.endswith('"'):
            stripped = stripped[1:-1]
        if stripped.startswith('<<EOT'):
            stripped = stripped[5:].removesuffix('EOT').strip()
        return stripped

    def _parse_permissions_hcl(self, content: str):
        """Parse HCL content and extract permission sets.

        Args:
            content: str raw HCL file content
        """
        parsed = hcl2.load(io.StringIO(content))

        for key, value in parsed.items():
            if key.startswith('__') or not isinstance(value, dict):
                continue

            if 'managed_policies' in value or 'description' in value:
                self._store_permission(key, value)
            else:
                for name, config in value.items():
                    if isinstance(config, dict):
                        self._store_permission(name, config)

    def _store_permission(self, name: str, config: dict):
        """Store a parsed permission set.

        Args:
            name: str permission set name
            config: dict permission set configuration
        """
        description = self._strip_hcl_quotes(config.get('description', ''))
        managed_policies = [
            self._strip_hcl_quotes(policy)
            for policy in config.get('managed_policies', [])
        ]
        inline_policies = [
            self._strip_hcl_quotes(policy)
            for policy in config.get('inline_policy', [])
        ]
        self.permissions[name] = Permission(
            name=name,
            description=description,
            managed_policies=managed_policies,
            inline_policies=inline_policies
        )
        logger.debug("Stored permission set '%s'", name)

    @lru_cache(maxsize=None)
    def get_user_permissions(self, user_alias: str) -> Optional[UserPermissions]:
        """Get aggregated permissions for a user (cached).

        Args:
            user_alias: str alias of the user

        Returns:
            UserPermissions: aggregated permissions, or None if user not found
        """
        if user_alias not in self.users:
            logger.debug("User '%s' not in users dict", user_alias)
            return None

        groups = self.user_to_groups.get(user_alias, [])
        roles = []
        for group in groups:
            roles.extend(self.group_to_roles.get(group, []))

        standing = defaultdict(list)
        eligible = defaultdict(list)

        for role in roles:
            for entitlement in self.role_entitlements.get(role, []):
                for account in entitlement.accounts:
                    if entitlement.entitlement_type == 'STANDING':
                        standing[account].append(entitlement.permission_set)
                    else:
                        eligible[account].append(entitlement.permission_set)

        return UserPermissions(
            user=user_alias,
            groups=groups,
            roles=list(set(roles)),
            standing_permissions=dict(standing),
            eligible_permissions=dict(eligible)
        )

    def get_users_with_access_to_account(self, account_name: str) -> List[str]:
        """Find all users with access to a given account using prebuilt index.

        Args:
            account_name: str name of the account

        Returns:
            List[str]: list of user aliases with access
        """
        users = self.account_to_users.get(account_name, [])
        logger.debug("Found %d users with access to '%s'", len(users), account_name)
        return users

    def get_permission_details(self, permission_name: str) -> Optional[Permission]:
        """Get details for a permission set.

        Args:
            permission_name: str name of the permission set

        Returns:
            Permission: permission set details, or None if not found
        """
        return self.permissions.get(permission_name)

    def find_user_by_email(self, email: str) -> Optional[str]:
        """Find a user alias by email address using prebuilt index.

        Args:
            email: str email address to search for

        Returns:
            str: user alias, or None if not found
        """
        return self.email_to_alias.get(email.lower())

    def get_groups_for_role(self, role_name: str) -> List[str]:
        """Find all groups that include a given role.

        Args:
            role_name: str name of the role

        Returns:
            List[str]: list of group names
        """
        return [group for group, roles in self.group_to_roles.items() if role_name in roles]

    def get_roles_using_permission(self, permission_name: str) -> List[str]:
        """Find all roles that use a given permission set.

        Args:
            permission_name: str name of the permission set to search for

        Returns:
            List[str]: list of role names that include this permission set
        """
        return [
            role for role, ents in self.role_entitlements.items()
            if any(ent.permission_set == permission_name for ent in ents)
        ]

    def get_all_accounts(self) -> List[str]:
        """Get all unique account names that appear in entitlements.

        Returns:
            List[str]: sorted list of all unique account names
        """
        return sorted(self.account_to_users.keys())

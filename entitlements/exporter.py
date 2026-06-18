"""Export entitlements data as JSON based on filter specifications."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any, Optional

from .model import EntitlementsModel

logger = logging.getLogger(__name__)


def _sort_value(value: Any) -> Any:
    """Recursively sort lists and dict keys in an export data structure.

    Args:
        value: Any value to sort (dict, list, or primitive)

    Returns:
        Any: the value with all dicts sorted by key and all lists sorted
    """
    if isinstance(value, dict):
        return {key: _sort_value(val) for key, val in sorted(value.items())}
    if isinstance(value, list):
        sorted_items = [_sort_value(item) for item in value]
        try:
            return sorted(
                sorted_items,
                key=lambda item: json.dumps(item, sort_keys=True, default=str),
            )
        except TypeError:
            return sorted_items
    return value


def export_data(model: EntitlementsModel, export_filter: str) -> Optional[dict | list]:
    """Build export data based on the given filter string.

    Args:
        model: EntitlementsModel instance with loaded data
        export_filter: str filter specification such as 'all', 'user=alias',
            'users', 'group=name', 'groups', 'role=name', 'roles',
            'permissionset=name', 'permissionsets', 'account=name', 'accounts'

    Returns:
        dict or list: exported data structure, or None if entity not found
    """
    logger.info("Processing export filter: '%s'", export_filter)

    handlers = {
        "all": lambda: _export_all(model),
        "users": lambda: _export_all_users(model),
        "groups": lambda: _export_all_groups(model),
        "roles": lambda: _export_all_roles(model),
        "permissionsets": lambda: _export_all_permissionsets(model),
        "accounts": lambda: _export_all_accounts(model),
    }

    if export_filter in handlers:
        result = _sort_value(handlers[export_filter]())
        logger.info("Export complete for filter '%s'", export_filter)
        return result

    prefix_handlers = {
        "user=": lambda value: _export_user(model, value),
        "group=": lambda value: _export_group(model, value),
        "role=": lambda value: _export_role(model, value),
        "permissionset=": lambda value: _export_permissionset(model, value),
        "account=": lambda value: _export_account(model, value),
    }

    for prefix, handler in prefix_handlers.items():
        if export_filter.startswith(prefix):
            entity_name = export_filter[len(prefix) :]
            logger.info("Exporting %s'%s'", prefix, entity_name)
            result = handler(entity_name)
            if result is None:
                logger.warning("No data found for %s'%s'", prefix, entity_name)
                return None
            return _sort_value(result)

    logger.warning("Unknown export filter: '%s'", export_filter)
    return None


def _export_all(model: EntitlementsModel) -> dict:
    """Export all entitlements data.

    Args:
        model: EntitlementsModel instance with loaded data

    Returns:
        dict: complete export of users, groups, roles, permission sets, accounts
    """
    logger.info("Exporting all data")
    return {
        "users": _export_all_users(model),
        "groups": _export_all_groups(model),
        "roles": _export_all_roles(model),
        "permission_sets": _export_all_permissionsets(model),
        "accounts": _export_all_accounts(model),
    }


def _export_user(model: EntitlementsModel, alias: str) -> Optional[dict]:
    """Export a single user's entitlements data.

    Args:
        model: EntitlementsModel instance with loaded data
        alias: str user alias to export

    Returns:
        dict: user data with permissions, or None if not found
    """
    perms = model.get_user_permissions(alias)
    if not perms:
        logger.debug("User '%s' not found for export", alias)
        return None
    user_data = model.users[alias]
    return {
        "alias": alias,
        "display_name": user_data["display_name"],
        "email": user_data["email"],
        "pod": user_data["pod"],
        "team": user_data["team"],
        "groups": perms.groups,
        "roles": perms.roles,
        "standing_permissions": perms.standing_permissions,
        "eligible_permissions": perms.eligible_permissions,
    }


def _export_all_users(model: EntitlementsModel) -> list:
    """Export all users' entitlements data.

    Args:
        model: EntitlementsModel instance with loaded data

    Returns:
        list: list of user export dicts
    """
    logger.debug("Exporting %d users", len(model.users))
    return [_export_user(model, alias) for alias in model.users]


def _export_group(model: EntitlementsModel, group_name: str) -> Optional[dict]:
    """Export a single group's data.

    Args:
        model: EntitlementsModel instance with loaded data
        group_name: str name of the group to export

    Returns:
        dict: group data with roles and members, or None if not found
    """
    if group_name not in model.groups:
        logger.debug("Group '%s' not found for export", group_name)
        return None
    config = model.groups[group_name]
    return {
        "name": group_name,
        "roles": model.group_to_roles.get(group_name, []),
        "collaborators": config.get("collaborators", []),
        "members": [
            user
            for user, groups in model.user_to_groups.items()
            if group_name in groups
        ],
    }


def _export_all_groups(model: EntitlementsModel) -> list:
    """Export all groups' data.

    Args:
        model: EntitlementsModel instance with loaded data

    Returns:
        list: list of group export dicts
    """
    logger.debug("Exporting %d groups", len(model.groups))
    return [_export_group(model, name) for name in model.groups]


def _export_role(model: EntitlementsModel, role_name: str) -> Optional[dict]:
    """Export a single role's data.

    Args:
        model: EntitlementsModel instance with loaded data
        role_name: str name of the role to export

    Returns:
        dict: role data with entitlements, or None if not found
    """
    if role_name not in model.role_entitlements:
        logger.debug("Role '%s' not found for export", role_name)
        return None
    return {
        "name": role_name,
        "groups": model.get_groups_for_role(role_name),
        "entitlements": [asdict(ent) for ent in model.role_entitlements[role_name]],
    }


def _export_all_roles(model: EntitlementsModel) -> list:
    """Export all roles' data.

    Args:
        model: EntitlementsModel instance with loaded data

    Returns:
        list: list of role export dicts
    """
    logger.debug("Exporting %d roles", len(model.role_entitlements))
    return [_export_role(model, name) for name in model.role_entitlements]


def _export_permissionset(model: EntitlementsModel, perm_name: str) -> Optional[dict]:
    """Export a single permission set's data.

    Args:
        model: EntitlementsModel instance with loaded data
        perm_name: str name of the permission set to export

    Returns:
        dict: permission set data with policies, or None if not found
    """
    perm = model.get_permission_details(perm_name)
    if not perm:
        logger.debug("Permission set '%s' not found for export", perm_name)
        return None
    return {
        "name": perm.name,
        "description": perm.description,
        "managed_policies": perm.managed_policies,
        "inline_policies": perm.inline_policies,
        "used_by_roles": model.get_roles_using_permission(perm_name),
    }


def _export_all_permissionsets(model: EntitlementsModel) -> list:
    """Export all permission sets' data.

    Args:
        model: EntitlementsModel instance with loaded data

    Returns:
        list: list of permission set export dicts
    """
    logger.debug("Exporting %d permission sets", len(model.permissions))
    return [_export_permissionset(model, name) for name in model.permissions]


def _export_account(model: EntitlementsModel, account_name: str) -> Optional[dict]:
    """Export access data for a single account.

    Args:
        model: EntitlementsModel instance with loaded data
        account_name: str name of the account to export

    Returns:
        dict: account access data with standing/eligible users, or None if no access
    """
    users = model.get_users_with_access_to_account(account_name)
    if not users:
        logger.debug("No users with access to account '%s'", account_name)
        return None
    standing = []
    eligible = []
    for alias in users:
        perms = model.get_user_permissions(alias)
        if account_name in perms.standing_permissions:
            standing.append(
                {
                    "user": alias,
                    "permissions": perms.standing_permissions[account_name],
                }
            )
        if account_name in perms.eligible_permissions:
            eligible.append(
                {
                    "user": alias,
                    "permissions": perms.eligible_permissions[account_name],
                }
            )
    logger.debug(
        "Account '%s': %d standing, %d eligible users",
        account_name,
        len(standing),
        len(eligible),
    )
    return {
        "account": account_name,
        "standing_access": standing,
        "eligible_access": eligible,
    }


def _export_all_accounts(model: EntitlementsModel) -> list:
    """Export access data for all accounts in entitlements.

    Args:
        model: EntitlementsModel instance with loaded data

    Returns:
        list: list of account export dicts
    """
    all_accounts = model.get_all_accounts()
    logger.debug("Exporting %d accounts", len(all_accounts))
    return [_export_account(model, name) for name in all_accounts]

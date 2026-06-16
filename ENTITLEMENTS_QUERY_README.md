# Entitlements Query Interface

A Python-based query interface for analyzing user permissions across AWS accounts based on the Terraform Identity Center entitlements configuration.

## Overview

This tool models the entitlements system which consists of:

1. **Users** - Defined in team CSV files under `terraform/env/{environment}/pods/{pod}/{team}.csv`
2. **Groups** - Defined in `groups.yaml` files, mapping teams to roles
3. **Roles** - Defined in `entitlements.yaml` files, mapping roles to accounts and permissions
4. **Permission Sets** - Defined in `permissions_*.auto.tfvars` files, containing IAM policies
5. **Accounts** - AWS accounts organized by OUs

## Architecture

```
User (CSV) → Group (groups.yaml) → Role (entitlements.yaml) → Permission Set (tfvars) → IAM Policies
                                         ↓
                                    AWS Accounts
```

### Key Concepts

- **Standing Permissions**: Always active, permanent access
- **Eligible Permissions**: Require approval/request, temporary elevated access
- **Assignment Sets**: Environment groupings (e.g., `sensitive`, `non_sensitive`, `production`)
- **Pods**: Organizational units grouping related teams (e.g., `security`, `platform-and-sre`)

## Installation

```bash
# Install dependencies
pip install pyyaml

# Make scripts executable
chmod +x entitlements_query.py entitlements_interactive.py
```

## Usage

### 1. Basic Query (Single User)

```bash
# Query all permissions for a user
python entitlements_query.py rorysedgwick

# Query user permissions in a specific account
python entitlements_query.py rorysedgwick ct-security-tooling
```

### 2. Interactive Mode

```bash
python entitlements_interactive.py
```

This launches an interactive menu with options:
1. User permissions (by alias)
2. User permissions (by email)
3. Account access audit
4. Role details
5. Permission set details
6. List all users
7. List all roles

### 3. Command Line Queries

```bash
# Query by user alias
python entitlements_interactive.py user rorysedgwick

# Query by email
python entitlements_interactive.py email rory.sedgwick@digital.cabinet-office.gov.uk

# Audit account access
python entitlements_interactive.py account ct-security-tooling

# View role details
python entitlements_interactive.py role security-operations-engineer

# View permission set details
python entitlements_interactive.py permission AdministratorAccessPermission

# List all users
python entitlements_interactive.py list-users

# List all roles
python entitlements_interactive.py list-roles
```

## Query Examples

### Example 1: What permissions does a user have?

```bash
$ python entitlements_query.py rorysedgwick

================================================================================
User: Rory Sedgwick (rorysedgwick)
Email: rory.sedgwick@digital.cabinet-office.gov.uk
Pod: security
================================================================================

Groups: security/security-operations-engineering
Roles: security-operations-engineer, security-auditing

Standing Permissions (Always Active):

  ct-security-tooling-sandbox:
    - AdministratorAccessPermission
    - ReadOnlyAccessPermission

  ct-security-tooling:
    - ViewOnlyAccessPermission

Eligible Permissions (Request Required):

  ct-security-tooling:
    - ApprovedAdmin
    - ApprovedPowerUser
```

### Example 2: Who has access to an account?

```bash
$ python entitlements_interactive.py account ct-security-tooling

================================================================================
Access Audit for Account: ct-security-tooling
================================================================================

Standing Access (9 users):

  Rory Sedgwick (rorysedgwick)
    - ViewOnlyAccessPermission

  James Woodland (jameswoodland)
    - ViewOnlyAccessPermission

Eligible Access (9 users):

  Rory Sedgwick (rorysedgwick)
    - ApprovedAdmin
    - ApprovedPowerUser
```

### Example 3: What does a role provide?

```bash
$ python entitlements_interactive.py role security-operations-engineer

================================================================================
Role: security-operations-engineer
================================================================================

Assigned to groups: security/security-operations-engineering

NON_SENSITIVE:
  Standing Permissions:
    AdministratorAccessPermission
      Accounts: ct-security-tooling-sandbox, di-secops-dev
      OUs: None

SENSITIVE:
  Standing Permissions:
    ViewOnlyAccessPermission
      Accounts: ct-security-tooling
      OUs: None

  Eligible Permissions:
    ApprovedAdmin
      Accounts: ct-security-tooling
      OUs: None
```

## Data Model

### EntitlementsModel Class

Main class that loads and models the configuration:

```python
from entitlements_query import EntitlementsModel

model = EntitlementsModel("path/to/terraform", environment="production")

# Get user permissions
perms = model.get_user_permissions("rorysedgwick")

# Get users with access to account
users = model.get_users_with_access_to_account("ct-security-tooling")

# Get permission details
perm_details = model.get_permission_details("AdministratorAccessPermission")
```

### Key Methods

- `get_user_permissions(user_alias)` - Returns UserPermissions object
- `get_users_with_access_to_account(account_name)` - Returns list of user aliases
- `get_permission_details(permission_name)` - Returns Permission object
- `query_user_access(user_alias, account_name)` - Prints formatted output

## Use Cases

### Security Auditing
- Identify who has admin access to production accounts
- Review standing vs eligible permissions
- Audit access to sensitive accounts

### Access Reviews
- Generate reports of user permissions
- Verify least privilege principles
- Identify over-privileged users

### Onboarding/Offboarding
- Verify new user has correct permissions
- Confirm removed user has no remaining access

### Troubleshooting
- Debug why a user can't access an account
- Verify role assignments
- Check permission set configurations

## Extending the Interface

### Adding Custom Queries

```python
from entitlements_query import EntitlementsModel

model = EntitlementsModel("path/to/terraform")

# Custom query: Find all users with admin access
for user_alias in model.users.keys():
    perms = model.get_user_permissions(user_alias)
    for account, perm_list in perms.standing_permissions.items():
        if "AdministratorAccessPermission" in perm_list:
            print(f"{user_alias} has admin on {account}")
```

### Exporting to JSON

```python
import json

perms = model.get_user_permissions("rorysedgwick")
output = {
    "user": perms.user,
    "groups": perms.groups,
    "roles": perms.roles,
    "standing": perms.standing_permissions,
    "eligible": perms.eligible_permissions
}

print(json.dumps(output, indent=2))
```

## Limitations

1. **HCL Parsing**: Uses simplified regex-based parsing for `.tfvars` files. For production use, consider using `python-hcl2` library.

2. **OU Resolution**: Currently stores OU paths but doesn't resolve them to actual accounts. Would need AWS Organizations API integration.

3. **Static Analysis**: Reads configuration files only, doesn't query actual AWS Identity Center state.

4. **Shared Roles**: Handles shared roles defined in `entitlements-shared.yaml` but may need additional testing.

## Future Enhancements

- [ ] Integrate with AWS Organizations API to resolve OUs to accounts
- [ ] Query actual AWS Identity Center assignments for comparison
- [ ] Generate compliance reports (CSV, PDF)
- [ ] Web UI for easier querying
- [ ] Diff mode to compare changes between commits
- [ ] Integration with approval workflows
- [ ] Export to visualization tools (Graphviz, etc.)

## Contributing

When modifying the entitlements configuration:

1. Run queries to verify expected access
2. Test with both standing and eligible permissions
3. Verify OU-based assignments resolve correctly
4. Check for unintended access grants

## Support

For issues or questions about the entitlements model, contact:
- Platform Team
- Security Team

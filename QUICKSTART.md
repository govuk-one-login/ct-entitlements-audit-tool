# Entitlements Query Interface - Quick Start

## What This Does

Query interface to answer questions like:
- "What AWS accounts can user X access?"
- "What permissions does user Y have in account Z?"
- "Who has admin access to production accounts?"
- "What IAM policies are granted through permission set P?"

## Files Created

1. **entitlements_query.py** - Core data model and basic queries
2. **entitlements_interactive.py** - Interactive CLI and advanced queries
3. **entitlements_export.py** - JSON export for integrations
4. **entitlements_examples.py** - Example usage and demonstrations
5. **ENTITLEMENTS_QUERY_README.md** - Full documentation
6. **requirements-entitlements.txt** - Python dependencies

## Quick Start

```bash
# Install dependencies
pip install -r requirements-entitlements.txt

# Run interactive mode
python entitlements_interactive.py

# Or query directly
python entitlements_query.py <user_alias>
python entitlements_query.py <user_alias> <account_name>
```

## Common Queries

### 1. User Permissions
```bash
# What can this user access?
python entitlements_query.py rorysedgwick

# What can this user do in this account?
python entitlements_query.py rorysedgwick ct-security-tooling
```

### 2. Account Audit
```bash
# Who has access to this account?
python entitlements_interactive.py account ct-security-tooling
```

### 3. Role Analysis
```bash
# What does this role provide?
python entitlements_interactive.py role security-operations-engineer
```

### 4. Export for Reporting
```bash
# Export user permissions as JSON
python entitlements_export.py user rorysedgwick > user_perms.json

# Export full access matrix
python entitlements_export.py matrix > access_matrix.json

# Export account access audit
python entitlements_export.py account ct-security-tooling > account_audit.json
```

### 5. Tests
```bash
# Run unit test suite
python -m pytest tests -vvv
```

## Data Flow

```
CSV Files (users)
    ↓
groups.yaml (team → roles mapping)
    ↓
entitlements.yaml (roles → accounts + permissions)
    ↓
permissions_*.tfvars (permission sets → IAM policies)
    ↓
Query Results
```

## Key Concepts

### Standing vs Eligible Permissions

- **Standing**: Always active, permanent access
  - Example: ViewOnlyAccess in production accounts

- **Eligible**: Requires approval, temporary elevated access
  - Example: AdministratorAccess in production (request required)

### Assignment Sets

Roles define permissions in different contexts:
- `non_sensitive` - Dev/sandbox accounts
- `sensitive` - Production accounts
- `production` - Prod-specific access
- `non-production` - Non-prod specific access

### Permission Sets

Map to AWS IAM policies:
- `AdministratorAccessPermission` → `arn:aws:iam::aws:policy/AdministratorAccess`
- `ReadOnlyAccessPermission` → `arn:aws:iam::aws:policy/ReadOnlyAccess`
- `ViewOnlyAccessPermission` → `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

## Example Output

```
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
        → arn:aws:iam::aws:policy/AdministratorAccess
    - ReadOnlyAccessPermission
        → arn:aws:iam::aws:policy/ReadOnlyAccess

  ct-security-tooling:
    - ViewOnlyAccessPermission
        → arn:aws:iam::aws:policy/job-function/ViewOnlyAccess

Eligible Permissions (Request Required):

  ct-security-tooling:
    - ApprovedAdmin
    - ApprovedPowerUser
```

## Use Cases

### Security Auditing
```bash
# Find all users with admin access
python entitlements_examples.py  # See Example 5

# Audit specific account
python entitlements_interactive.py account <production-account>
```

### Access Reviews
```bash
# Review user's access
python entitlements_query.py <user_alias>

# Export for spreadsheet
python entitlements_export.py all-users > users_review.json
```

### Troubleshooting
```bash
# Why can't user X access account Y?
python entitlements_query.py <user_alias> <account_name>

# What roles provide access to account Y?
python entitlements_interactive.py account <account_name>
```

### Compliance Reporting
```bash
# Generate access matrix
python entitlements_export.py matrix > compliance_report.json

# Export full model for analysis
python entitlements_export.py full > full_model.json
```

## Integration Examples

### Python Script
```python
from entitlements_query import EntitlementsModel

model = EntitlementsModel("fog/terraform-aws-identitystore/terraform")
perms = model.get_user_permissions("rorysedgwick")

for account, perm_list in perms.standing_permissions.items():
    print(f"{account}: {', '.join(perm_list)}")
```

### Shell Script
```bash
#!/bin/bash
# Audit all production accounts

for account in $(cat production_accounts.txt); do
    echo "Auditing $account..."
    python entitlements_export.py account "$account" > "audit_${account}.json"
done
```

### CI/CD Pipeline
```yaml
# Example GitHub Action
- name: Audit Entitlements Changes
  run: |
    python entitlements_export.py matrix > before.json
    # Apply terraform changes
    python entitlements_export.py matrix > after.json
    diff before.json after.json
```

## Limitations

1. **Static Analysis Only**: Reads Terraform config, doesn't query AWS
2. **OU Resolution**: Stores OU paths but doesn't expand to accounts
3. **Simplified HCL Parsing**: May need `python-hcl2` for complex configs
4. **No State Tracking**: Doesn't track actual AWS Identity Center state

## Next Steps

1. Read full documentation: `ENTITLEMENTS_QUERY_README.md`
2. Run examples: `python entitlements_examples.py`
3. Try interactive mode: `python entitlements_interactive.py`
4. Integrate into your workflows

## Support

For questions about:
- **The tool**: See `ENTITLEMENTS_QUERY_README.md`
- **Entitlements model**: Contact Platform/Security teams
- **Access requests**: Use your organization's approval process

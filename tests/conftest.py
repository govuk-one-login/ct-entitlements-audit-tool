
import pytest
import yaml


ALPHA_TEAM_CSV = """\
user_alias,display_name,email,family_name,given_name
alice,Alice Smith,alice@example.com,Smith,Alice
bob,Bob Jones,bob@example.com,Jones,Bob
"""

BETA_TEAM_CSV = """\
user_alias,display_name,email,family_name,given_name
nopr,No Prod,nopr@example.com,Prod,No
"""

ROLE_CSV = """\
user_alias,display_name,email,family_name,given_name
ignored,Ignored User,ignored@example.com,User,Ignored
"""

ALPHA_GROUPS_YAML = """\
---
################################################################################
# Alpha Pod Groups
################################################################################
alpha-team-one:
  description: Alpha Team One
  roles:
    - team-one-engineers
    - team-two-engineers
  collaborators:
    - charlie

alpha-team-two:
  description: Alpha Team Two
  roles:
    - team-two-engineers
  permanent_members:
    - danielle
"""

BETA_GROUPS_YAML = """\
---
beta-team-one:
  description: Beta Team
  roles:
    - dev-only-engineers
"""

ALPHA_ENTITLEMENTS_YAML = """\
---
################################################################################
# Alpha Pod Entitlements
################################################################################

team-one-engineers:
  development:
    accounts:
      - dev-account-a
      - dev-account-b
    org_units:
      - dev-ou
    standing_permissions:
      - Admin

  non-production:
    accounts:
      - staging-account
    org_units:
      - staging-ou
    standing_permissions:
      - ReadOnly
    eligible_permissions:
      - Admin

  production:
    accounts:
      - prod-account-a
    org_units:
      - production-ou
    standing_permissions:
      - ViewOnly
    eligible_permissions:
      - PowerUser

  emergency_access:
    accounts:
      - prod-account-a
    standing_permissions:
      - EmergencyAdmin

team-two-engineers:
  production:
    accounts:
      - prod-account-b
    org_units: []
    standing_permissions:
      - ViewOnly
    eligible_permissions:
      - ReadOnly
"""

BETA_ENTITLEMENTS_YAML = """\
---
dev-only-engineers:
  development:
    accounts:
      - dev-only-account
    standing_permissions:
      - Admin
"""

PERMISSIONS_TFVARS = """\
ViewOnly = {
  description = "View only access"
  managed_policies = ["arn:aws:iam::aws:policy/ViewOnlyAccess"]
}

PowerUser = {
  description = "Power user access"
  managed_policies = ["arn:aws:iam::aws:policy/PowerUserAccess", "arn:aws:iam::aws:policy/IAMReadOnlyAccess"]
}
"""


@pytest.fixture
def base_path(tmp_path):
    """Create a minimal file structure mimicking the terraform layout."""
    alpha_pod = tmp_path / "env" / "production" / "pods" / "alpha"
    alpha_pod.mkdir(parents=True)

    (alpha_pod / "alpha-team-one.csv").write_text(ALPHA_TEAM_CSV)
    (alpha_pod / "role.csv").write_text(ROLE_CSV)
    (alpha_pod / "groups.yaml").write_text(ALPHA_GROUPS_YAML)
    (alpha_pod / "entitlements.yaml").write_text(ALPHA_ENTITLEMENTS_YAML)

    beta_pod = tmp_path / "env" / "production" / "pods" / "beta"
    beta_pod.mkdir(parents=True)
    (beta_pod / "beta-team-one.csv").write_text(BETA_TEAM_CSV)
    (beta_pod / "groups.yaml").write_text(BETA_GROUPS_YAML)
    (beta_pod / "entitlements.yaml").write_text(BETA_ENTITLEMENTS_YAML)

    (tmp_path / "permissions_pod_standing.auto.tfvars").write_text(PERMISSIONS_TFVARS)

    return tmp_path

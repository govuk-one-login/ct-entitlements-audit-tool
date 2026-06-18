
import pytest
import yaml


TEAM_CSV = """\
user_alias,display_name,email,family_name,given_name
alice,Alice Smith,alice@example.com,Smith,Alice
bob,Bob Jones,bob@example.com,Jones,Bob
"""

ROLE_CSV = """\
user_alias,display_name,email,family_name,given_name
ignored,Ignored User,ignored@example.com,User,Ignored
"""

GROUPS_YAML = """\
---
################################################################################
# Alpha Pod Groups
################################################################################
alpha-team-one:
  description: Alpha Team One
  roles:
    - team-one
    - team-two
  collaborators:
    - charlie

alpha-team-two:
  description: Alpha Team Two
  roles:
    - team-two
  permanent_members:
    - danielle
"""

ENTITLEMENTS_YAML = """\
---
################################################################################
# Alpha Pod Entitlements
################################################################################

team-one:
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

team-two:
  production:
    accounts:
      - prod-account-b
    org_units: []
    standing_permissions:
      - ViewOnly
    eligible_permissions:
      - ReadOnly
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
    env_pods = tmp_path / "env" / "production" / "pods" / "alpha"
    env_pods.mkdir(parents=True)

    (env_pods / "alpha-team-one.csv").write_text(TEAM_CSV)
    (env_pods / "role.csv").write_text(ROLE_CSV)
    (env_pods / "groups.yaml").write_text(GROUPS_YAML)
    (env_pods / "entitlements.yaml").write_text(ENTITLEMENTS_YAML)
    (tmp_path / "permissions_pod_standing.auto.tfvars").write_text(PERMISSIONS_TFVARS)

    return tmp_path

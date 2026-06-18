
import pytest
import yaml


@pytest.fixture
def base_path(tmp_path):
    """Create a minimal file structure mimicking the terraform layout."""
    env_pods = tmp_path / "env" / "production" / "pods" / "alpha"
    env_pods.mkdir(parents=True)

    # Team CSV
    csv_content = "user_alias,display_name,email\nalice,Alice Smith,alice@example.com\nbob,Bob Jones,bob@example.com\n"
    (env_pods / "alpha-team-one.csv").write_text(csv_content)

    # Skipped CSVs
    (env_pods / "role.csv").write_text("user_alias,display_name,email\nignored,Ignored,ignored@example.com\n")

    # Groups yaml
    groups = {
        "alpha-team-one": {
            "roles": ["team-one", "team-two"],
            "collaborators": ["charlie"]
        },
        "alpha-team-two": {
            "roles": ["team-two"],
            "permanent_members": ["danielle"]
        }
    }
    (env_pods / "groups.yaml").write_text(yaml.dump(groups))

    # Entitlements yaml
    entitlements = {
        "team-one": {
            "development": {
                "accounts": ["dev-account-a", "dev-account-b"],
                "org_units": ["dev-ou"],
                "standing_permissions": ["Admin"]
            },
            "non-production": {
                "accounts": ["staging-account"],
                "org_units": ["staging-ou"],
                "standing_permissions": ["ReadOnly"],
                "eligible_permissions": ["Admin"]
            },
            "production": {
                "accounts": ["prod-account-a"],
                "org_units": ["production-ou"],
                "standing_permissions": ["ViewOnly"],
                "eligible_permissions": ["PowerUser"]
            },
            "emergency_access": {
                "accounts": ["prod-account-a"],
                "standing_permissions": ["EmergencyAdmin"]
            }
        },
        "team-two": {
            "production": {
                "accounts": ["prod-account-b"],
                "org_units": [],
                "standing_permissions": ["ViewOnly"],
                "eligible_permissions": ["ReadOnly"]
            }
        }
    }
    (env_pods / "entitlements.yaml").write_text(yaml.dump(entitlements))

    # Permissions tfvars file
    perms_content = '''
ViewOnly = {
  description = "View only access"
  managed_policies = ["arn:aws:iam::aws:policy/ViewOnlyAccess"]
}

PowerUser = {
  description = "Power user access"
  managed_policies = ["arn:aws:iam::aws:policy/PowerUserAccess", "arn:aws:iam::aws:policy/IAMReadOnlyAccess"]
}
'''
    (tmp_path / "permissions_pod_standing.auto.tfvars").write_text(perms_content)

    return tmp_path

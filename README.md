# CT Entitlements Audit Tool

A CLI tool for querying and auditing AWS Identity Center entitlements
configured via Terraform. It parses user CSVs, group YAML files,
entitlement YAML files, and HCL permission set definitions to provide
a unified view of who has access to what.

## Features

- Query user permissions by alias or email
- Audit account access (who has standing/eligible access)
- Inspect roles and permission sets
- Export all entitlements data as JSON
- Diff two JSON exports to detect changes over time

## Prerequisites

- Python 3.12+
- Access to the terraform identity store directory (set via `ENTITLEMENTS_BASE_PATH`
  env var or `--base-path`)

## Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd ct-entitlements-audit-tool

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
make install

# Install test/dev dependencies
make install-test
```

### Pre-commit Hooks

The project uses pre-commit for automated checks on commit:

```bash
pre-commit install
pre-commit install --hook-type commit-msg
```

## Usage

### entitlements.py

Set the `ENTITLEMENTS_BASE_PATH` environment variable, or pass `--base-path`,
to point to the terraform directory in your local copy of
the Identity Center configuration repo:

```bash
export ENTITLEMENTS_BASE_PATH=/path/to/terraform
```

#### Query user permissions

```bash
# By alias or email
python entitlements.py user <alias | email>

# By alias, filtered to a specific account
python entitlements.py user <alias> <account_name>
```

#### Audit account access

```bash
python entitlements.py account <account_name>
```

#### Inspect roles and permission sets

```bash
python entitlements.py role <role_name>
python entitlements.py permission <permission_set_name>
```

#### List all users or roles

```bash
python entitlements.py list-users
python entitlements.py list-roles
```

#### Export as JSON

```bash
# Export everything
python entitlements.py export all > all.json

# Export specific entities
python entitlements.py export users
python entitlements.py export user=<alias>
python entitlements.py export groups
python entitlements.py export group=<name>
python entitlements.py export roles
python entitlements.py export role=<name>
python entitlements.py export permissionsets
python entitlements.py export permissionset=<name>
python entitlements.py export accounts
python entitlements.py export account=<name>
```

#### Interactive mode

```bash
python entitlements.py interactive
```

#### Options

| Flag | Description |
|------|-------------|
| `--base-path` | Path to the terraform directory (overrides `ENTITLEMENTS_BASE_PATH`) |
| `--environment` | Environment name (default: `production`) |

#### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Invalid or missing command |
| 3 | Base path does not exist |
| 5 | User/Account/Role not found |

### jsondiff.py exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | File not found or JSON parse error |

### jsondiff.py

Compares two JSON exports (e.g. before and after a change) and prints a
colour-coded diff summary.

```bash
# Generate baseline and updated exports
python entitlements.py export all > all.json
# ... make changes ...
python entitlements.py export all > all-new.json

# Print diff summary to stdout
python jsondiff.py

# Use custom file paths
python jsondiff.py --old baseline.json --new updated.json

# Write structured diff to a JSON file
python jsondiff.py --output diff.json
```

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--old` | `all.json` | Path to baseline JSON export |
| `--new` | `all-new.json` | Path to updated JSON export |
| `--output` | (none) | Write diff as JSON to file instead of printing summary |
| `--colour` / `--no-colour` | `--colour` | Enable or disable ANSI coloured output |
| `--compact` / `--no-compact` | `--compact` | Trim long lines with `...` or show full lists |

The summary output uses ANSI colours: removed items are highlighted in
red with a `-` prefix, added items in green with a `+` prefix. Long
lines are trimmed with `...` to keep output readable.

## Makefile

Run `make help` to see all available targets:

| Target | Description |
|--------|-------------|
| `make install` | Install runtime dependencies |
| `make install-test` | Install test/dev dependencies |
| `make test` | Run pytest with coverage |
| `make interactive` | Launch interactive query mode |
| `make export-all` | Export all users to JSON |
| `make export-matrix` | Export access matrix to JSON |
| `make list-users` | List all users |
| `make list-roles` | List all roles |
| `make query-user USER=<alias>` | Query a specific user |
| `make query-account ACCOUNT=<name>` | Audit a specific account |
| `make query-role ROLE=<name>` | Show role details |
| `make clean` | Remove generated files and caches |

## Running Checks, Lints, and Tests

### Linting with Ruff

```bash
# Check for lint errors
ruff check .

# Auto-fix fixable issues
ruff check --fix .

# Check formatting
ruff format --check .

# Apply formatting
ruff format .
```

### Security scanning with Bandit

```bash
bandit -r .
```

### Tests with pytest

```bash
# Run tests with coverage
python -m pytest tests/ -v

# Or via make
make test
```

Coverage is configured in `pyproject.toml` to require a minimum of 80%
coverage on the `entitlements` package.

### All-in-one script

```bash
./lint_and_test.sh
```

This runs ruff check, ruff format check, pytest with coverage, and bandit
in sequence.

## Project Structure

```text
ct-entitlements-audit-tool/
├── entitlements/
│   ├── __init__.py        # Package exports
│   ├── model.py           # Data model (loads CSV/YAML/HCL)
│   └── export.py          # JSON export logic
├── tests/
│   ├── conftest.py        # Test fixtures
│   └── test_entitlements_model.py
├── entitlements.py        # Main CLI entry point
├── jsondiff.py            # JSON diff tool
├── Makefile               # Development shortcuts
├── pyproject.toml         # Ruff and pytest configuration
├── requirements.txt       # Runtime dependencies
└── requirements-test.txt  # Test/dev dependencies
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ENTITLEMENTS_BASE_PATH` | Path to the terraform identity store directory |
| `DEBUG` | Set to any value to enable debug logging |

.PHONY: help install install-test test interactive examples test-user test-account export-all clean

help:
	@echo "Entitlements Query Interface - Make Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install          Install Python dependencies"
	@echo ""
	@echo "Usage:"
	@echo "  make interactive      Launch interactive query mode"
	@echo "  make examples         Run example queries"
	@echo "  make test-user        Test query for a sample user"
	@echo "  make test-account     Test account audit"
	@echo ""
	@echo "Export:"
	@echo "  make export-all       Export all users to JSON"
	@echo "  make export-matrix    Export access matrix to JSON"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean            Remove generated files"
	@echo ""
	@echo "Custom queries:"
	@echo "  make query-user USER=<alias>"
	@echo "  make query-account ACCOUNT=<name>"
	@echo "  make query-role ROLE=<name>"

install:
	pip install -r requirements-entitlements.txt

install-test:
	pip install -r requirements-test.txt

test:
	python -m pytest tests/ -v

interactive:
	python entitlements_interactive.py

examples:
	python entitlements_examples.py

test-user:
	@echo "Testing user query..."
	@python entitlements_interactive.py list-users | head -20
	@echo ""
	@echo "To query a specific user, run: make query-user USER=<alias>"

test-account:
	@echo "Testing account audit..."
	@echo "Available accounts in entitlements:"
	@python -c "from entitlements_query import EntitlementsModel; \
		from pathlib import Path; \
		m = EntitlementsModel(str(Path('fog/terraform-aws-identitystore/terraform'))); \
		accounts = set(); \
		[accounts.update(e.accounts) for r in m.role_entitlements.values() for e in r]; \
		[print(f'  - {a}') for a in sorted(accounts)[:10]]"
	@echo ""
	@echo "To audit a specific account, run: make query-account ACCOUNT=<name>"

query-user:
	@if [ -z "$(USER)" ]; then \
		echo "Error: USER not specified"; \
		echo "Usage: make query-user USER=<alias>"; \
		exit 1; \
	fi
	python entitlements_query.py $(USER)

query-account:
	@if [ -z "$(ACCOUNT)" ]; then \
		echo "Error: ACCOUNT not specified"; \
		echo "Usage: make query-account ACCOUNT=<name>"; \
		exit 1; \
	fi
	python entitlements_interactive.py account $(ACCOUNT)

query-role:
	@if [ -z "$(ROLE)" ]; then \
		echo "Error: ROLE not specified"; \
		echo "Usage: make query-role ROLE=<name>"; \
		exit 1; \
	fi
	python entitlements_interactive.py role $(ROLE)

export-all:
	@echo "Exporting all users to entitlements_all_users.json..."
	python entitlements_export.py all-users > entitlements_all_users.json
	@echo "Done! Output saved to entitlements_all_users.json"

export-matrix:
	@echo "Exporting access matrix to entitlements_matrix.json..."
	python entitlements_export.py matrix > entitlements_matrix.json
	@echo "Done! Output saved to entitlements_matrix.json"

export-full:
	@echo "Exporting full model to entitlements_full.json..."
	python entitlements_export.py full > entitlements_full.json
	@echo "Done! Output saved to entitlements_full.json"

list-users:
	python entitlements_interactive.py list-users

list-roles:
	python entitlements_interactive.py list-roles

clean:
	rm -f entitlements_*.json
	rm -rf __pycache__ .pytest_cache
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete

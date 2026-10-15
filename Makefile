PYTHON ?= python3
LABORATORY_ARGS ?=

.PHONY: doctor list-plugins validate-packages check-packages generate-marketplaces \
	check-marketplaces validate-contract check-docs sync-agent-adapters check-agent-adapters \
	check-prerequisites check-issue-coverage setup-hooks generate-playbooks check-playbooks check-laboratory check

check-docs:
	"$(PYTHON)" scripts/agent/validate_docs.py

generate-playbooks:
	"$(PYTHON)" scripts/generate_plugin_playbooks.py

check-playbooks:
	"$(PYTHON)" scripts/generate_plugin_playbooks.py --check

# Kept separate from portable checks; a blocked isolation boundary fails readiness.
check-laboratory:
	"$(PYTHON)" scripts/check_laboratory.py $(LABORATORY_ARGS)

doctor:
	"$(PYTHON)" scripts/agent/doctor.py

list-plugins:
	"$(PYTHON)" -m cops list

validate-packages:
	"$(PYTHON)" -m cops validate

check-packages:
	"$(PYTHON)" -m cops check

generate-marketplaces:
	"$(PYTHON)" -m cops generate

check-marketplaces:
	"$(PYTHON)" -m cops generate --check

validate-contract:
	"$(PYTHON)" scripts/agent/validate_contract.py

sync-agent-adapters:
	"$(PYTHON)" scripts/agent/sync_adapters.py

check-agent-adapters:
	"$(PYTHON)" scripts/agent/sync_adapters.py --check

check-prerequisites:
	"$(PYTHON)" scripts/agent/check_prerequisites.py

check-issue-coverage:
	"$(PYTHON)" scripts/agent/check_issue_coverage.py

setup-hooks:
	"$(PYTHON)" scripts/agent/install_hooks.py

check: check-prerequisites
	"$(PYTHON)" scripts/agent/check.py

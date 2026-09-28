PYTHON ?= python3

.PHONY: doctor list-plugins validate-packages check-packages generate-marketplaces \
	check-marketplaces validate-contract sync-agent-adapters check-agent-adapters check-prerequisites check

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

check: check-prerequisites
	"$(PYTHON)" scripts/agent/check.py

.PHONY: doctor validate-contract sync-agent-adapters check-agent-adapters check

doctor:
	python3 scripts/agent/doctor.py

validate-contract:
	python3 scripts/agent/validate_contract.py

sync-agent-adapters:
	python3 scripts/agent/sync_adapters.py

check-agent-adapters:
	python3 scripts/agent/sync_adapters.py --check

check:
	python3 scripts/agent/check.py

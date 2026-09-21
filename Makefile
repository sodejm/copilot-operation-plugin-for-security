.PHONY: doctor list-plugins validate-packages check-packages generate-marketplaces \
	check-marketplaces validate-contract sync-agent-adapters check-agent-adapters check

doctor:
	python3 scripts/agent/doctor.py

list-plugins:
	python3 -m cops list

validate-packages:
	python3 -m cops validate

check-packages:
	python3 -m cops check

generate-marketplaces:
	python3 -m cops generate

check-marketplaces:
	python3 -m cops generate --check

validate-contract:
	python3 scripts/agent/validate_contract.py

sync-agent-adapters:
	python3 scripts/agent/sync_adapters.py

check-agent-adapters:
	python3 scripts/agent/sync_adapters.py --check

check:
	python3 scripts/agent/check.py

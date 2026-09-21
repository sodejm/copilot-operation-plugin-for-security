.PHONY: validate test verify-adapters check

validate:
	python3 scripts/huntwb.py validate library

test:
	python3 scripts/huntwb.py test library --seed 20260916

verify-adapters:
	python3 scripts/huntwb.py verify-adapters

check: validate test verify-adapters

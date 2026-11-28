PYTHON ?= python3

.PHONY: validate test verify-adapters unit stress check release

validate:
	$(PYTHON) scripts/validate_package.py

test:
	$(PYTHON) scripts/huntwb.py test library --seed 20260916

verify-adapters:
	$(PYTHON) scripts/huntwb.py verify-adapters

unit:
	$(PYTHON) -m unittest discover -s tests -v

stress:
	$(PYTHON) scripts/stress_test.py --seed 20260916

check: validate unit stress verify-adapters

release: check
	$(PYTHON) scripts/build_release_artifacts.py --seed 20260916

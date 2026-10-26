PYTHON ?= python3

.PHONY: test
test: ## Run every tool's test suite; fails if any suite fails or runs zero tests
	$(PYTHON) run_tests.py

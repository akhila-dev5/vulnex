# VULNEX developer shortcuts. Everything runs from the repo root.
PY      ?= python3
VENV    := backend/.venv
PYBIN   := .venv/bin/python
BRANCHES ?= 3.0-dev,fasttrack/3.0
PORT    ?= 8000

.PHONY: help venv install test scan serve export screenshots clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv: ## Create the backend virtualenv
	$(PY) -m venv $(VENV)

install: venv ## Install runtime + dev dependencies
	$(VENV)/bin/python -m pip install --upgrade pip
	$(VENV)/bin/python -m pip install -r backend/requirements-dev.txt

test: ## Run the scanner test suite
	cd backend && $(PYBIN) -m pytest -q

scan: ## Run a full scan over both Azure Linux branches
	cd backend && $(PYBIN) -m vulnex.cli scan --branches "$(BRANCHES)"
	cd backend && $(PYBIN) -m vulnex.cli stats

serve: ## Serve the live dashboard + API on :$(PORT)
	cd backend && $(PYBIN) -m vulnex.cli serve --port $(PORT)

export: ## Build the static GitHub Pages dashboard into site/
	cd backend && $(PYBIN) -m vulnex.cli export --out ../site

screenshots: ## Regenerate docs/screenshots (needs the optional playwright extra)
	cd backend && $(PYBIN) ../scripts/screenshots.py

clean: ## Remove caches and generated site output
	rm -rf backend/.pytest_cache site data/cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

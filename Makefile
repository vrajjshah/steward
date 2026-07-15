ifeq ($(origin PYTHON), undefined)
PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
endif

.PHONY: demo run eval eval-deterministic test lint

demo:
	STEWARD_DEMO=1 $(PYTHON) -m uvicorn steward.app:app --reload

run:
	$(PYTHON) -m uvicorn steward.app:app --reload

eval:
	@echo "Running the deterministic gate plus the offline LLM-tier measurement..."
	$(PYTHON) -m evals.run

eval-deterministic:
	$(PYTHON) -m evals.run --deterministic-only

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

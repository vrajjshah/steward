ifeq ($(origin PYTHON), undefined)
PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
endif

.PHONY: demo run eval eval-deterministic test lint llm-benchmark llm-benchmark-live

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

llm-benchmark:
	@echo "Re-verifying the committed LLM-tier benchmark cache (no model call)..."
	$(PYTHON) -m evals.llm_benchmark

llm-benchmark-live:
	@echo "Running the labeled LLM-tier benchmark against configured Bedrock models..."
	$(PYTHON) -m evals.llm_benchmark --live

lint:
	$(PYTHON) -m ruff check .

# ═══════════════════════════════════════════════════════════════════════════
#  TURRET OS — Master Makefile
#  Usage: make <target>
# ═══════════════════════════════════════════════════════════════════════════

.PHONY: all run stop harvest graph rules train explain pack eval test report \
        lint format typecheck clean build-ui dev-ui install install-ui

PYTHON      := poetry run python
PYTEST      := poetry run pytest
SEED        ?= 42
EPOCHS      ?= 60
DATA_DIR    ?= data/raw
REPORT_DIR  ?= reports
EVIDENCE_DIR?= evidence_packs

# ── Default ────────────────────────────────────────────────────────────────
all: test

# ── Infrastructure ─────────────────────────────────────────────────────────
run:
	@echo "🚀  Starting TURRET OS stack..."
	docker compose -f infra/docker-compose.yml up -d
	@echo "✅  Services up. Neo4j: http://localhost:7474 | API: http://localhost:8000/docs | UI: http://localhost:5173"

stop:
	docker compose -f infra/docker-compose.yml down

logs:
	docker compose -f infra/docker-compose.yml logs -f

# ── Pipeline Stages ────────────────────────────────────────────────────────
install:
	poetry install

install-ui:
	cd apps/ui && npm install

harvest:
	@echo "🔍  L1 Harvest — extracting metadata from $(DATA_DIR)"
	$(PYTHON) -m turret_harvest.cli \
	    --source $(DATA_DIR) \
	    --out data/processed/records.parquet \
	    --config config/default.yaml

graph:
	@echo "🕸️   L2 Graph — loading provenance KG into Neo4j"
	$(PYTHON) -m turret_graph.cli load \
	    --parquet data/processed/records.parquet \
	    --config config/default.yaml

rules:
	@echo "📋  L3 Rules — evaluating 8 espionage rules"
	$(PYTHON) -m turret_detect.rules \
	    --config config/espionage_rules.yaml \
	    --out data/processed/rule_alerts.parquet

train:
	@echo "🧠  L3 GNN — training GraphSAGE+Time2Vec ($(EPOCHS) epochs, seed=$(SEED))"
	$(PYTHON) -m turret_detect.trainer \
	    --epochs $(EPOCHS) \
	    --seed $(SEED) \
	    --checkpoint models/checkpoints/gnn_latest.pt

explain:
	@echo "💡  L3 Explain — SHAP + GNNExplainer"
	$(PYTHON) -m turret_detect.explain \
	    --checkpoint models/checkpoints/gnn_latest.pt \
	    --out data/processed/explanations.parquet

pack:
	@echo "📦  L4 Evidence — packaging signed forensic bundles"
	$(PYTHON) -m turret_evidence.cli \
	    --alerts data/processed/rule_alerts.parquet \
	    --out $(EVIDENCE_DIR)/

pipeline: harvest graph rules train explain pack
	@echo "✅  Full pipeline complete."

# ── Evaluation (Experiment Tables I–VII) ──────────────────────────────────
eval:
	@echo "📊  Running all experiments (Tables I–VII)..."
	$(PYTHON) scripts/run_experiments.py \
	    --seeds 42,43,44,45,46 \
	    --out $(REPORT_DIR)/

report:
	@echo "📈  Generating paper-ready plots + LaTeX tables..."
	$(PYTHON) scripts/plot_results.py --report-dir $(REPORT_DIR)/
	@echo "✅  Reports written to $(REPORT_DIR)/"

# ── TSEC Synthetic Corpus ─────────────────────────────────────────────────
tsec:
	@echo "🏗️   Generating TSEC synthetic corpus (seed=$(SEED))..."
	$(PYTHON) scripts/generate_tsec.py \
	    --seed $(SEED) \
	    --users 500 \
	    --days 365 \
	    --out data/tsec/

# ── Testing ────────────────────────────────────────────────────────────────
test:
	$(PYTEST) tests/ -v --tb=short

test-unit:
	$(PYTEST) tests/unit/ -v

test-integration:
	$(PYTEST) tests/integration/ -v

test-adversarial:
	$(PYTEST) tests/adversarial/ -v

test-cov:
	$(PYTEST) tests/ --cov=packages --cov-report=html --cov-report=term-missing

# ── Code Quality ───────────────────────────────────────────────────────────
lint:
	poetry run ruff check packages/ apps/ scripts/

format:
	poetry run black packages/ apps/ scripts/
	poetry run ruff check --fix packages/ apps/ scripts/

typecheck:
	poetry run mypy packages/ apps/

# ── UI ─────────────────────────────────────────────────────────────────────
dev-ui:
	cd apps/ui && npm run dev

build-ui:
	cd apps/ui && npm run build

# ── Cleanup ────────────────────────────────────────────────────────────────
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage 2>/dev/null || true
	@echo "🧹  Clean complete."

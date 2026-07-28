# TURRET OS

> **TURRET OS** — A W3C-PROV-Aligned Provenance Knowledge Graph with Multi-Timescale Graph Neural Networks for Counter-Espionage Insider Threat Detection and ISO/IEC 27043-Compliant Forensic Evidence Generation in Tiered-Clearance Networks.

---

## Architecture

```
L1 Harvest  →  L2 Knowledge Graph  →  L3 Detector  →  L4 Evidence Pack  →  L5 Analyst UI
Tika/ExifTool   Neo4j + PROV-JSON-LD  GNN + Rules     Merkle + Ed25519      React + Cytoscape
```

Five layers, one command spin-up.

---

## Quick Start

```bash
# 1. Clone and install
git clone <repo>
cd turret-os
cp .env.example .env          # fill in secrets

# 2. Install Python dependencies (requires Python 3.11 + Poetry)
poetry install

# 3. Install UI dependencies
cd apps/ui && npm install && cd ../..

# 4. Bring up the full stack
make run

# Services:
#   Neo4j Browser   → http://localhost:7474
#   API (Swagger)   → http://localhost:8000/docs
#   UI Dashboard    → http://localhost:5173
#   Prometheus      → http://localhost:9090
```

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make run` | Docker Compose up (Neo4j + API + Worker + UI) |
| `make harvest` | Run L1 metadata harvest on `data/raw/` |
| `make graph` | Load Parquet records into Neo4j KG |
| `make rules` | Evaluate 8 espionage rules, emit alerts |
| `make train` | Train GraphSAGE+Time2Vec GNN (60 epochs) |
| `make explain` | Run SHAP + GNNExplainer on latest alerts |
| `make pack` | Package signed evidence bundles |
| `make eval` | Run all experiment tables (Tables I–VII) |
| `make test` | Run full pytest suite |
| `make report` | Generate paper-ready plots + LaTeX tables |

---

## Datasets

| ID | Source | Path |
|----|--------|------|
| D1 | CERT r6.2 | `data/raw/cert_r6.2/` |
| D2 | CERT r4.2 | `data/raw/cert_r4.2/` |
| D3 | TSEC (synthetic) | `data/tsec/` |
| D4 | WikiLeaks metadata (negative control) | `data/raw/wikileaks_meta/` |
| D5 | Internal SharePoint test tenant | `data/raw/internal_sp/` |

Generate TSEC corpus: `python scripts/generate_tsec.py --seed 42 --users 500 --days 365`

---

## Reproducibility

See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for pre-registered hypotheses and step-by-step instructions to reproduce all paper tables from raw data using `make eval`.

All random seeds are set via `TURRET_SEED` env var (default: `42`).

---

## Security

- All API keys loaded from environment — never hardcoded
- Neo4j credentials via `.env` only  
- Ed25519-signed evidence packs; replay verification in `tests/`
- See `SECURITY.md` for disclosure policy

---

## Project Layout

```
turret-os/
├── apps/api/           # FastAPI server
├── apps/worker/        # Celery ingest worker
├── apps/trainer/       # GNN training entry-point
├── apps/ui/            # React + Cytoscape.js analyst dashboard
├── packages/
│   ├── turret-common/  # Shared schemas, hashing, config
│   ├── turret-harvest/ # L1 multi-format metadata parsers
│   ├── turret-graph/   # L2 Neo4j KG + PROV-JSON-LD
│   ├── turret-detect/  # L3 GNN + rule engine + explainer
│   └── turret-evidence/# L4 forensic evidence packager
├── config/             # YAML configs + espionage rules
├── data/               # Raw + processed datasets
├── infra/              # Docker Compose + Neo4j + Prometheus
├── models/checkpoints/ # GNN model checkpoints
├── scripts/            # CLI pipeline scripts
├── tests/              # Unit + integration + adversarial tests
├── training/           # GNN definitions + rule YAML + adversarial
├── evidence_packs/     # Output signed evidence bundles
├── reports/            # Generated tables + plots
└── notebooks/          # EDA + results analysis
```

---

## Citation

```bibtex
@article{turret2025,
  title   = {TURRET OS: A W3C-PROV-Aligned Provenance Knowledge Graph ...},
  author  = {...},
  journal = {IEEE Transactions on Information Forensics and Security},
  year    = {2025}
}
```

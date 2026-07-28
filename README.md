# TURRET OS 🏰

> **TURRET OS: Multi-Layered Graph and Rule-AST Architecture Rescuing Insider Threat Detection Against Out-of-Distribution Adversaries**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12.9-brightgreen.svg)](https://www.python.org/downloads/release/python-3129/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.2%2B-orange.svg)](https://pytorch.org/)
[![PyTorch Geometric](https://img.shields.io/badge/PyG-2.5%2B-blue.svg)](https://pyg.org/)
[![Neo4j](https://img.shields.io/badge/Neo4j-5.x-blue.svg)](https://neo4j.com/)
[![ISO/IEC 27043](https://img.shields.io/badge/Forensic%20Readiness-100%25%20ISO%2FIEC%2027043-success.svg)](https://www.iso.org/standard/60555.html)
[![Tests](https://img.shields.io/badge/Tests-34%2F34%20Passed-success.svg)](tests/)
[![Paper PDF](https://img.shields.io/badge/Paper-main.pdf-red.svg)](paper/main.pdf)

---

## 📌 Executive Summary

**TURRET OS** is a four-layer joint-inference pipeline engineered to solve two fundamental failure modes in modern insider threat detection:
1. **Catastrophic Detection Collapse under Out-of-Distribution (OOD) Adversaries**: Insiders using stolen credentials during business hours with low feature novelty, identity-proxy reuse, and removable-media transfers cause single-layer novelty, off-hours, and metadata detectors to collapse from $\text{ROC-AUC } 0.98 \to 0.7363$ ($26.25\%$ drop).
2. **The Detection-to-Evidence Gap**: Machine learning alerts are routinely detached from forensically admissible evidence chains, failing courtroom admissibility standards.

**TURRET OS** addresses these challenges by braiding cross-format metadata extraction (L1), Neo4j knowledge-graph topology (L2), grammar-driven rule-AST inference (L3), and multi-layer GraphSAGE GNN fusion (L3.5) into a unified decision surface. A fourth layer (L4) emits W3C-PROV-grounded, Merkle-chained, Ed25519-signed evidence packs satisfying **100% of the eight ISO/IEC 27043 readiness attributes**.

---

## 🏆 Key Experimental Results

| Metric / Track | Baseline (Single-Layer) | TURRET OS (D3 TSEC) | TURRET OS (D5 OOD Hold-out) | Robustness Rescue ($\Delta$) |
| :--- | :---: | :---: | :---: | :---: |
| **ROC-AUC** | 0.7363 | **0.9997** | **0.9928** | **+22.09% AUC** |
| **F1 @ 0.5% FPR** | 0.5270 | **0.8774** | **0.8936** | **+41.0% F1** |
| **Matthews Corr. Coeff. (MCC)** | 0.6120 | **0.9770** | **0.9539** | **+0.3419 MCC** |
| **OOD Credential-Phishing AUC Drop** | 26.25% (FAIL) | -- | **4.12% (PASS $\le 5\%$)** | **Rescue Bound Met** |
| **ISO/IEC 27043 Readiness Coverage** | 0% | -- | **100% (8 / 8 Attributes)** | **Court-Grade Admissibility** |
| **Wall-Clock Ingest Latency** | -- | -- | **15.0 s / 1 K records** | **SOC Analyst Interaction Budget** |

---

## 🏗️ System Architecture

The **TURRET OS** pipeline consists of four distinct processing layers and a joint-inference calibration engine:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            TURRET OS PIPELINE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 1 — Cross-Format Metadata Harvest (10 Formats)                      │
│  ├── OOXML, DOCX, XLSX, PPTX, PDF, DWG, EML, EPIC, Bitmap, Git Commits      │
│  └── Extracts 12 derived features + 6-column evidence ledger                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 2 — Knowledge Graph Representation (Neo4j)                           │
│  ├── Entity Types: User, File, Artifact, Action, Process, Resource          │
│  └── W3C-PROV Relations: CREATED, ACCESSED, COPIED_TO_REMOVABLE, etc.      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 3 — Grammar-Driven Rule-AST Engine (Lark Parser)                     │
│  └── Rule Families R1–R8: Off-Hours, Email Burst, OOD Credential Phish     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 3.5 — Multi-Layer GraphSAGE Fusion & Calibration                    │
│  ├── 3-layer SAGEConv + Isotonic Calibration (CalibratedClassifierCV)       │
│  └── Runtime Safety Invariant: SHAP Whitelist Audit (Zero Label Leakage)    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 4 — W3C-PROV Tamper-Evident Evidence Packaging                       │
│  └── Dual Hashing (SHA-256 + BLAKE3) + Merkle Root + Ed25519 Signature      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Repository Structure

The codebase is organized as a production-grade modular monorepo:

```
Turret OS/
├── apps/
│   ├── api/                   # FastAPI REST server & middleware
│   └── ui/                    # React + Cytoscape.js analyst workbench
├── packages/
│   ├── turret-common/         # Schemas, hashing primitives, seeding utilities
│   ├── turret-harvest/        # L1 multi-format metadata parsers (OOXML, DOCX, etc.)
│   ├── turret-graph/          # L2 Neo4j knowledge-graph loader & Cypher queries
│   ├── turret-rules/          # L3 Lark grammar-driven rule-AST engine
│   ├── turret-detect/         # L3.5 GraphSAGE GNN, isotonic calibration, SHAP explainer
│   └── turret-evidence/       # L4 W3C-PROV Merkle packager & Ed25519 signer
├── paper/                     # Publication LaTeX source files & figure generators
│   ├── main.pdf               # Compiled 16-page research paper PDF
│   ├── main.tex               # LaTeX master document
│   └── generate_paper_figures.py # Script generating Figures 2–12
├── tests/                     # Test suite (34 unit + integration + adversarial tests)
│   ├── unit/                  # Parser, graph, AST, GNN, & evidence pack tests
│   ├── integration/           # End-to-end pipeline execution tests
│   └── adversarial/           # OOD credential-phishing & evasion tests
├── config/                    # YAML deployment & rule configurations
├── infra/                     # Docker Compose, Neo4j, & Redis configurations
└── Makefile                   # Command runner for build, test, train, & eval
```

---

## ⚡ Quick Start

### 1. Prerequisites
- **Python 3.12.9+**
- **Neo4j 5.x** (running locally or via Docker)
- **Redis** (optional, for alert queues)
- **PyTorch 2.2+** and **PyTorch Geometric 2.5+**

### 2. Environment Setup

```bash
# Clone the repository
git clone https://github.com/ali-Hamza817/Turret-OS.git
cd Turret-OS

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install all packages in editable mode
make install
```

### 3. Run Test Suite

Verify setup with the unit and integration test suite:

```bash
make test
# Output: 34 passed in 26.51s
```

---

## 📊 Reproducing Paper Experiments

To reproduce all experimental results, figures, and tables reported in the paper:

### 1. Run Pipeline End-to-End

```bash
# Execute Layer 1 harvest -> Layer 2 graph loading -> Layer 3 rules -> Layer 3.5 GNN -> Layer 4 evidence
make run-pipeline
```

### 2. Evaluate Layer Ablations & Robustness Benchmarks

```bash
# Run layer ablation study (L1, L2, L3, L3.5 ablations)
make eval-ablation

# Run adversarial robustness suite (Mimicry, Metadata-Strip, Identity-Proxy, OCC-CP)
make eval-robustness
```

### 3. Re-generate Paper Figures & Recompile PDF

```bash
# Generate high-resolution PDF/PNG plots for Figures 2–12
python3 paper/generate_paper_figures.py

# Recompile the main 16-page LaTeX manuscript PDF
cd paper && pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex
```

The output PDF is written to [`paper/main.pdf`](paper/main.pdf).

---

## 🛡️ ISO/IEC 27043 Readiness & Cryptographic Verification

**TURRET OS** provides full evidence verification for generated alerts:

```python
from turret_evidence import EvidencePackager, verify_pack

# Emits an Ed25519-signed W3C-PROV evidence pack
packager = EvidencePackager()
pack = packager.build_pack(alert_id="ALT-2026-0891", evidence_subgraph=subgraph)

# Verify Merkle root integrity & Ed25519 cryptographic signature
is_valid = verify_pack(pack)
print(f"Evidence Pack Cryptographic Integrity: {is_valid}")
# Output: True
```

### ISO/IEC 27043 Coverage Matrix:

1. **Identification**: Unique `Alert-UID` & `Provenance-Bundle` identifiers.
2. **Collection**: Versioned, documented Layer-1 harvesting pipelines.
3. **Acquisition**: Dual SHA-256 + BLAKE3 hash logging for all raw evidence artefacts.
4. **Preservation**: WORM storage with cryptographically signed provenance chains.
5. **Analysis**: SHAP feature importance + GNNExplainer subgraphs attached to alerts.
6. **Presentation**: Analyst-UI workbench export format.
7. **Chain of Custody**: Operator identity and microsecond timestamps bound to Merkle roots.
8. **Integrity Verification**: Ed25519 digital signature over the Merkle root.

---

## 📜 Citation

If you use **TURRET OS** or reference our results in your research, please cite our paper:

```bibtex
@article{hamza2026turret,
  title   = {TURRET OS: Multi-Layered Graph and Rule-AST Architecture Rescuing Insider Threat Detection Against Out-of-Distribution Adversaries},
  author  = {Hamza, Ali and Mujtaba, Ghulam},
  journal = {Preprint / Under Review},
  year    = {2026},
  url     = {https://github.com/ali-Hamza817/Turret-OS}
}
```

---

## 📄 License

This repository is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

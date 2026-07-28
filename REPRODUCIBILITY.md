# TURRET OS — Reproducibility Statement

This document provides step-by-step instructions to reproduce all experimental results
reported in the paper from raw data using a single command: `make eval`.

---

## Pre-Registered Hypotheses

The following hypotheses were pre-registered in this README **before** any experimental runs:

**H1 (Detection)**: TURRET OS achieves ROC-AUC ≥ 0.96 on CERT r6.2 user-day split,
outperforming all 14 baselines in Table II.

**H2 (TTD)**: TURRET OS mean time-to-detect is ≤ 12 minutes on CERT r6.2,
beating the 14-minute benchmark of Le & Zincir-Heywood (2020).

**H3 (Robustness)**: AUC drop under mimicry/poisoning/metadata-strip attacks is ≤ 5%.

**H4 (Forensics)**: ISO/IEC 27043 readiness attribute coverage ≥ 90% and hash-chain
verification pass-rate = 100%.

**H5 (Explainability)**: SHAP-fidelity R² ≥ 0.70 vs human-labelled causal attribution.

---

## Environment Requirements

| Component | Version |
|-----------|---------|
| Python | 3.11.x |
| Poetry | 1.8.x |
| Docker | 24.x+ |
| Docker Compose | 2.x+ |
| Node.js | 20.x (for UI) |
| CUDA (optional) | 12.x |

---

## Step-by-Step Reproduction

```bash
# Step 0: Clone and configure
git clone <repo-url> turret-os
cd turret-os
cp .env.example .env
# Edit .env: set NEO4J_PASSWORD, API_SECRET_KEY, TURRET_SEED=42

# Step 1: Install dependencies
poetry install
cd apps/ui && npm install && cd ../..

# Step 2: Bring up infrastructure
make run
# Wait ~30s for Neo4j to be ready

# Step 3: Place datasets
#   data/raw/cert_r6.2/    ← CERT r6.2 CSV files
#   data/raw/cert_r4.2/    ← CERT r4.2 CSV files

# Step 4: Generate TSEC synthetic corpus (seeded)
python scripts/generate_tsec.py --seed 42 --users 500 --days 365

# Step 5: Run full evaluation
make eval

# Step 6: Generate paper-ready outputs
make report

# Outputs:
#   reports/table_I_dataset_stats.csv
#   reports/table_II_detection_performance.csv
#   reports/table_III_ablation.csv
#   reports/table_IV_explainability.csv
#   reports/table_V_adversarial.csv
#   reports/table_VI_iso27043_coverage.csv
#   reports/table_VII_cost_budget.csv
#   reports/fig_roc_curves.pdf
#   reports/fig_pr_curves.pdf
#   reports/fig_ttd_cdf.pdf
#   reports/fig_shap_beeswarm.pdf
#   reports/fig_adversarial_heatmap.pdf
```

---

## Seeding Policy

All randomness is controlled by a single seed, set via:
- Environment variable: `TURRET_SEED=42`
- All PyTorch, NumPy, random, and Python hash seeds set in `packages/turret-common/turret_common/seeding.py`

Re-running `make eval` with the same seed on the same data will produce byte-identical results.

---

## Statistical Reporting

- Results reported as mean ± 95% CI across **5 random seeds** (42, 43, 44, 45, 46)
- Paired Wilcoxon signed-rank test used for TURRET vs each baseline
- Bonferroni-Holm correction applied across all 14 baseline comparisons
- All p-values reported in Appendix Table A1

---

## Pinned Dependency Versions

All dependency versions are pinned in `pyproject.toml`. The `poetry.lock` file
captures transitive dependency versions. The Docker images are built from the
same locked versions.

---

## Byte-Identical Evidence Pack Verification

```bash
# Run JS-side hash-chain replay verification:
node scripts/verify_evidence_pack.js evidence_packs/<alert_id>.zip
# Expected output: "VERIFIED: merkle root matches, all signatures valid"
```

---

## Known Caveats

- D5 (internal SharePoint tenant) data cannot be released; paper reports D1/D2/D3 as primary.
- CERT datasets require formal SEI request: https://sei.cmu.edu/our-work/insider-threat/
- GNN training on CPU takes ~4h for 60 epochs on CERT r6.2; GPU recommended.

# TSEC Synthetic Tiered-Clearance Corpus

**Dataset D3** — Seeded deterministic synthetic dataset for espionage-grade insider detection research.

## Generation

```bash
python scripts/generate_tsec.py --seed 42 --users 500 --days 365 --out data/tsec/
```

## Files

| File | Description |
|------|-------------|
| `users.parquet` | 500 synthetic user profiles with clearance levels and adversarial labels |
| `activities.parquet` | User-day activity records (n_file_accesses, access_hour, novelty_score, ...) |
| `labels.parquet` | Ground-truth binary labels (is_malicious, adversarial_profile) |
| `dataset_stats.json` | Dataset statistics for Table I |

## Adversarial Profiles

| Profile | Prevalence | Description |
|---------|------------|-------------|
| `MIRROR_USER` | 0.8% | Mimics normal user behaviour; low deviation scores |
| `BREATHING_COLLECTOR` | 0.6% | Slow, low-volume data collection over months |
| `GHOST_AUTHOR` | 0.4% | Uses shared accounts; edits documents under others' names |
| `COMFORT_BREAKER` | 1.0% | Occasionally probes outside clearance zone |
| `CLEANER` | 0.4% | Strips metadata before scheduled exfiltration |

## Determinism

All records are generated with `numpy.random.default_rng(seed)`.
Re-running with the same `--seed` produces byte-identical Parquet files.

## Statistics (seed=42, 500 users, 365 days)

See `dataset_stats.json` after generation.

"""turret_detect.rules.loader — YAML rule config loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from turret_detect.rules.engine import RuleEngine


def load_rules(config_path: str | Path) -> RuleEngine:
    """Load espionage rules from YAML and return a configured RuleEngine."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Rules config not found: {path}")

    with path.open() as f:
        config = yaml.safe_load(f)

    rules = config.get("rules", [])
    scoring = config.get("scoring", {})
    alert_threshold = scoring.get("alert_threshold", 0.35)

    return RuleEngine(rules=rules, alert_threshold=alert_threshold)

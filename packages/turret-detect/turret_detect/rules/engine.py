"""
turret_detect.rules.engine
============================
Boolean AST rule engine for TURRET OS espionage detection rules.
Evaluates 8 espionage rules with configurable thresholds and weights.
Output: normalised aggregate score + list of RuleHit objects.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from turret_common.schemas import RuleHit

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Evaluate espionage detection rules against a user activity window.

    Rules are loaded from YAML (see config/espionage_rules.yaml) and
    evaluated as a weighted sum.  The final score is normalised to [0, 1]
    by the sum of all rule weights.
    """

    def __init__(self, rules: list[dict[str, Any]], alert_threshold: float = 0.35) -> None:
        self.rules = rules
        self.alert_threshold = alert_threshold
        self._total_weight = sum(r.get("weight", 0.0) for r in rules)

    def evaluate(self, activity: dict[str, Any]) -> tuple[float, list[RuleHit]]:
        """
        Evaluate all rules against an activity record.

        Args:
            activity: dict with user activity fields for a time window.

        Returns:
            (normalised_score, [RuleHit, ...])
        """
        hits: list[RuleHit] = []
        weighted_sum = 0.0

        for rule in self.rules:
            triggered, evidence = self._evaluate_rule(rule, activity)
            if triggered:
                hit = RuleHit(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    weight=rule["weight"],
                    triggered_at=datetime.now(tz=timezone.utc),
                    evidence_fields=evidence,
                    severity=rule.get("severity", "medium"),
                )
                hits.append(hit)
                weighted_sum += rule["weight"]
                logger.debug("Rule %s triggered for activity window", rule["id"])

        score = weighted_sum / self._total_weight if self._total_weight > 0 else 0.0
        return score, hits

    def _evaluate_rule(
        self, rule: dict[str, Any], activity: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        """
        Dispatch rule evaluation by condition type.
        Returns (triggered: bool, evidence: dict).
        """
        condition = rule.get("condition", {})
        ctype = condition.get("type", "")

        dispatch = {
            "threshold": self._eval_threshold,
            "statistical": self._eval_statistical,
            "temporal": self._eval_temporal,
            "metadata_mismatch": self._eval_metadata_mismatch,
            "device_clearance": self._eval_device_clearance,
            "compound": self._eval_compound,
            "temporal_correlation": self._eval_temporal_correlation,
            "metadata_delta": self._eval_metadata_delta,
        }

        handler = dispatch.get(ctype)
        if not handler:
            logger.warning("Unknown rule condition type: %s for rule %s", ctype, rule["id"])
            return False, {}

        return handler(condition, activity, rule)

    # ── Rule evaluators ──────────────────────────────────────────────────

    def _eval_threshold(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """CLEARANCE_VIOLATION: file classifier above user clearance."""
        clearance_order = {"open": 0, "cui": 1, "secret": 2, "ts": 3, "ts_sci": 4}
        file_clf = act.get("file_classifier", "open")
        user_clf = act.get("user_max_clearance", "open")
        triggered = clearance_order.get(file_clf, 0) > clearance_order.get(user_clf, 0)
        evidence = {"file_classifier": file_clf, "user_clearance": user_clf}
        return triggered, evidence

    def _eval_statistical(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """COMFORT_ZONE_BREACH: access novelty z-score above threshold."""
        score = act.get("access_novelty_score", 0.0)
        sigma = cond.get("sigma_threshold", 3.0)
        triggered = float(score) > sigma
        return triggered, {"access_novelty_score": score, "sigma_threshold": sigma}

    def _eval_temporal(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """AFTER_HOURS_SPIKE: above-multiplier activity outside business hours."""
        hour = act.get("access_hour", 12)
        off_hours = hour < 7 or hour >= 19
        multiplier = act.get("off_hours_multiplier", 1.0)
        threshold = cond.get("activity_multiplier", 2.5)
        triggered = off_hours and float(multiplier) >= threshold
        return triggered, {"hour": hour, "off_hours_multiplier": multiplier}

    def _eval_metadata_mismatch(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """IDENTITY_PROXY: session user != document author strings."""
        session_user = act.get("session_user", "").lower().strip()
        doc_author = act.get("doc_author", "").lower().strip()
        last_modifier = act.get("last_modifier", "").lower().strip()
        mismatch = bool(session_user and doc_author and session_user not in doc_author)
        evidence = {"session_user": session_user, "doc_author": doc_author, "last_modifier": last_modifier}
        return mismatch, evidence

    def _eval_device_clearance(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """PRINT_TO_NON_SECRET_DEVICE: print to under-cleared printer."""
        clearance_order = {"open": 0, "cui": 1, "secret": 2, "ts": 3, "ts_sci": 4}
        action = act.get("action", "")
        file_clf = act.get("file_classifier", "open")
        device_clf = act.get("device_clearance", "open")
        file_clfs = cond.get("file_classifier", [])
        triggered = (
            action == "print"
            and file_clf in file_clfs
            and clearance_order.get(device_clf, 0) < clearance_order.get(file_clf, 0)
        )
        return triggered, {"action": action, "file_classifier": file_clf, "device_clearance": device_clf}

    def _eval_compound(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """LARGE_OOXML_OUTBOUND: compound multi-field check."""
        conditions = cond.get("all", [])
        evidence: dict = {}
        for sub_cond in conditions:
            field = sub_cond.get("field", "")
            op = sub_cond.get("operator", "eq")
            value = sub_cond.get("value") or sub_cond.get("values", [])
            field_val = act.get(field, None)
            if op == "in" and field_val not in (value if isinstance(value, list) else [value]):
                return False, evidence
            elif op == "gt" and not (isinstance(field_val, (int, float)) and field_val > value):
                return False, evidence
            elif op == "eq" and field_val != value:
                return False, evidence
            evidence[field] = field_val
        return True, evidence

    def _eval_temporal_correlation(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """COPY_TO_REMOVABLE_AT_BADGE: file copy near badge event."""
        removable_copy = act.get("copy_to_removable", False)
        badge_gap_min = act.get("badge_gap_minutes", 999)
        max_gap = cond.get("max_gap_minutes", 30)
        triggered = removable_copy and badge_gap_min <= max_gap
        return triggered, {"copy_to_removable": removable_copy, "badge_gap_minutes": badge_gap_min}

    def _eval_metadata_delta(self, cond: dict, act: dict, rule: dict) -> tuple[bool, dict]:
        """METADATA_STRIP: metadata nulled before outbound transfer."""
        stripped = act.get("metadata_stripped", False)
        followed_by_outbound = act.get("followed_by_outbound", False)
        outbound_gap = act.get("outbound_gap_minutes", 999)
        max_gap = cond.get("followed_by", {}).get("within_minutes", 60)
        triggered = stripped and followed_by_outbound and outbound_gap <= max_gap
        return triggered, {"metadata_stripped": stripped, "outbound_gap_minutes": outbound_gap}

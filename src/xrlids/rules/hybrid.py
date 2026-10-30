"""Deterministic and Machine Learning Hybrid Decision Engine for XRL-IDARS.

Combines statistical tabular Random Forest predictions with deterministic
policy rules from the RuleEngine:
1. Applies documented deterministic priority: high-confidence rule violations
   (RFC violations, extreme SYN floods, volumetric bursts) override benign ML scores.
2. Concordant detections (both RF and Rule triggering) are classified as HYBRID.
3. Machine learning detections without rule matches are classified as RF.
4. Deterministic policy hits without ML confidence are classified as RULE.
5. Missing or unavailable rule features are explicitly tracked and never silently
   zero-filled or faked.
6. Emits structured HybridDecision with continuous threat score, severity,
   verdict, detection source, and full rule attribution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:
    from xrlids.demo.flow import Flow

from xrlids.rules.engine import RuleEngine, RuleMatch


@dataclass(frozen=True)
class HybridDecision:
    """Structured, immutable output of the Hybrid Decision Engine."""

    verdict: str  # "ATTACK" or "BENIGN"
    is_attack: bool
    threat_score: float  # Continuous threat score in [0.0, 1.0]
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
    detection_source: str  # "HYBRID", "RULE", "RF", "NONE"
    rf_probability: float
    rf_prediction: str  # "ATTACK" or "BENIGN"
    rule_triggered: bool
    matched_rules: list[RuleMatch] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    unavailable_features: list[str] = field(default_factory=list)
    unavailable_rules: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert decision to a serializable dictionary."""
        return {
            "verdict": self.verdict,
            "is_attack": self.is_attack,
            "threat_score": round(self.threat_score, 4),
            "severity": self.severity,
            "detection_source": self.detection_source,
            "rf_probability": round(self.rf_probability, 4),
            "rf_prediction": self.rf_prediction,
            "rule_triggered": self.rule_triggered,
            "rule_ids": list(self.rule_ids),
            "unavailable_features": list(self.unavailable_features),
            "unavailable_rules": list(self.unavailable_rules),
            "details": self.details,
        }


class HybridDecisionEngine:
    """Production-grade Hybrid Decision Engine combining RF and deterministic rules."""

    # Rule requirements mapping: rule_id -> set of required feature keys
    RULE_FEATURE_REQUIREMENTS: dict[str, set[str]] = {
        "RULE-SYN-FLOOD": {"syn_count", "ack_count"},
        "RULE-PORT-SCAN": {"syn_count", "packet_length_mean"},
        "RULE-HIGH-RATE-BURST": {"flow_packets_per_s", "flow_bytes_per_s"},
    }

    def __init__(
        self,
        rf_threshold: float = 0.50,
        high_severity_rf_threshold: float = 0.85,
        medium_severity_rf_threshold: float = 0.65,
        high_severity_rule_floor: float = 0.85,
        medium_severity_rule_floor: float = 0.65,
        low_severity_rule_floor: float = 0.50,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        """Initialize the hybrid decision engine with configurable thresholds.

        Args:
            rf_threshold: Classification decision boundary for RF model.
            high_severity_rf_threshold: RF posterior required for HIGH severity.
            medium_severity_rf_threshold: RF posterior required for MEDIUM severity.
            high_severity_rule_floor: Minimum continuous threat score if a HIGH rule fires.
            medium_severity_rule_floor: Minimum continuous threat score if a MEDIUM rule fires.
            low_severity_rule_floor: Minimum continuous threat score if a LOW rule fires.
            rule_engine: Optional shared RuleEngine instance.
        """
        self.rf_threshold = float(rf_threshold)
        self.high_severity_rf_threshold = float(high_severity_rf_threshold)
        self.medium_severity_rf_threshold = float(medium_severity_rf_threshold)
        self.high_severity_rule_floor = float(high_severity_rule_floor)
        self.medium_severity_rule_floor = float(medium_severity_rule_floor)
        self.low_severity_rule_floor = float(low_severity_rule_floor)
        self.rule_engine = rule_engine or RuleEngine()

    def evaluate(
        self,
        rf_probability: float,
        rule_matches: Sequence[RuleMatch] | None = None,
        *,
        unavailable_features: Sequence[str] | None = None,
        unavailable_rules: Sequence[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> HybridDecision:
        """Combine RF posterior probability and rule matches into a unified decision.

        Deterministic priority rules:
        - If RuleEngine matches any rule, rule_triggered is True.
        - If rf_probability >= rf_threshold, rf_alert is True.
        - Attack verdict is declared if either rule_alert or rf_alert is True.
        - Detection source:
          * HYBRID: both RF and Rule indicate attack (highest confidence).
          * RULE: deterministic policy hit without ML confidence (rule priority).
          * RF: statistical model detection without explicit rule signature.
          * NONE: neither tier triggered.
        - Threat score:
          * Continuous score in [0.0, 1.0].
          * If rules match, threat score is at least the highest rule floor,
            ensuring deterministic detections are never dampened by low RF probabilities.
        """
        prob = max(0.0, min(1.0, float(rf_probability)))
        rf_alert = prob >= self.rf_threshold
        rf_prediction = "ATTACK" if rf_alert else "BENIGN"

        matches = list(rule_matches) if rule_matches is not None else []
        rule_triggered = len(matches) > 0
        rule_ids = [m.rule_id for m in matches]

        is_attack = rf_alert or rule_triggered
        verdict = "ATTACK" if is_attack else "BENIGN"

        # Detection source determination
        if rf_alert and rule_triggered:
            detection_source = "HYBRID"
        elif rule_triggered:
            detection_source = "RULE"
        elif rf_alert:
            detection_source = "RF"
        else:
            detection_source = "NONE"

        # Threat score calculation: preserve RF score but enforce rule severity floors
        threat_score = prob
        if rule_triggered:
            rule_floors = []
            for m in matches:
                if m.severity == "HIGH":
                    rule_floors.append(self.high_severity_rule_floor)
                elif m.severity == "MEDIUM":
                    rule_floors.append(self.medium_severity_rule_floor)
                elif m.severity == "LOW":
                    rule_floors.append(self.low_severity_rule_floor)
            if rule_floors:
                threat_score = max(threat_score, max(rule_floors))

        # Severity determination
        has_high_rule = any(m.severity == "HIGH" for m in matches)
        has_med_rule = any(m.severity == "MEDIUM" for m in matches)

        if has_high_rule or prob >= self.high_severity_rf_threshold:
            severity = "HIGH"
        elif has_med_rule or prob >= self.medium_severity_rf_threshold:
            severity = "MEDIUM"
        elif is_attack:
            severity = "LOW"
        else:
            severity = "INFORMATIONAL"

        details = dict(context or {})
        details["rf_threshold"] = self.rf_threshold
        details["rule_count"] = len(matches)

        return HybridDecision(
            verdict=verdict,
            is_attack=is_attack,
            threat_score=threat_score,
            severity=severity,
            detection_source=detection_source,
            rf_probability=prob,
            rf_prediction=rf_prediction,
            rule_triggered=rule_triggered,
            matched_rules=matches,
            rule_ids=rule_ids,
            unavailable_features=list(unavailable_features or []),
            unavailable_rules=list(unavailable_rules or []),
            details=details,
        )

    def evaluate_features(
        self,
        features: dict[str, float],
        rf_probability: float,
        endpoints: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> HybridDecision:
        """Evaluate hybrid decision from pre-extracted feature dictionary.

        Performs strict feature-presence auditing: checks which rule features
        are missing (e.g., in degraded sensor contracts such as UNSW-NB15 R4)
        and prevents silent zero-filling.
        """
        available_keys = set(features.keys())
        missing_features: set[str] = set()
        unavailable_rules: set[str] = set()

        # Audit rule feature availability
        evaluable_features = dict(features)
        for rule_id, req_keys in self.RULE_FEATURE_REQUIREMENTS.items():
            diff = req_keys - available_keys
            if diff:
                missing_features.update(diff)
                unavailable_rules.add(rule_id)

        # Evaluate rules only using present features
        matches = self.rule_engine.evaluate_features(evaluable_features, endpoints=endpoints)

        # Filter out matches for rules that were missing required features
        valid_matches = [m for m in matches if m.rule_id not in unavailable_rules]

        return self.evaluate(
            rf_probability=rf_probability,
            rule_matches=valid_matches,
            unavailable_features=sorted(missing_features),
            unavailable_rules=sorted(unavailable_rules),
            context=context,
        )

    def evaluate_flow(
        self,
        flow: Flow,
        rf_probability: float,
        context: dict[str, Any] | None = None,
    ) -> HybridDecision:
        """Evaluate hybrid decision directly from a live Flow object."""
        matches = self.rule_engine.evaluate_flow(flow)
        return self.evaluate(
            rf_probability=rf_probability,
            rule_matches=matches,
            context=context,
        )

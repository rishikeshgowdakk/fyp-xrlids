"""Dual-layer Action Decision Audit Card generation (SPEC Section 13).

Provides structured JSON and Markdown audit artifacts for every non-ALLOW autonomous action:
- Layer 1: Perception explainability via TreeSHAP feature attribution.
- Layer 2: Response policy explainability via Q-value decomposition and driving state factors.
- Deterministic safety gate invariant verification.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np


@dataclass
class PerceptionLayerAttribution:
    detector_score: float
    top_contributing_features: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PolicyLayerExplainability:
    q_values: dict[str, float]
    decision_margin: float
    driving_state_factors: list[str] = field(default_factory=list)


@dataclass
class SafetyGateAudit:
    invariants_checked: list[str]
    action_overruled: bool
    override_reason: str | None = None


@dataclass
class ActionAuditCard:
    timestamp: str
    flow_id: str | int
    host_id: str
    proposed_action: str
    enforced_action: str
    perception_layer: PerceptionLayerAttribution
    policy_layer: PolicyLayerExplainability
    safety_gate: SafetyGateAudit

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ActionAuditCardJSON = dict[str, Any]


def explain_state_factors(
    state: np.ndarray,
    enforced_action: str,
    q_values: dict[str, float] | None = None,
) -> list[str]:
    """Generate human-readable explanations of what state factors drove policy decision.

    State dimensions:
    0: detector_score (S_t in [0, 1])
    1: ewma_score (in [0, 1])
    2: delta_score (rate of change in [-1, 1])
    3: consecutive_attacks (count normalized min(n, 10)/10)
    4: destination_critical (0 or 1)
    5: cooldown_remaining (steps normalized min(c, 30)/30)
    """
    factors: list[str] = []
    if len(state) < 6:
        return ["State vector contains insufficient dimensions for interpretation"]

    s_curr = float(state[0])
    s_ewma = float(state[1])
    s_delta = float(state[2])
    s_consec = float(state[3])
    s_crit = float(state[4])
    s_cool = float(state[5])

    # Perception threat score
    if s_curr >= 0.75:
        factors.append(f"Instantaneous attack risk is severe (S_t={s_curr:.3f} >= 0.75)")
    elif s_curr >= 0.50:
        factors.append(f"Instantaneous attack risk exceeds baseline research threshold (S_t={s_curr:.3f} >= 0.50)")
    elif s_curr >= 0.40:
        factors.append(f"Instantaneous score is in stealth/suspect band (S_t={s_curr:.3f} in [0.40, 0.50])")
    else:
        factors.append(f"Instantaneous score is benign (S_t={s_curr:.3f} < 0.40)")

    # Historical moving average
    if s_ewma >= 0.50:
        factors.append(f"Exponentially smoothed threat density is elevated (EWMA={s_ewma:.3f})")
    elif s_ewma >= 0.30:
        factors.append(f"Moderate sustained threat background present (EWMA={s_ewma:.3f})")

    # Rate of change
    if s_delta > 0.15:
        factors.append(f"Threat velocity accelerating rapidly (rate-of-change delta={s_delta:+.2f})")
    elif s_delta < -0.15:
        factors.append(f"Threat velocity decelerating (rate-of-change delta={s_delta:+.2f})")

    # Consecutive attack bursts
    consec_count = int(round(s_consec * 10))
    if consec_count >= 3:
        factors.append(f"Persistent attack burst detected ({consec_count}+ consecutive elevated flows)")

    # Destination criticality
    if s_crit > 0.5:
        factors.append("Destination endpoint is designated critical infrastructure (isolation strictly prohibited)")
    else:
        factors.append("Destination endpoint is standard network asset (isolation permissible if justified)")

    # Active cooldown
    cooldown_steps = int(round(s_cool * 30))
    if cooldown_steps > 0:
        factors.append(f"Endpoint active cooldown in effect ({cooldown_steps} steps remaining)")

    # Action rationale
    if enforced_action == "ISOLATE":
        factors.append("High cumulative threat density and persistent attack pattern justify complete endpoint containment")
    elif enforced_action == "RATE_LIMIT":
        factors.append("Suspicious velocity or critical infrastructure status indicates rate-limiting to preserve availability")
    elif enforced_action == "ALERT":
        factors.append("Threat score elevated but risk does not warrant disruptive traffic containment")

    return factors


def audit_card_to_markdown(card: ActionAuditCard | dict[str, Any]) -> str:
    """Format an Action Decision Audit Card as clean GitHub-style Markdown."""
    c = card.to_dict() if isinstance(card, ActionAuditCard) else card

    lines = [
        f"### Action Decision Audit Card: `{c.get('flow_id', 'UNKNOWN')}`",
        "",
        f"- **Timestamp**: `{c.get('timestamp', 'N/A')}`",
        f"- **Target Host**: `{c.get('host_id', 'N/A')}`",
        f"- **Proposed Action**: `{c.get('proposed_action', 'N/A')}`",
        f"- **Enforced Action**: `{c.get('enforced_action', 'N/A')}`",
        "",
        "#### Layer 1: Perception Explainability (TreeSHAP)",
        f"- **Detector Risk Score ($S_t$)**: `{c.get('perception_layer', {}).get('detector_score', 0.0):.4f}`",
        "- **Top Contributing Features**:",
    ]

    top_feats = c.get("perception_layer", {}).get("top_contributing_features", [])
    if top_feats:
        for f in top_feats:
            val_str = f" (Value: {f.get('feature_value', 'N/A'):.2f})" if isinstance(f.get('feature_value'), (int, float)) else ""
            lines.append(f"  - `{f.get('feature')}`: SHAP `{f.get('shap_value', 0.0):+.4f}`{val_str}")
    else:
        lines.append("  - *(No individual feature contributions logged)*")

    lines.extend([
        "",
        "#### Layer 2: Response Policy Explainability",
        "- **Action Q-Values**:",
    ])

    q_vals = c.get("policy_layer", {}).get("q_values", {})
    if q_vals:
        q_strs = [f"`{act}: {q:+.2f}`" for act, q in sorted(q_vals.items())]
        lines.append(f"  - {', '.join(q_strs)}")
    lines.append(f"- **Decision Margin**: `+{c.get('policy_layer', {}).get('decision_margin', 0.0):.2f}`")

    lines.append("- **Driving State Factors**:")
    factors = c.get("policy_layer", {}).get("driving_state_factors", [])
    for f in factors:
        lines.append(f"  - {f}")

    lines.extend([
        "",
        "#### Deterministic Safety Invariants",
        f"- **Invariants Checked**: {', '.join(f'`{inv}`' for inv in c.get('safety_gate', {}).get('invariants_checked', []))}",
        f"- **Action Overruled**: `{'YES' if c.get('safety_gate', {}).get('action_overruled') else 'NO'}`",
    ])

    if c.get("safety_gate", {}).get("action_overruled"):
        lines.append(f"- **Override Reason**: `{c.get('safety_gate', {}).get('override_reason')}`")

    lines.append("")
    return "\n".join(lines)

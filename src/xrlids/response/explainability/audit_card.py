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
    *,
    is_critical: bool = False,
) -> list[str]:
    """Generate human-readable explanations of what state factors drove policy decision.

    State dimensions (SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 4):
    0: S_t (Instantaneous detector risk score in [0, 1])
    1: ΔS_t (Score trajectory / rate-of-change in [-1, 1] relative to past 5 flows)
    2: N_alert (Recent alert density in [0, 1] over past 20 flows)
    3: a_(t-1) (Normalized previous action state in [0, 1])
    4: c_t (Remaining cooldown timer fraction in [0, 1])
    5: v_t (Normalized logarithmic volumetric throughput in [0, 1])
    """
    factors: list[str] = []
    if len(state) < 6:
        return ["State vector contains insufficient dimensions for interpretation"]

    s_curr = float(state[0])
    s_traj = float(state[1])
    s_alert = float(state[2])
    s_prev = float(state[3])
    s_cool = float(state[4])
    s_vol = float(state[5])

    # 1. Perception threat score (Dimension 0)
    if s_curr >= 0.75:
        factors.append(f"Instantaneous attack risk is severe (S_t={s_curr:.3f} >= 0.75)")
    elif s_curr >= 0.50:
        factors.append(f"Instantaneous attack risk exceeds baseline research threshold (S_t={s_curr:.3f} >= 0.50)")
    elif s_curr >= 0.40:
        factors.append(f"Instantaneous score is in stealth/suspect band (S_t={s_curr:.3f} in [0.40, 0.50])")
    else:
        factors.append(f"Instantaneous score is benign (S_t={s_curr:.3f} < 0.40)")

    # 2. Score trajectory / rate of change (Dimension 1)
    if s_traj > 0.15:
        factors.append(f"Threat velocity accelerating rapidly (rate-of-change delta={s_traj:+.2f} over 5-flow window)")
    elif s_traj < -0.15:
        factors.append(f"Threat velocity decelerating (rate-of-change delta={s_traj:+.2f} over 5-flow window)")

    # 3. Recent alert density (Dimension 2)
    if s_alert >= 0.50:
        factors.append(f"Recent alert density is elevated (N_alert={s_alert*100:.1f}% of past 20 flows >= 0.50)")
    elif s_alert >= 0.20:
        factors.append(f"Moderate sustained threat background present (N_alert={s_alert*100:.1f}%)")

    # 4. Previous action state (Dimension 3)
    # Normalized: ALLOW=0.0, ALERT=0.333, RATE_LIMIT=0.667, ISOLATE=1.0
    if s_prev >= 0.85:
        factors.append("Previous action state: ISOLATE (endpoint previously contained)")
    elif s_prev >= 0.50:
        factors.append("Previous action state: RATE_LIMIT (traffic previously throttled)")
    elif s_prev >= 0.20:
        factors.append("Previous action state: ALERT (monitoring active)")

    # 5. Remaining cooldown timer (Dimension 4)
    cooldown_steps = int(round(s_cool * 30))
    if cooldown_steps > 0:
        factors.append(f"Endpoint active cooldown in effect ({cooldown_steps} steps remaining)")

    # 6. Volumetric scale (Dimension 5)
    if s_vol >= 0.60:
        factors.append(f"Elevated flow byte volume detected (v_t={s_vol:.2f}, heavy transfer)")

    # 7. Endpoint criticality (Safety Gate context)
    if is_critical:
        factors.append("Destination endpoint is designated critical infrastructure (isolation strictly prohibited by safety gate)")
    else:
        factors.append("Destination endpoint is standard network inventory (isolation permissible if justified)")

    # 8. Action rationale
    if enforced_action == "ISOLATE":
        factors.append("High cumulative threat density and persistent attack pattern justify complete endpoint containment")
    elif enforced_action == "RATE_LIMIT":
        factors.append("Suspicious velocity or critical infrastructure status indicates rate-limiting to preserve availability")
    elif enforced_action == "ALERT":
        factors.append("Threat score elevated but risk does not warrant disruptive traffic containment")
    elif enforced_action == "ALLOW":
        factors.append("Traffic profile conforms to normal operational patterns")

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

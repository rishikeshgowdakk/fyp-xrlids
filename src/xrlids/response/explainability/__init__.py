"""Explainability engine and Action Decision Audit Card generation (Task 5 / Phase 2E).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 13:
- Layer 1: Perception Explainability (TreeSHAP attribution of detector score)
- Layer 2: Response Policy Explainability (Q-values, decision margin, driving state factors)
- Deterministic Safety Gate Invariant Audit
"""

from xrlids.response.explainability.audit_card import (
    ActionAuditCard,
    ActionAuditCardJSON,
    PerceptionLayerAttribution,
    PolicyLayerExplainability,
    SafetyGateAudit,
    audit_card_to_markdown,
    explain_state_factors,
)
from xrlids.response.explainability.auditor import AutonomousResponseAuditor

__all__ = [
    "ActionAuditCard",
    "ActionAuditCardJSON",
    "AutonomousResponseAuditor",
    "PerceptionLayerAttribution",
    "PolicyLayerExplainability",
    "SafetyGateAudit",
    "audit_card_to_markdown",
    "explain_state_factors",
]

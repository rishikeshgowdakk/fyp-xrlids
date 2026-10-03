"""Autonomous response auditor implementing Dual-Layer Explainability (Phase 2E).

Provides 100% audit coverage for all non-ALLOW interventions:
- Layer 1: TreeSHAP local attribution for the detector perception score.
- Layer 2: Q-value decomposition and driving state factor attribution for policy selection.
- Deterministic safety gate compliance logging.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import numpy as np
import shap

from xrlids.response.explainability.audit_card import (
    ActionAuditCard,
    PerceptionLayerAttribution,
    PolicyLayerExplainability,
    SafetyGateAudit,
    explain_state_factors,
)
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.types import Action, ActionSpaceMode, StepRecord


class AutonomousResponseAuditor:
    """Auditor generating dual-layer explainability records for autonomous actions."""

    def __init__(
        self,
        detector_rf_model: Any,
        feature_names: list[str],
        agent: Any,
        top_k_features: int = 3,
    ) -> None:
        """Initialize auditor with frozen detector and policy agent.

        Parameters
        ----------
        detector_rf_model: Any
            Underlying sklearn RandomForestClassifier from frozen Phase 1 detector.
        feature_names: list[str]
            Feature column names matching the detector's input dimensions.
        agent: Any
            DqnAgent instance for computing Q-values and decision margins.
        top_k_features: int
            Number of top SHAP-attributed features to include in audit card.
        """
        self.detector_rf_model = detector_rf_model
        self.feature_names = feature_names
        self.agent = agent
        self.top_k_features = top_k_features

        # Initialize TreeExplainer on frozen Random Forest
        # Use TreeExplainer for fast exact tree shap computation
        self.tree_explainer = shap.TreeExplainer(self.detector_rf_model)

    def explain_perception(
        self,
        feature_vector: np.ndarray,
        detector_score: float,
        precomputed_shap: np.ndarray | None = None,
    ) -> PerceptionLayerAttribution:
        """Compute TreeSHAP local feature attribution for a single flow."""
        feat_2d = np.atleast_2d(feature_vector)
        if precomputed_shap is not None:
            att_shap = precomputed_shap
        else:
            # Compute shap values
            shap_values = self.tree_explainer.shap_values(feat_2d)

            # For binary classification, shap_values can be (N, M, 2) or list of 2 arrays of (N, M)
            if isinstance(shap_values, list):
                # Attack class is index 1
                att_shap = shap_values[1][0]
            elif isinstance(shap_values, np.ndarray):
                if shap_values.ndim == 3:
                    att_shap = shap_values[0, :, 1]
                else:
                    att_shap = shap_values[0]
            else:
                att_shap = np.zeros(len(self.feature_names))

        # Rank features by absolute SHAP attribution
        ranked_indices = np.argsort(np.abs(att_shap))[::-1][: self.top_k_features]
        top_feats: list[dict[str, Any]] = []

        for idx in ranked_indices:
            feat_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            feat_val = float(feat_2d[0, idx]) if idx < feat_2d.shape[1] else None
            top_feats.append({
                "feature": feat_name,
                "shap_value": float(att_shap[idx]),
                "feature_value": feat_val,
            })

        return PerceptionLayerAttribution(
            detector_score=float(detector_score),
            top_contributing_features=top_feats,
        )

    def explain_policy(
        self,
        state: np.ndarray,
        enforced_action: str,
    ) -> PolicyLayerExplainability:
        """Decompose Q-values and identify driving state factors."""
        q_vals_dict = self.agent.get_q_values(state)
        # Convert keys to string names
        q_dict_str = {
            (act.name if isinstance(act, Action) else str(act)): float(val)
            for act, val in q_vals_dict.items()
        }

        # Compute margin
        margin = self.agent.get_decision_margin(state)

        # Explain state factors
        driving_factors = explain_state_factors(
            state=state,
            enforced_action=enforced_action,
            q_values=q_dict_str,
        )

        return PolicyLayerExplainability(
            q_values=q_dict_str,
            decision_margin=float(margin),
            driving_state_factors=driving_factors,
        )

    def audit_step(
        self,
        step_record: StepRecord,
        raw_features: np.ndarray | None = None,
        host_id: str | None = None,
        precomputed_shap: np.ndarray | None = None,
    ) -> ActionAuditCard:
        """Create complete ActionAuditCard for a single simulation step."""
        ts = datetime.now(timezone.utc).isoformat()
        flow_id = step_record.flow_id
        target_host = host_id or "host-standard"

        prop_act = step_record.proposed_action.name if hasattr(step_record.proposed_action, "name") else str(step_record.proposed_action)
        enf_act = step_record.enforced_action.name if hasattr(step_record.enforced_action, "name") else str(step_record.enforced_action)

        # Layer 1: Perception
        score = getattr(step_record, "attack_score", getattr(step_record, "detector_score", 0.0))
        if raw_features is not None or precomputed_shap is not None:
            feat_arr = raw_features if raw_features is not None else np.zeros(len(self.feature_names))
            perception = self.explain_perception(feat_arr, score, precomputed_shap=precomputed_shap)
        else:
            perception = PerceptionLayerAttribution(
                detector_score=score,
                top_contributing_features=[],
            )

        # Layer 2: Policy
        policy = self.explain_policy(step_record.state, enf_act)

        # Safety Gate
        safety = SafetyGateAudit(
            invariants_checked=[
                "CRITICAL_INFRASTRUCTURE_EXEMPTION",
                "MANDATORY_ACTION_COOLDOWN",
                "BLAST_RADIUS_CIRCUIT_BREAKER",
            ],
            action_overruled=step_record.overridden,
            override_reason=step_record.override_reason,
        )

        return ActionAuditCard(
            timestamp=ts,
            flow_id=flow_id,
            host_id=target_host,
            proposed_action=prop_act,
            enforced_action=enf_act,
            perception_layer=perception,
            policy_layer=policy,
            safety_gate=safety,
        )

    def audit_simulation_run(
        self,
        step_records: list[StepRecord],
        flow_features: np.ndarray | None = None,
        host_ids: list[str] | None = None,
        audit_only_interventions: bool = True,
        max_cards: int | None = None,
    ) -> tuple[list[ActionAuditCard], dict[str, Any]]:
        """Audit a complete simulation run, ensuring 100% coverage on non-ALLOW actions.

        Parameters
        ----------
        step_records: list[StepRecord]
            Log of steps from OfflineResponseSimulator.
        flow_features: np.ndarray | None
            Array of raw feature rows corresponding to each step.
        host_ids: list[str] | None
            Optional list of host IDs corresponding to each step.
        audit_only_interventions: bool
            If True, generates audit cards for all non-ALLOW enforced actions.
        max_cards: int | None
            Optional limit on persisted detailed audit cards.

        Returns
        -------
        tuple[list[ActionAuditCard], dict[str, Any]]
            (audit_cards, audit_summary_metrics)
        """
        cards: list[ActionAuditCard] = []
        total_steps = len(step_records)
        non_allow_count = 0
        overruled_count = 0
        total_margin = 0.0

        # Identify all target steps to audit
        target_step_indices: list[int] = []
        for idx, rec in enumerate(step_records):
            is_intervention = rec.enforced_action != Action.ALLOW
            if is_intervention:
                non_allow_count += 1
            if rec.overridden:
                overruled_count += 1

            if audit_only_interventions and not is_intervention:
                continue

            target_step_indices.append(idx)

        # Apply card limit if specified
        steps_to_audit = target_step_indices
        if max_cards is not None and len(steps_to_audit) > max_cards:
            steps_to_audit = steps_to_audit[:max_cards]

        # Batched TreeSHAP precomputation across all audited steps
        precomputed_shaps: dict[int, np.ndarray] = {}
        if flow_features is not None and len(steps_to_audit) > 0:
            batch_X = flow_features[steps_to_audit]
            raw_shap = self.tree_explainer.shap_values(batch_X)
            if isinstance(raw_shap, list):
                attack_shap_mat = raw_shap[1]
            elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 3:
                attack_shap_mat = raw_shap[:, :, 1]
            else:
                attack_shap_mat = np.asarray(raw_shap)

            for local_idx, step_idx in enumerate(steps_to_audit):
                precomputed_shaps[step_idx] = attack_shap_mat[local_idx]

        for idx in steps_to_audit:
            rec = step_records[idx]
            feats = flow_features[idx] if flow_features is not None and idx < len(flow_features) else None
            host = host_ids[idx] if host_ids is not None and idx < len(host_ids) else None
            p_shap = precomputed_shaps.get(idx)

            card = self.audit_step(rec, raw_features=feats, host_id=host, precomputed_shap=p_shap)
            cards.append(card)
            total_margin += card.policy_layer.decision_margin

        # Check coverage
        target_count = non_allow_count if audit_only_interventions else total_steps
        coverage_pct = 100.0 if target_count == 0 else min(100.0, (len(cards) / target_count) * 100.0)

        summary_metrics = {
            "total_steps_evaluated": total_steps,
            "non_allow_interventions_count": non_allow_count,
            "audit_cards_generated": len(cards),
            "audit_coverage_pct": float(coverage_pct),
            "safety_overrides_logged": overruled_count,
            "mean_decision_margin": float(total_margin / max(1, len(cards))),
            "rq7_3_pass": coverage_pct >= 99.99,
        }

        return cards, summary_metrics

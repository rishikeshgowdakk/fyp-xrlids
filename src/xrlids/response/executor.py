"""Autonomous Response Executor and Lifecycle Coordinator for XRL-IDARS (Priority 5).

Formalizes the 5-stage action lifecycle:
    PROPOSED -> AUTHORIZED -> EXECUTED -> VERIFIED -> EXPIRED / ROLLED_BACK

Coordinates:
1. Deterministic Safety Gate: Invariant checking, blast-radius limiting, critical-host exemptions.
2. Controlled Transaction Manager: Atomic snapshotting and rollback compensation.
3. Response Verifier: Post-action state confirmation and collateral outage protection.
4. Outcome Feedback Loop: Causal transition logging and reward calculation for offline RL.
5. Invariant: Advisory mode is enabled by default (zero real operating system mutations).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Mapping, Sequence
import time
import numpy as np

from xrlids.response.feedback import ResponseOutcomeFeedbackLoop, TransitionRecord
from xrlids.response.safety import Action, DeterministicSafetyGate, SafetyCheckResult
from xrlids.response.transaction import (
    ActuatorBackend,
    ControlledResponseTransactionManager,
    SimulatedActuatorBackend,
    TransactionState,
)
from xrlids.response.verification import ResponseVerifier, VerificationResult, VerificationStatus
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class ActionLifecycleState(str, Enum):
    """Formal lifecycle states of an autonomous response action."""

    PROPOSED = "PROPOSED"
    REJECTED = "REJECTED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass(frozen=True)
class ExecutionReport:
    """Complete auditable report for a single response execution attempt."""

    execution_id: str
    target_host: str
    proposed_action: Action
    authorized_action: Action
    final_lifecycle_state: ActionLifecycleState
    is_advisory: bool
    safety_check: SafetyCheckResult
    verification: VerificationResult
    transition: TransitionRecord | None = None
    applied_ttl_seconds: float = 0.0
    latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "target_host": self.target_host,
            "proposed_action": self.proposed_action.name if hasattr(self.proposed_action, "name") else str(self.proposed_action),
            "authorized_action": self.authorized_action.name if hasattr(self.authorized_action, "name") else str(self.authorized_action),
            "final_lifecycle_state": self.final_lifecycle_state.value,
            "is_advisory": self.is_advisory,
            "safety_check": self.safety_check.to_dict(),
            "verification": self.verification.to_dict(),
            "applied_ttl_seconds": self.applied_ttl_seconds,
            "latency_ms": round(self.latency_ms, 4),
            "timestamp": self.timestamp,
        }


class ResponseExecutor:
    """Coordinates end-to-end response lifecycle, verification, and feedback."""

    def __init__(
        self,
        safety_gate: DeterministicSafetyGate | None = None,
        actuator_backend: ActuatorBackend | None = None,
        verifier: ResponseVerifier | None = None,
        feedback_loop: ResponseOutcomeFeedbackLoop | None = None,
        advisory_mode: bool = True,
        default_ttl_seconds: float = 300.0,  # 5 minutes default mitigation TTL
    ) -> None:
        self.advisory_mode = advisory_mode
        self.default_ttl_seconds = default_ttl_seconds
        self.safety_gate = safety_gate or DeterministicSafetyGate(advisory_mode=advisory_mode)
        self.actuator_backend = actuator_backend or SimulatedActuatorBackend()
        self.verifier = verifier or ResponseVerifier(critical_hosts=self.safety_gate.critical_hosts)
        self.feedback_loop = feedback_loop or ResponseOutcomeFeedbackLoop()
        
        self.tx_manager = ControlledResponseTransactionManager(
            backend=self.actuator_backend,
            safety_gate=self.safety_gate,
            default_ttl_s=self.default_ttl_seconds,
        )

        # Active mitigations table: target_ip -> {action, expire_timestamp, execution_id}
        self.active_mitigations: dict[str, dict[str, Any]] = {}

    def execute_action(
        self,
        proposed_action: Action,
        target_host: str,
        state_before: np.ndarray | Sequence[float],
        ground_truth: int | None = None,
        metadata: Mapping[str, Any] | None = None,
        ttl_seconds: float | None = None,
    ) -> ExecutionReport:
        """Process an action through the formal lifecycle.
        
        Lifecycle progression:
        1. PROPOSED: Validate against DeterministicSafetyGate.
        2. AUTHORIZED: Passed invariants, within blast radius.
        3. EXECUTED: Dispatched to actuator transaction manager.
        4. VERIFIED: Verified via ResponseVerifier.
        """
        import uuid
        t0 = time.perf_counter()
        exec_id = f"exec-{uuid.uuid4().hex[:10]}"
        ttl = float(ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds)

        # 1. PROPOSED -> SAFETY GATE CHECK
        safety_result = self.safety_gate.check(
            action=proposed_action,
            target_host=target_host,
            current_time=time.time(),
        )

        authorized_action = safety_result.action

        # If safety gate rejected or downgraded to ALLOW with error
        if not safety_result.allowed or authorized_action == Action.ALLOW and proposed_action != Action.ALLOW:
            final_lifecycle = ActionLifecycleState.REJECTED
            verif_result = VerificationResult(
                verified=False,
                status=VerificationStatus.FAILED_CRITICAL_HOST_IMPACTED if "exempt" in safety_result.reason.lower() else VerificationStatus.FAILED_COLLATERAL_OUTAGE,
                target_host=target_host,
                action=authorized_action,
                details={"reason": safety_result.reason},
            )
            report = ExecutionReport(
                execution_id=exec_id,
                target_host=target_host,
                proposed_action=proposed_action,
                authorized_action=authorized_action,
                final_lifecycle_state=final_lifecycle,
                is_advisory=self.advisory_mode,
                safety_check=safety_result,
                verification=verif_result,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )
            return report

        # 2. AUTHORIZED -> EXECUTE VIA TRANSACTION MANAGER
        # In advisory mode, we simulate the action cleanly
        if self.advisory_mode:
            verif_result = self.verifier.verify_action(
                action=authorized_action,
                target_host=target_host,
                actuator_state=None,
                is_advisory=True,
            )
            final_lifecycle = ActionLifecycleState.VERIFIED
            if authorized_action in (Action.RATE_LIMIT, Action.ISOLATE):
                self.active_mitigations[target_host] = {
                    "action": authorized_action,
                    "expire_timestamp": time.time() + ttl,
                    "execution_id": exec_id,
                }
        else:
            # Full atomic transaction execution
            tx = self.tx_manager.begin_transaction(
                target_host=target_host,
                action=authorized_action,
            )
            if tx.state == TransactionState.COMMITTED:
                verif_result = self.verifier.verify_action(
                    action=authorized_action,
                    target_host=target_host,
                    actuator_state=self.actuator_backend.inspect_state(),
                    is_advisory=False,
                )
                final_lifecycle = ActionLifecycleState.VERIFIED if verif_result.verified else ActionLifecycleState.ROLLED_BACK
                if verif_result.verified and authorized_action in (Action.RATE_LIMIT, Action.ISOLATE):
                    self.active_mitigations[target_host] = {
                        "action": authorized_action,
                        "expire_timestamp": time.time() + ttl,
                        "execution_id": exec_id,
                    }
            else:
                verif_result = VerificationResult(
                    verified=False,
                    status=VerificationStatus.FAILED_EFFECT_NOT_OBSERVED,
                    target_host=target_host,
                    action=authorized_action,
                    details={"tx_state": tx.state.value, "tx_errors": tx.errors},
                )
                final_lifecycle = ActionLifecycleState.ROLLED_BACK

        # 3. VERIFIED -> OUTCOME FEEDBACK LOOP RECORDING
        # Approximate post-action state s_{t+1} (risk reduced if mitigated)
        s_arr = np.asarray(state_before, dtype=float).copy()
        if len(s_arr) >= 6:
            if authorized_action in (Action.RATE_LIMIT, Action.ISOLATE) and verif_result.verified:
                s_arr[0] = max(0.0, s_arr[0] * 0.2)  # Risk drops significantly upon containment
                s_arr[1] = -0.5  # Negative trajectory
                s_arr[4] = 1.0   # Action in active cooldown

        transition = self.feedback_loop.record_transition(
            target_host=target_host,
            state_before=state_before,
            action=authorized_action,
            state_after=s_arr,
            verified=verif_result.verified,
            ground_truth=ground_truth,
            metadata=metadata,
        )

        report = ExecutionReport(
            execution_id=exec_id,
            target_host=target_host,
            proposed_action=proposed_action,
            authorized_action=authorized_action,
            final_lifecycle_state=final_lifecycle,
            is_advisory=self.advisory_mode,
            safety_check=safety_result,
            verification=verif_result,
            transition=transition,
            applied_ttl_seconds=ttl,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return report

    def check_expirations(self, current_time: float | None = None) -> list[str]:
        """Expire mitigations whose TTL has elapsed, restoring normal network state."""
        now = time.time() if current_time is None else float(current_time)
        expired_hosts = []
        for host, meta in list(self.active_mitigations.items()):
            if now >= meta["expire_timestamp"]:
                expired_hosts.append(host)
                del self.active_mitigations[host]
                logger.info("Mitigation for %s has expired (TTL elapsed). Restored to ALLOW.", host)
        return expired_hosts

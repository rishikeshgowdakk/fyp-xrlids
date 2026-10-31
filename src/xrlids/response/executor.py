"""Autonomous Response Executor and Lifecycle Coordinator for XRL-IDARS.

Formalizes the 5-stage action lifecycle:
    PROPOSED -> AUTHORIZED -> EXECUTED -> VERIFIED -> EXPIRED / ROLLED_BACK

Coordinates:
1. Deterministic Safety Gate: Invariant checking, blast-radius limiting, critical-host exemptions.
2. Lab Firewall Manager: Strict lab-subnet allowlisting (10.200.1.0/24), temporary rules,
   real enforcement enablement, packet counters, and verified traffic blocking/restoration.
3. Controlled Transaction Manager: Atomic snapshotting and rollback compensation.
4. Response Verifier: Post-action state confirmation and collateral outage protection.
5. Outcome Feedback Loop: Causal transition logging and reward calculation for offline RL.
6. Invariants:
   - Default dry-run mode (zero OS mutations without explicit operator enablement).
   - Never silently turn ALERT into ISOLATE.
   - Never claim BLOCKED merely because DQN proposed ISOLATE. Only display BLOCKED after
     actual firewall enforcement and verification.
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
from xrlids.response.firewall import FirewallRuleRecord, LabFirewallManager
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
    firewall_rule: dict[str, Any] | None = None
    traffic_verification: dict[str, Any] | None = None
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
            "firewall_rule": self.firewall_rule,
            "traffic_verification": self.traffic_verification,
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
        firewall_manager: LabFirewallManager | None = None,
        advisory_mode: bool = True,
        default_ttl_seconds: float = 30.0,
    ) -> None:
        self.advisory_mode = advisory_mode
        self.default_ttl_seconds = default_ttl_seconds
        self.safety_gate = safety_gate or DeterministicSafetyGate(advisory_mode=advisory_mode)
        self.actuator_backend = actuator_backend or SimulatedActuatorBackend()
        self.verifier = verifier or ResponseVerifier(critical_hosts=self.safety_gate.critical_hosts)
        self.feedback_loop = feedback_loop or ResponseOutcomeFeedbackLoop()
        self.firewall_manager = firewall_manager or LabFirewallManager(
            enforcement_enabled=not advisory_mode,
            default_ttl_seconds=self.default_ttl_seconds,
        )

        self.tx_manager = ControlledResponseTransactionManager(
            backend=self.actuator_backend,
            safety_gate=self.safety_gate,
            default_ttl_s=self.default_ttl_seconds,
        )

        # Active mitigations table: target_ip -> {action, expire_timestamp, execution_id}
        self.active_mitigations: dict[str, dict[str, Any]] = {}

    def set_enforcement_mode(self, enabled: bool) -> None:
        """Toggle real firewall enforcement mode."""
        self.advisory_mode = not enabled
        if enabled:
            self.firewall_manager.enable_enforcement()
        else:
            self.firewall_manager.disable_enforcement()

    def execute_action(
        self,
        proposed_action: Action,
        target_host: str,
        state_before: np.ndarray | Sequence[float],
        dest_host: str = "10.200.1.3",
        ground_truth: int | None = None,
        metadata: Mapping[str, Any] | None = None,
        ttl_seconds: float | None = None,
        step: int | None = None,
    ) -> ExecutionReport:
        """Process an action through the formal lifecycle.

        Lifecycle progression:
        1. PROPOSED: Validate against DeterministicSafetyGate.
        2. AUTHORIZED: Passed invariants, within blast radius. (Never turn ALERT into ISOLATE).
        3. EXECUTED: Dispatched to firewall manager / actuator transaction manager.
        4. VERIFIED: Verified via ResponseVerifier and traffic block probes.
        """
        import uuid
        t0 = time.perf_counter()
        exec_id = f"exec-{uuid.uuid4().hex[:10]}"
        if ttl_seconds is not None:
            ttl = float(ttl_seconds)
        elif self.firewall_manager is not None:
            ttl = float(self.firewall_manager.default_ttl_seconds)
        else:
            ttl = float(self.default_ttl_seconds)

        # 1. PROPOSED -> SAFETY GATE CHECK
        curr_time = float(step) if step is not None else time.time()
        safety_result = self.safety_gate.check(
            action=proposed_action,
            target_host=target_host,
            current_time=curr_time,
        )

        authorized_action = safety_result.action

        # INVARIANT: Never silently escalate ALERT to ISOLATE
        if proposed_action == Action.ALERT and authorized_action == Action.ISOLATE:
            authorized_action = Action.ALERT

        # If safety gate rejected or downgraded to ALLOW with error
        if not safety_result.allowed or (authorized_action == Action.ALLOW and proposed_action != Action.ALLOW):
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

        # 2. AUTHORIZED -> EXECUTE VIA FIREWALL MANAGER & TRANSACTION MANAGER
        fw_rule_record: FirewallRuleRecord | None = None
        traffic_verif: dict[str, Any] | None = None

        if authorized_action in (Action.ISOLATE, Action.RATE_LIMIT):
            # Apply through firewall manager
            fw_rule_record = self.firewall_manager.install_rule(
                source_ip=target_host,
                dest_ip=dest_host,
                action=authorized_action,
                ttl_seconds=ttl,
            )

            if not self.advisory_mode and self.firewall_manager.enforcement_enabled:
                if fw_rule_record.status == "FAILED":
                    # Kernel firewall mutation failed
                    err_msg = fw_rule_record.verification_details.get("error", "Firewall installation failed")
                    verif_result = VerificationResult(
                        verified=False,
                        status=VerificationStatus.FAILED_EFFECT_NOT_OBSERVED,
                        target_host=target_host,
                        action=authorized_action,
                        latency_ms=(time.perf_counter() - t0) * 1000.0,
                        details={
                            "rule_id": fw_rule_record.rule_id,
                            "status": "FAILED",
                            "error": err_msg,
                            "kernel_applied": False,
                        },
                    )
                    final_lifecycle = ActionLifecycleState.REJECTED
                    traffic_verif = {
                        "source_ip": target_host,
                        "dest_ip": dest_host,
                        "is_blocked": False,
                        "status": "FAILED_INSTALLATION",
                        "error": err_msg,
                    }
                else:
                    # Active enforcement mode: verify traffic block
                    traffic_verif = self.firewall_manager.verify_traffic_blocked(
                        source_ip=target_host,
                        dest_ip=dest_host,
                    )
                    is_tr_blocked = bool(traffic_verif.get("is_blocked", False))
                    verif_result = VerificationResult(
                        verified=is_tr_blocked,
                        status=VerificationStatus.VERIFIED if is_tr_blocked else VerificationStatus.FAILED_EFFECT_NOT_OBSERVED,
                        target_host=target_host,
                        action=authorized_action,
                        latency_ms=(time.perf_counter() - t0) * 1000.0,
                        details={
                            "rule_id": fw_rule_record.rule_id,
                            "status": "BLOCKED" if is_tr_blocked else "NOT_BLOCKED",
                            "kernel_applied": fw_rule_record.kernel_rule_applied,
                            "traffic_verification": traffic_verif,
                        },
                    )
                    final_lifecycle = ActionLifecycleState.VERIFIED if is_tr_blocked else ActionLifecycleState.REJECTED
                    if is_tr_blocked:
                        self.active_mitigations[target_host] = {
                            "action": authorized_action,
                            "expire_timestamp": time.time() + ttl,
                            "execution_id": exec_id,
                            "rule_id": fw_rule_record.rule_id,
                        }
            else:
                # Advisory / Dry-run mode: do not claim BLOCKED
                verif_result = self.verifier.verify_action(
                    action=authorized_action,
                    target_host=target_host,
                    actuator_state=None,
                    is_advisory=True,
                )
                final_lifecycle = ActionLifecycleState.VERIFIED
                self.active_mitigations[target_host] = {
                    "action": authorized_action,
                    "expire_timestamp": time.time() + ttl,
                    "execution_id": exec_id,
                    "mode": "DRY_RUN",
                }
        else:
            # ALLOW or ALERT: Non-disruptive, no firewall drop rule installed
            verif_result = self.verifier.verify_action(
                action=authorized_action,
                target_host=target_host,
                actuator_state=None,
                is_advisory=True,
            )
            final_lifecycle = ActionLifecycleState.VERIFIED

        # 3. VERIFIED -> OUTCOME FEEDBACK LOOP RECORDING
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
            is_advisory=self.advisory_mode or not self.firewall_manager.enforcement_enabled,
            safety_check=safety_result,
            verification=verif_result,
            firewall_rule=fw_rule_record.to_dict() if fw_rule_record else None,
            traffic_verification=traffic_verif,
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

        # Also expire rules in firewall manager
        self.firewall_manager.check_expirations()
        return expired_hosts

    def rollback_rule(self, source_ip_or_rule_id: str) -> tuple[bool, str, dict[str, Any]]:
        """Rollback an active firewall rule and verify restored connectivity."""
        self.active_mitigations.pop(source_ip_or_rule_id, None)
        return self.firewall_manager.rollback_rule(source_ip_or_rule_id)

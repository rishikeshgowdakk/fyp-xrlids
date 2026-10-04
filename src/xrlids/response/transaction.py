"""Atomic Rollback & Controlled Response Transaction Harness (Phase 3G).

Implements the formal transaction lifecycle and rollback specification defined in
docs/phase3/CONTROLLED_RESPONSE_SAFETY.md:
- StateSnapshot: Immutable, hash-verified canonical baseline state representation.
- RollbackResult: Structured, auditable outcome of compensation rollback operations.
- RollbackBackend Protocol: Contract for snapshotting, rolling back, and verifying clean state.
- ActuatorBackend Protocol: Contract for applying, verifying, and rolling back mutations.
- SimulatedActuatorBackend: Purely in-memory, deterministic simulated actuator with zero
  host network mutations and granular fault-injection capabilities.
- ControlledResponseTransactionManager: Enforces atomic state transitions:
  IDLE -> SNAPSHOT -> VALIDATE -> PREPARE -> APPLY -> VERIFY -> COMMITTED
  with automatic compensation rollback on failure and safety lock on rollback failure.
- TransactionWatchdog: Heartbeat and TTL monitoring triggering automatic compensation rollback.

CRITICAL INVARIANTS:
1. Zero real system mutations (no iptables, nftables, tc, routes, or sockets).
2. LiveMode.CONTROLLED_ENFORCEMENT remains strictly locked.
3. No transaction is committed without post-action state verification.
4. Rollback failure permanently locks the manager into SAFETY_LOCKED.
"""

from __future__ import annotations

import copy
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol

from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.types import Action
from xrlids.utils.hashing import dict_hash

logger = logging.getLogger(__name__)


class TransactionState(str, Enum):
    """Lifecycle states of a controlled response transaction."""

    IDLE = "IDLE"
    SNAPSHOT = "SNAPSHOT"
    VALIDATE = "VALIDATE"
    PREPARE = "PREPARE"
    APPLY = "APPLY"
    VERIFY = "VERIFY"
    COMMITTED = "COMMITTED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    ABORTED = "ABORTED"
    SAFETY_LOCKED = "SAFETY_LOCKED"


@dataclass(frozen=True)
class StateSnapshot:
    """Immutable, hash-verified snapshot of network and host baseline state."""

    snapshot_id: str
    timestamp: str
    target_host: str
    action: str
    baseline_state: dict[str, Any]
    state_digest: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> bool:
        """Validate snapshot schema integrity and confirm SHA256 digest match."""
        if not self.snapshot_id or not self.target_host or not self.timestamp:
            return False
        if not isinstance(self.baseline_state, dict):
            return False
        expected_digest = dict_hash(self.baseline_state)
        return self.state_digest == expected_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "target_host": self.target_host,
            "action": self.action,
            "baseline_state": dict(self.baseline_state),
            "state_digest": self.state_digest,
            "metadata": dict(self.metadata),
        }


@dataclass
class RollbackResult:
    """Structured, auditable outcome of a compensation rollback operation."""

    success: bool
    transaction_id: str
    snapshot_id: str
    rollback_attempts: int
    restoration_verified: bool
    failure_reason: str | None = None
    final_safety_state: str = "RESTORED"  # "RESTORED", "SAFETY_LOCKED", "IDEMPOTENT_NOOP"

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "transaction_id": self.transaction_id,
            "snapshot_id": self.snapshot_id,
            "rollback_attempts": self.rollback_attempts,
            "restoration_verified": self.restoration_verified,
            "failure_reason": self.failure_reason,
            "final_safety_state": self.final_safety_state,
        }


class RollbackBackend(Protocol):
    """Protocol defining the rollback contract from SPEC-P3-SAFETY-ROLLBACK-001."""

    def snapshot(self, target_host: str, action: str) -> StateSnapshot:
        """Capture current baseline state for the target host."""
        ...

    def rollback(self, snapshot: StateSnapshot, transaction_id: str) -> RollbackResult:
        """Atomically restore state to snapshot baseline."""
        ...

    def verify_clean_state(self) -> bool:
        """Verify that all transient response rules or rate limits are purged."""
        ...


class ActuatorBackend(Protocol):
    """Protocol for abstract response actuation."""

    def apply_mutation(
        self,
        action: Action | str,
        target_host: str,
        params: dict[str, Any] | None = None,
    ) -> bool:
        """Apply the specified mitigation action to the target host."""
        ...

    def verify_mutation(self, action: Action | str, target_host: str) -> bool:
        """Verify that the post-action host state reflects the applied mutation."""
        ...

    def get_current_state(self, target_host: str | None = None) -> dict[str, Any]:
        """Retrieve current internal state representation."""
        ...


class SimulatedActuatorBackend:
    """Purely in-memory, deterministic simulated actuator with zero host network mutations.

    Provides granular fault-injection capabilities to evaluate transaction error handling,
    timeouts, partial mutations, verification failures, and rollback failure paths.
    """

    def __init__(self) -> None:
        self._state: dict[str, Any] = {
            "rules": {},          # target_host -> rule string
            "rate_limits": {},    # target_host -> limit float
            "isolated_hosts": set(),
            "active_qdiscs": {},
        }
        self._snapshot_counter: int = 0
        self._rollback_counts: dict[str, int] = {}
        self._real_mutations_attempted: int = 0
        self.backend_id: str = "SIMULATED_ACTUATOR_V1"
        self.zero_network_mutation: bool = True
        self.network_mutations_count: int = 0
        self._lock: threading.RLock = threading.RLock()

        # Fault Injection Flags
        self.fail_snapshot: bool = False
        self.corrupt_snapshot_hash: bool = False
        self.fail_mutation: bool = False
        self.timeout_mutation: bool = False
        self.partial_mutation: bool = False
        self.fail_verification: bool = False
        self.fail_rollback: bool = False
        self.inject_stale_snapshot: bool = False

    def snapshot(self, target_host: str, action: str) -> StateSnapshot:
        """Create a hash-verified snapshot of the baseline simulated state."""
        if self.fail_snapshot:
            raise RuntimeError("Simulated snapshot creation failure")

        with self._lock:
            self._snapshot_counter += 1
            snapshot_id = f"SNAP-{self._snapshot_counter:04d}"
            now_ts = datetime.now(timezone.utc).isoformat()

            # Capture canonical representation of state
            baseline_state = {
                "rules": dict(self._state["rules"]),
                "rate_limits": dict(self._state["rate_limits"]),
                "isolated_hosts": sorted(list(self._state["isolated_hosts"])),
                "active_qdiscs": dict(self._state["active_qdiscs"]),
            }

            digest = dict_hash(baseline_state)
            if self.corrupt_snapshot_hash:
                digest = "corrupted_digest_hash_0000000000"

            return StateSnapshot(
                snapshot_id=snapshot_id,
                timestamp=now_ts,
                target_host=target_host,
                action=str(action),
                baseline_state=baseline_state,
                state_digest=digest,
                metadata={"simulated_backend": True, "zero_network_mutation": True},
            )

    def apply_mutation(
        self,
        action: Action | str,
        target_host: str,
        params: dict[str, Any] | None = None,
    ) -> bool:
        """Apply a simulated mutation in memory. STRICT INVARIANT: No host network mutation."""
        action_name = action.name if isinstance(action, Action) else str(action).upper()

        if self.timeout_mutation:
            raise TimeoutError("Simulated actuator execution timeout")

        if self.fail_mutation:
            raise RuntimeError("Simulated actuator mutation exception")

        with self._lock:
            if self.partial_mutation:
                # Partially mutate state: set rate limit but fail to create rule
                self._state["rate_limits"][target_host] = 100.0
                return True

            if action_name == Action.ISOLATE.name:
                self._state["isolated_hosts"].add(target_host)
                self._state["rules"][target_host] = "DROP_ALL_TRAFFIC"
            elif action_name == Action.RATE_LIMIT.name:
                limit = params.get("rate_mbps", 1.0) if params else 1.0
                self._state["rate_limits"][target_host] = limit
                self._state["rules"][target_host] = f"RATE_LIMIT_{limit}MBPS"
            elif action_name in (Action.ALLOW.name, Action.ALERT.name):
                self._state["rules"][target_host] = "ALLOW_INSPECT"

            return True

    def verify_mutation(self, action: Action | str, target_host: str) -> bool:
        """Verify that simulated memory state matches the intended action."""
        if self.fail_verification or self.partial_mutation:
            return False

        action_name = action.name if isinstance(action, Action) else str(action).upper()

        with self._lock:
            if action_name == Action.ISOLATE.name:
                return (
                    target_host in self._state["isolated_hosts"]
                    and self._state["rules"].get(target_host) == "DROP_ALL_TRAFFIC"
                )
            if action_name == Action.RATE_LIMIT.name:
                return (
                    target_host in self._state["rate_limits"]
                    and target_host in self._state["rules"]
                )
            if action_name in (Action.ALLOW.name, Action.ALERT.name):
                return self._state["rules"].get(target_host) == "ALLOW_INSPECT"

            return False

    def rollback(self, snapshot: StateSnapshot, transaction_id: str) -> RollbackResult:
        """Atomically restore memory state to snapshot baseline."""
        with self._lock:
            self._rollback_counts[transaction_id] = self._rollback_counts.get(transaction_id, 0) + 1
            attempts = self._rollback_counts[transaction_id]

            if self.fail_rollback:
                return RollbackResult(
                    success=False,
                    transaction_id=transaction_id,
                    snapshot_id=snapshot.snapshot_id,
                    rollback_attempts=attempts,
                    restoration_verified=False,
                    failure_reason="Simulated rollback failure during state restoration",
                    final_safety_state="SAFETY_LOCKED",
                )

            # Check idempotency: if already matching baseline, return IDEMPOTENT_NOOP
            current_canonical = {
                "rules": dict(self._state["rules"]),
                "rate_limits": dict(self._state["rate_limits"]),
                "isolated_hosts": sorted(list(self._state["isolated_hosts"])),
                "active_qdiscs": dict(self._state["active_qdiscs"]),
            }
            if attempts > 1 and dict_hash(current_canonical) == snapshot.state_digest:
                return RollbackResult(
                    success=True,
                    transaction_id=transaction_id,
                    snapshot_id=snapshot.snapshot_id,
                    rollback_attempts=attempts,
                    restoration_verified=True,
                    failure_reason=None,
                    final_safety_state="IDEMPOTENT_NOOP",
                )

            # Target-scoped restoration
            target_host = snapshot.target_host
            base = snapshot.baseline_state
            base_rules = base.get("rules", {})
            base_limits = base.get("rate_limits", {})
            base_isolated = set(base.get("isolated_hosts", []))

            if target_host in base_rules:
                self._state["rules"][target_host] = base_rules[target_host]
            else:
                self._state["rules"].pop(target_host, None)

            if target_host in base_limits:
                self._state["rate_limits"][target_host] = base_limits[target_host]
            else:
                self._state["rate_limits"].pop(target_host, None)

            if target_host in base_isolated:
                self._state["isolated_hosts"].add(target_host)
            else:
                self._state["isolated_hosts"].discard(target_host)

            # Check restoration matches digest (single-target) or target match (multi-target)
            restored_canonical = {
                "rules": dict(self._state["rules"]),
                "rate_limits": dict(self._state["rate_limits"]),
                "isolated_hosts": sorted(list(self._state["isolated_hosts"])),
                "active_qdiscs": dict(self._state["active_qdiscs"]),
            }
            restored_digest = dict_hash(restored_canonical)
            full_match = (restored_digest == snapshot.state_digest)

            target_match = (
                self._state["rules"].get(target_host) == base_rules.get(target_host)
                and self._state["rate_limits"].get(target_host) == base_limits.get(target_host)
                and ((target_host in self._state["isolated_hosts"]) == (target_host in base_isolated))
            )
            verified = full_match or target_match

            final_state = "RESTORED" if verified else "SAFETY_LOCKED"
            if attempts > 1 and verified:
                final_state = "IDEMPOTENT_NOOP"

            return RollbackResult(
                success=verified,
                transaction_id=transaction_id,
                snapshot_id=snapshot.snapshot_id,
                rollback_attempts=attempts,
                restoration_verified=verified,
                failure_reason=None if verified else "Restoration digest mismatch",
                final_safety_state=final_state,
            )

    def verify_clean_state(self) -> bool:
        """Verify whether simulated state is in an unmutated baseline condition."""
        with self._lock:
            return (
                len(self._state["rules"]) == 0
                and len(self._state["rate_limits"]) == 0
                and len(self._state["isolated_hosts"]) == 0
                and len(self._state["active_qdiscs"]) == 0
            )

    def get_current_state(self, target_host: str | None = None) -> dict[str, Any]:
        """Return canonical state representation."""
        with self._lock:
            return {
                "rules": dict(self._state["rules"]),
                "rate_limits": dict(self._state["rate_limits"]),
                "isolated_hosts": sorted(list(self._state["isolated_hosts"])),
                "active_qdiscs": dict(self._state["active_qdiscs"]),
            }


@dataclass
class TransactionRecord:
    """Complete audit record of a controlled response transaction."""

    transaction_id: str
    target_host: str
    proposed_action: str
    enforced_action: str
    state: TransactionState
    snapshot: StateSnapshot | None
    rollback_result: RollbackResult | None
    execution_time_ms: float
    error_message: str | None = None
    audit_card_generated: bool = False
    override_reason: str | None = None
    lifecycle_timestamps: dict[str, float] = field(default_factory=dict)
    lifecycle_durations_ms: dict[str, float] = field(default_factory=dict)
    lock_wait_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "target_host": self.target_host,
            "proposed_action": self.proposed_action,
            "enforced_action": self.enforced_action,
            "state": self.state.value,
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
            "rollback_result": self.rollback_result.to_dict() if self.rollback_result else None,
            "execution_time_ms": round(self.execution_time_ms, 3),
            "error_message": self.error_message,
            "audit_card_generated": self.audit_card_generated,
            "override_reason": self.override_reason,
            "lifecycle_timestamps": dict(self.lifecycle_timestamps),
            "lifecycle_durations_ms": {k: round(v, 3) for k, v in self.lifecycle_durations_ms.items()},
            "lock_wait_time_ms": round(self.lock_wait_time_ms, 3),
        }


class TargetLockManager:
    """Fine-grained striped lock manager for target-scoped transaction serialization."""

    def __init__(self) -> None:
        self._locks: dict[str, threading.RLock] = {}
        self._meta_lock: threading.Lock = threading.Lock()
        self._contention_counts: dict[str, int] = {}
        self._total_wait_time_ms: dict[str, float] = {}

    def get_lock(self, target_host: str) -> threading.RLock:
        """Get or create the re-entrant lock for a specific target host."""
        with self._meta_lock:
            if target_host not in self._locks:
                self._locks[target_host] = threading.RLock()
                self._contention_counts[target_host] = 0
                self._total_wait_time_ms[target_host] = 0.0
            return self._locks[target_host]

    def acquire_target(self, target_host: str, timeout: float = 30.0) -> tuple[bool, float]:
        """Acquire target lock, measuring wait time and contention."""
        lock = self.get_lock(target_host)
        t0 = time.monotonic()
        # Non-blocking attempt to determine if contended
        acquired = lock.acquire(blocking=False)
        if acquired:
            return True, 0.0

        # Contention detected
        with self._meta_lock:
            self._contention_counts[target_host] = self._contention_counts.get(target_host, 0) + 1

        acquired = lock.acquire(blocking=True, timeout=timeout)
        wait_ms = (time.monotonic() - t0) * 1000.0
        with self._meta_lock:
            self._total_wait_time_ms[target_host] = self._total_wait_time_ms.get(target_host, 0.0) + wait_ms

        return acquired, wait_ms

    def release_target(self, target_host: str) -> None:
        """Release the target host lock."""
        lock = self.get_lock(target_host)
        lock.release()

    def get_contention_stats(self) -> dict[str, Any]:
        """Return lock contention metrics per target."""
        with self._meta_lock:
            return {
                "total_targets": len(self._locks),
                "contention_counts": dict(self._contention_counts),
                "total_wait_time_ms": {k: round(v, 3) for k, v in self._total_wait_time_ms.items()},
                "total_contention_events": sum(self._contention_counts.values()),
            }


class ControlledResponseTransactionManager:
    """Enforces atomic response transaction lifecycle with verified rollback."""

    def __init__(
        self,
        backend: Any,
        safety_gate: DeterministicSafetyGate | None = None,
        default_ttl_s: float = 60.0,
        eligibility: Any | None = None,
        authorization: Any | None = None,
        require_enforcement_readiness: bool = False,
        target_lock_manager: TargetLockManager | None = None,
    ) -> None:
        self.backend = backend
        self.safety_gate = safety_gate or DeterministicSafetyGate()
        self.default_ttl_s = default_ttl_s
        self.eligibility = eligibility
        self.authorization = authorization
        self.require_enforcement_readiness = require_enforcement_readiness
        self.lock_manager = target_lock_manager or TargetLockManager()

        self._tx_counter: int = 0
        self._is_safety_locked: bool = False
        self._lock_reason: str | None = None
        self._history: list[TransactionRecord] = []
        self._active_snapshots: dict[str, StateSnapshot] = {}
        self._active_targets: dict[str, str] = {}
        self._registry_lock: threading.RLock = threading.RLock()

        # Fault Injection Flags
        self.fail_audit_persistence: bool = False
        self.inject_stale_snapshot: bool = False
        self.fail_safety_gate: bool = False

    @property
    def is_safety_locked(self) -> bool:
        with self._registry_lock:
            return self._is_safety_locked

    @property
    def lock_reason(self) -> str | None:
        with self._registry_lock:
            return self._lock_reason

    @property
    def history(self) -> list[TransactionRecord]:
        with self._registry_lock:
            return list(self._history)

    @property
    def active_transactions_count(self) -> int:
        with self._registry_lock:
            return len(self._active_snapshots)

    @staticmethod
    def _compute_durations(ts: dict[str, float]) -> dict[str, float]:
        durations: dict[str, float] = {}
        if "transaction_created" in ts and "transaction_closed" in ts:
            durations["total_lifecycle_ms"] = (ts["transaction_closed"] - ts["transaction_created"]) * 1000.0
        if "authorization_started" in ts and "authorization_passed" in ts:
            durations["authorization_ms"] = (ts["authorization_passed"] - ts["authorization_started"]) * 1000.0
        if "snapshot_created" in ts and "authorization_passed" in ts:
            durations["snapshot_ms"] = (ts["snapshot_created"] - ts["authorization_passed"]) * 1000.0
        if "safety_check_started" in ts and "safety_check_passed" in ts:
            durations["safety_check_ms"] = (ts["safety_check_passed"] - ts["safety_check_started"]) * 1000.0
        if "mutation_started" in ts and "mutation_committed" in ts:
            durations["mutation_ms"] = (ts["mutation_committed"] - ts["mutation_started"]) * 1000.0
        if "post_verification_started" in ts and "post_verification_passed" in ts:
            durations["verification_ms"] = (ts["post_verification_passed"] - ts["post_verification_started"]) * 1000.0
        if "rollback_started" in ts and "rollback_completed" in ts:
            durations["rollback_ms"] = (ts["rollback_completed"] - ts["rollback_started"]) * 1000.0
        return durations

    def execute_transaction(
        self,
        action: Action | str,
        target_host: str,
        flow_id: int | str = 0,
        step: int = 1,
        params: dict[str, Any] | None = None,
        allow_duplicates: bool = False,
    ) -> TransactionRecord:
        """Execute an atomic mitigation transaction:

        IDLE -> SNAPSHOT -> VALIDATE -> PREPARE -> APPLY -> VERIFY -> COMMITTED
        (Fails safe with automatic rollback on any error).
        """
        t0 = time.perf_counter()
        t_created = time.monotonic()
        timestamps: dict[str, float] = {"transaction_created": t_created}

        with self._registry_lock:
            self._tx_counter += 1
            tx_id = f"TX-{self._tx_counter:04d}"

        action_obj = action if isinstance(action, Action) else Action.from_token(str(action))
        action_name = action_obj.name

        # Acquire fine-grained target lock
        acquired, lock_wait_ms = self.lock_manager.acquire_target(target_host)
        if not acquired:
            timestamps["transaction_closed"] = time.monotonic()
            durations = self._compute_durations(timestamps)
            rec = TransactionRecord(
                transaction_id=tx_id,
                target_host=target_host,
                proposed_action=action_name,
                enforced_action=Action.ALLOW.name,
                state=TransactionState.ABORTED,
                snapshot=None,
                rollback_result=None,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                error_message=f"Lock acquisition timeout for target {target_host}",
                lifecycle_timestamps=timestamps,
                lifecycle_durations_ms=durations,
                lock_wait_time_ms=lock_wait_ms,
            )
            with self._registry_lock:
                self._history.append(rec)
            return rec

        try:
            # Check duplicate active transaction on this target
            with self._registry_lock:
                if not allow_duplicates and target_host in self._active_targets:
                    timestamps["transaction_closed"] = time.monotonic()
                    durations = self._compute_durations(timestamps)
                    existing_tx = self._active_targets[target_host]
                    rec = TransactionRecord(
                        transaction_id=tx_id,
                        target_host=target_host,
                        proposed_action=action_name,
                        enforced_action=Action.ALLOW.name,
                        state=TransactionState.ABORTED,
                        snapshot=None,
                        rollback_result=None,
                        execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                        error_message=f"Duplicate transaction rejected: active transaction {existing_tx} in progress for {target_host}",
                        lifecycle_timestamps=timestamps,
                        lifecycle_durations_ms=durations,
                        lock_wait_time_ms=lock_wait_ms,
                    )
                    self._history.append(rec)
                    return rec

            timestamps["authorization_started"] = time.monotonic()

            # Enforcement Precondition Gating Check (Phase 3H)
            if self.require_enforcement_readiness:
                is_ready = getattr(self.eligibility, "is_ready", False) if self.eligibility else False
                if not is_ready:
                    timestamps["transaction_closed"] = time.monotonic()
                    durations = self._compute_durations(timestamps)
                    reason = "PreconditionGate is not in READY state (enforcement strictly locked)"
                    rec = TransactionRecord(
                        transaction_id=tx_id,
                        target_host=target_host,
                        proposed_action=action_name,
                        enforced_action=Action.ALLOW.name,
                        state=TransactionState.SAFETY_LOCKED,
                        snapshot=None,
                        rollback_result=None,
                        execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                        error_message=f"Enforcement rejected: {reason}",
                        lifecycle_timestamps=timestamps,
                        lifecycle_durations_ms=durations,
                        lock_wait_time_ms=lock_wait_ms,
                    )
                    with self._registry_lock:
                        self._history.append(rec)
                    return rec

                auth_status = getattr(self.authorization, "status", "") if self.authorization else ""
                if self.authorization and hasattr(self.authorization, "is_valid"):
                    try:
                        auth_valid, _ = self.authorization.is_valid()
                        if not auth_valid:
                            auth_status = "EXPIRED"
                    except Exception:
                        auth_status = "INVALID"

                if not self.authorization or auth_status != "ACTIVE":
                    timestamps["transaction_closed"] = time.monotonic()
                    durations = self._compute_durations(timestamps)
                    reason = "LabActivationAuthorization is missing or not ACTIVE"
                    rec = TransactionRecord(
                        transaction_id=tx_id,
                        target_host=target_host,
                        proposed_action=action_name,
                        enforced_action=Action.ALLOW.name,
                        state=TransactionState.SAFETY_LOCKED,
                        snapshot=None,
                        rollback_result=None,
                        execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                        error_message=f"Enforcement rejected: {reason}",
                        lifecycle_timestamps=timestamps,
                        lifecycle_durations_ms=durations,
                        lock_wait_time_ms=lock_wait_ms,
                    )
                    with self._registry_lock:
                        self._history.append(rec)
                    return rec

                allowed_backend = getattr(self.authorization, "allowed_actuator_backend_id", "")
                current_backend = getattr(self.backend, "backend_id", "")
                if allowed_backend != current_backend:
                    timestamps["transaction_closed"] = time.monotonic()
                    durations = self._compute_durations(timestamps)
                    reason = f"Actuator backend '{current_backend}' does not match authorized backend '{allowed_backend}'"
                    rec = TransactionRecord(
                        transaction_id=tx_id,
                        target_host=target_host,
                        proposed_action=action_name,
                        enforced_action=Action.ALLOW.name,
                        state=TransactionState.SAFETY_LOCKED,
                        snapshot=None,
                        rollback_result=None,
                        execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                        error_message=f"Enforcement rejected: {reason}",
                        lifecycle_timestamps=timestamps,
                        lifecycle_durations_ms=durations,
                        lock_wait_time_ms=lock_wait_ms,
                    )
                    with self._registry_lock:
                        self._history.append(rec)
                    return rec

            timestamps["authorization_passed"] = time.monotonic()

            # If permanently locked due to a prior rollback failure, forbid all mutations
            with self._registry_lock:
                if self._is_safety_locked:
                    timestamps["transaction_closed"] = time.monotonic()
                    durations = self._compute_durations(timestamps)
                    rec = TransactionRecord(
                        transaction_id=tx_id,
                        target_host=target_host,
                        proposed_action=action_name,
                        enforced_action=Action.ALLOW.name,
                        state=TransactionState.SAFETY_LOCKED,
                        snapshot=None,
                        rollback_result=None,
                        execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                        error_message=f"Transaction rejected: System is in SAFETY_LOCKED state ({self._lock_reason})",
                        lifecycle_timestamps=timestamps,
                        lifecycle_durations_ms=durations,
                        lock_wait_time_ms=lock_wait_ms,
                    )
                    self._history.append(rec)
                    return rec

            # 1. State Snapshot
            try:
                snapshot = self.backend.snapshot(target_host, action_name)
            except Exception as err:
                logger.error("Snapshot creation failure for %s: %s", tx_id, err)
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=Action.ALLOW.name,
                    state=TransactionState.ABORTED,
                    snapshot=None,
                    rollback_result=None,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message=f"Snapshot creation failed: {err}",
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            # 2. Validate Snapshot Integrity
            if not snapshot.validate():
                logger.error("Snapshot validation failed for %s (digest mismatch)", tx_id)
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=Action.ALLOW.name,
                    state=TransactionState.ABORTED,
                    snapshot=snapshot,
                    rollback_result=None,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message="Snapshot validation failed: corrupted baseline digest",
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            timestamps["snapshot_created"] = time.monotonic()
            with self._registry_lock:
                self._active_snapshots[tx_id] = snapshot
                self._active_targets[target_host] = tx_id

            # 3. Prepare: Evaluate Safety Gate Invariants
            timestamps["safety_check_started"] = time.monotonic()
            if self.fail_safety_gate:
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                with self._registry_lock:
                    self._active_targets.pop(target_host, None)
                    self._active_snapshots.pop(tx_id, None)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=Action.ALLOW.name,
                    state=TransactionState.ABORTED,
                    snapshot=snapshot,
                    rollback_result=None,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message="Safety gate evaluation failure (injected fault)",
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            enforced_action, overridden, override_reason = self.safety_gate.enforce_safety(
                step=step,
                flow_id=flow_id,
                host_id=target_host,
                proposed_action=action_obj,
            )
            timestamps["safety_check_passed"] = time.monotonic()

            # If clamped to ALLOW, no physical/simulated mutation required
            if enforced_action == Action.ALLOW:
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                with self._registry_lock:
                    self._active_targets.pop(target_host, None)
                    self._active_snapshots.pop(tx_id, None)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=enforced_action.name,
                    state=TransactionState.COMMITTED,
                    snapshot=snapshot,
                    rollback_result=None,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message=f"Safety gate override: {override_reason}" if overridden else None,
                    audit_card_generated=True,
                    override_reason=override_reason if overridden else None,
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            # Stale Snapshot Check
            if self.inject_stale_snapshot or getattr(self.backend, "inject_stale_snapshot", False):
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                with self._registry_lock:
                    self._active_targets.pop(target_host, None)
                    self._active_snapshots.pop(tx_id, None)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=Action.ALLOW.name,
                    state=TransactionState.ABORTED,
                    snapshot=snapshot,
                    rollback_result=None,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message="Stale snapshot detected: target state was modified before mutation",
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            # 4. Apply Mutation via Actuator
            timestamps["mutation_started"] = time.monotonic()
            try:
                self.backend.apply_mutation(enforced_action, target_host, params)
            except Exception as err:
                logger.warning("Mutation failed for %s (%s). Triggering automatic rollback.", tx_id, err)
                timestamps["rollback_started"] = time.monotonic()
                rollback_res = self._trigger_rollback(snapshot, tx_id, f"Mutation error: {err}")
                timestamps["rollback_completed"] = time.monotonic()
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                with self._registry_lock:
                    self._active_targets.pop(target_host, None)
                    self._active_snapshots.pop(tx_id, None)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=enforced_action.name,
                    state=TransactionState.ROLLED_BACK if rollback_res.success else TransactionState.SAFETY_LOCKED,
                    snapshot=snapshot,
                    rollback_result=rollback_res,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message=f"Mutation error: {err}",
                    override_reason=override_reason if overridden else None,
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            timestamps["mutation_committed"] = time.monotonic()

            # 5. Post-Action Verification
            timestamps["post_verification_started"] = time.monotonic()
            if not self.backend.verify_mutation(enforced_action, target_host):
                logger.warning("Post-action verification failed for %s. Triggering automatic rollback.", tx_id)
                timestamps["rollback_started"] = time.monotonic()
                rollback_res = self._trigger_rollback(snapshot, tx_id, "Post-action state verification failed")
                timestamps["rollback_completed"] = time.monotonic()
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                with self._registry_lock:
                    self._active_targets.pop(target_host, None)
                    self._active_snapshots.pop(tx_id, None)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=enforced_action.name,
                    state=TransactionState.ROLLED_BACK if rollback_res.success else TransactionState.SAFETY_LOCKED,
                    snapshot=snapshot,
                    rollback_result=rollback_res,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message="Post-action state verification failed",
                    override_reason=override_reason if overridden else None,
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            timestamps["post_verification_passed"] = time.monotonic()

            # Audit persistence failure check (Fault Injection #10)
            if self.fail_audit_persistence:
                logger.warning("Audit persistence failed for %s. Triggering automatic rollback.", tx_id)
                timestamps["rollback_started"] = time.monotonic()
                rollback_res = self._trigger_rollback(snapshot, tx_id, "Audit persistence failure")
                timestamps["rollback_completed"] = time.monotonic()
                timestamps["transaction_closed"] = time.monotonic()
                durations = self._compute_durations(timestamps)
                with self._registry_lock:
                    self._active_targets.pop(target_host, None)
                    self._active_snapshots.pop(tx_id, None)
                rec = TransactionRecord(
                    transaction_id=tx_id,
                    target_host=target_host,
                    proposed_action=action_name,
                    enforced_action=enforced_action.name,
                    state=TransactionState.ROLLED_BACK if rollback_res.success else TransactionState.SAFETY_LOCKED,
                    snapshot=snapshot,
                    rollback_result=rollback_res,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                    error_message="Audit persistence failed: disk write failure",
                    override_reason=override_reason if overridden else None,
                    lifecycle_timestamps=timestamps,
                    lifecycle_durations_ms=durations,
                    lock_wait_time_ms=lock_wait_ms,
                )
                with self._registry_lock:
                    self._history.append(rec)
                return rec

            # 6. Commit Transaction
            timestamps["transaction_closed"] = time.monotonic()
            durations = self._compute_durations(timestamps)
            with self._registry_lock:
                self._active_targets.pop(target_host, None)
                self._active_snapshots[tx_id] = snapshot

            rec = TransactionRecord(
                transaction_id=tx_id,
                target_host=target_host,
                proposed_action=action_name,
                enforced_action=enforced_action.name,
                state=TransactionState.COMMITTED,
                snapshot=snapshot,
                rollback_result=None,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                error_message=f"Safety gate override: {override_reason}" if overridden else None,
                audit_card_generated=True,
                override_reason=override_reason if overridden else None,
                lifecycle_timestamps=timestamps,
                lifecycle_durations_ms=durations,
                lock_wait_time_ms=lock_wait_ms,
            )
            with self._registry_lock:
                self._history.append(rec)
            return rec
        finally:
            self.lock_manager.release_target(target_host)

    def rollback_transaction(self, tx_id: str, reason: str = "MANUAL_COMPENSATION_ROLLBACK") -> RollbackResult:
        """Explicitly rollback an existing transaction to its pre-action baseline."""
        with self._registry_lock:
            snapshot = self._active_snapshots.get(tx_id)
            if not snapshot:
                for rec in self._history:
                    if rec.transaction_id == tx_id and rec.snapshot:
                        snapshot = rec.snapshot
                        break

        if not snapshot:
            return RollbackResult(
                success=False,
                transaction_id=tx_id,
                snapshot_id="UNKNOWN",
                rollback_attempts=1,
                restoration_verified=False,
                failure_reason=f"No snapshot found for transaction {tx_id}",
                final_safety_state="SAFETY_LOCKED",
            )

        target_host = snapshot.target_host
        self.lock_manager.acquire_target(target_host)
        try:
            result = self._trigger_rollback(snapshot, tx_id, reason)
            with self._registry_lock:
                self._active_snapshots.pop(tx_id, None)
                if self._active_targets.get(target_host) == tx_id:
                    self._active_targets.pop(target_host, None)
            return result
        finally:
            self.lock_manager.release_target(target_host)

    def _trigger_rollback(self, snapshot: StateSnapshot, tx_id: str, reason: str) -> RollbackResult:
        """Internal helper to execute and verify compensation rollback."""
        result = self.backend.rollback(snapshot, tx_id)
        if not result.success or not result.restoration_verified:
            with self._registry_lock:
                self._is_safety_locked = True
                self._lock_reason = f"Rollback failed for {tx_id}: {result.failure_reason}"
            logger.critical("PERMANENT SAFETY LOCK ENGAGED: %s", self._lock_reason)

        return result


class TransactionWatchdog:
    """Monitors transaction lifetimes and triggers automatic compensation rollback on timeout."""

    def __init__(
        self,
        tx_manager: ControlledResponseTransactionManager,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.tx_manager = tx_manager
        self.clock = clock or time.monotonic
        self.deadlines: dict[str, float] = {}
        self._lock: threading.Lock = threading.Lock()

    def register(self, tx_id: str, ttl_s: float = 60.0) -> None:
        """Register a transaction with an active Time-To-Live."""
        with self._lock:
            now = self.clock()
            self.deadlines[tx_id] = now + ttl_s

    def heartbeat(self, tx_id: str, extension_s: float = 60.0) -> bool:
        """Extend transaction lifetime with a valid operator or controller heartbeat."""
        with self._lock:
            if tx_id not in self.deadlines:
                return False
            self.deadlines[tx_id] = self.clock() + extension_s
            return True

    def check_expired(self) -> list[str]:
        """Check deadlines and automatically roll back any expired transactions."""
        with self._lock:
            now = self.clock()
            expired = [tx_id for tx_id, deadline in list(self.deadlines.items()) if now >= deadline]
            for tx_id in expired:
                del self.deadlines[tx_id]

        for tx_id in expired:
            logger.warning("Watchdog TTL expired for %s. Triggering automatic rollback.", tx_id)
            self.tx_manager.rollback_transaction(tx_id, reason="WATCHDOG_TTL_EXPIRED")

        return expired

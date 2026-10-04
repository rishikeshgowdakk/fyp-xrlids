"""Unit tests for Phase 3G Atomic Rollback & Controlled Response Transaction Harness."""

from __future__ import annotations

import pytest

from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.transaction import (
    ControlledResponseTransactionManager,
    RollbackResult,
    SimulatedActuatorBackend,
    StateSnapshot,
    TransactionRecord,
    TransactionState,
    TransactionWatchdog,
)
from xrlids.response.types import Action


def test_snapshot_generation_and_validation():
    """Verify StateSnapshot generates canonical SHA256 digest and validates integrity."""
    backend = SimulatedActuatorBackend()
    snapshot = backend.snapshot("192.168.1.50", "RATE_LIMIT")

    assert snapshot.target_host == "192.168.1.50"
    assert snapshot.action == "RATE_LIMIT"
    assert snapshot.state_digest is not None
    assert len(snapshot.state_digest) == 64
    assert snapshot.validate() is True

    # Tampered snapshot fails validation
    tampered = StateSnapshot(
        snapshot_id=snapshot.snapshot_id,
        timestamp=snapshot.timestamp,
        target_host=snapshot.target_host,
        action=snapshot.action,
        baseline_state={"tampered": True},
        state_digest=snapshot.state_digest,
    )
    assert tampered.validate() is False


def test_snapshot_corruption_aborts_transaction():
    """Verify that a corrupted baseline snapshot aborts transaction before mutation."""
    backend = SimulatedActuatorBackend()
    backend.corrupt_snapshot_hash = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.ISOLATE, "10.0.0.99")
    assert rec.state == TransactionState.ABORTED
    assert "corrupted baseline digest" in (rec.error_message or "")
    assert backend.verify_clean_state() is True


def test_snapshot_failure_prevents_mutation():
    """Verify snapshot generation error aborts transaction before mutation is attempted."""
    backend = SimulatedActuatorBackend()
    backend.fail_snapshot = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.ISOLATE, "10.0.0.99")
    assert rec.state == TransactionState.ABORTED
    assert "Snapshot creation failed" in (rec.error_message or "")
    assert backend.verify_clean_state() is True


def test_successful_transaction_commit():
    """Verify full nominal lifecycle commits when mutation and verification succeed."""
    backend = SimulatedActuatorBackend()
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.RATE_LIMIT, "192.168.1.10", params={"rate_mbps": 5.0})
    assert rec.state == TransactionState.COMMITTED
    assert rec.enforced_action == Action.RATE_LIMIT.name
    assert rec.rollback_result is None
    assert rec.audit_card_generated is True
    assert backend.verify_mutation(Action.RATE_LIMIT, "192.168.1.10") is True


def test_mutation_exception_triggers_automatic_rollback():
    """Verify mutation exceptions automatically trigger compensation rollback."""
    backend = SimulatedActuatorBackend()
    backend.fail_mutation = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.ISOLATE, "192.168.1.15")
    assert rec.state == TransactionState.ROLLED_BACK
    assert rec.rollback_result is not None
    assert rec.rollback_result.success is True
    assert rec.rollback_result.restoration_verified is True
    assert backend.verify_clean_state() is True


def test_mutation_timeout_triggers_automatic_rollback():
    """Verify actuator timeout automatically triggers compensation rollback."""
    backend = SimulatedActuatorBackend()
    backend.timeout_mutation = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.RATE_LIMIT, "192.168.1.20")
    assert rec.state == TransactionState.ROLLED_BACK
    assert rec.rollback_result is not None
    assert rec.rollback_result.success is True
    assert backend.verify_clean_state() is True


def test_partial_mutation_triggers_automatic_rollback():
    """Verify partial mutation fails verification and triggers compensation rollback."""
    backend = SimulatedActuatorBackend()
    backend.partial_mutation = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.ISOLATE, "192.168.1.25")
    assert rec.state == TransactionState.ROLLED_BACK
    assert rec.rollback_result is not None
    assert rec.rollback_result.success is True
    assert backend.verify_clean_state() is True


def test_verification_failure_triggers_automatic_rollback():
    """Verify explicit verification failure triggers compensation rollback."""
    backend = SimulatedActuatorBackend()
    backend.fail_verification = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.RATE_LIMIT, "192.168.1.30")
    assert rec.state == TransactionState.ROLLED_BACK
    assert rec.rollback_result is not None
    assert rec.rollback_result.success is True
    assert backend.verify_clean_state() is True


def test_rollback_failure_engages_safety_lock():
    """Verify failed rollback locks the manager into SAFETY_LOCKED permanently."""
    backend = SimulatedActuatorBackend()
    backend.fail_mutation = True
    backend.fail_rollback = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.ISOLATE, "192.168.1.40")
    assert rec.state == TransactionState.SAFETY_LOCKED
    assert manager.is_safety_locked is True
    assert "Rollback failed" in (manager.lock_reason or "")

    # Subsequent transactions must be immediately rejected
    rec2 = manager.execute_transaction(Action.ALLOW, "192.168.1.41")
    assert rec2.state == TransactionState.SAFETY_LOCKED
    assert "SAFETY_LOCKED" in (rec2.error_message or "")


def test_rollback_idempotency():
    """Verify repeated rollback requests on the same transaction return IDEMPOTENT_NOOP."""
    backend = SimulatedActuatorBackend()
    manager = ControlledResponseTransactionManager(backend=backend)

    # First commit a transaction
    rec = manager.execute_transaction(Action.ISOLATE, "192.168.1.55")
    assert rec.state == TransactionState.COMMITTED

    # First manual rollback
    res1 = manager.rollback_transaction(rec.transaction_id)
    assert res1.success is True
    assert res1.final_safety_state == "RESTORED"

    # Repeated rollback (idempotent)
    res2 = manager.rollback_transaction(rec.transaction_id)
    assert res2.success is True
    assert res2.final_safety_state == "IDEMPOTENT_NOOP"
    assert res2.rollback_attempts == 2


def test_transaction_watchdog_ttl_expiration_and_heartbeat():
    """Verify watchdog monitors TTL, accepts heartbeats, and triggers rollback upon timeout."""
    fake_time = 1000.0

    def mock_clock() -> float:
        return fake_time

    backend = SimulatedActuatorBackend()
    manager = ControlledResponseTransactionManager(backend=backend)
    watchdog = TransactionWatchdog(tx_manager=manager, clock=mock_clock)

    # Commit a transaction
    rec = manager.execute_transaction(Action.ISOLATE, "192.168.1.60")
    assert rec.state == TransactionState.COMMITTED
    assert backend.verify_mutation(Action.ISOLATE, "192.168.1.60") is True

    # Register with watchdog (TTL = 60s -> deadline = 1060s)
    watchdog.register(rec.transaction_id, ttl_s=60.0)

    # Advance time within TTL (at 1030s)
    fake_time = 1030.0
    expired = watchdog.check_expired()
    assert len(expired) == 0

    # Extend with heartbeat (extension = 60s -> deadline = 1090s)
    renewed = watchdog.heartbeat(rec.transaction_id, extension_s=60.0)
    assert renewed is True

    # Advance time to 1080s (still alive)
    fake_time = 1080.0
    expired = watchdog.check_expired()
    assert len(expired) == 0

    # Advance time to 1095s (expired)
    fake_time = 1095.0
    expired = watchdog.check_expired()
    assert expired == [rec.transaction_id]

    # Verify that the watchdog triggered rollback on the backend
    assert backend.verify_clean_state() is True


def test_safety_gate_allow_and_critical_host_override():
    """Verify safety gate allows safe commits and critical host overrides safely."""
    gate = DeterministicSafetyGate(critical_hosts=frozenset(["192.168.10.1"]))
    backend = SimulatedActuatorBackend()
    manager = ControlledResponseTransactionManager(backend=backend, safety_gate=gate)

    # 1. ALLOW action commits directly without mutation
    rec1 = manager.execute_transaction(Action.ALLOW, "192.168.1.70", flow_id=1, step=1)
    assert rec1.state == TransactionState.COMMITTED
    assert rec1.enforced_action == Action.ALLOW.name
    assert rec1.audit_card_generated is True
    assert backend.verify_clean_state() is True

    # 2. Critical host exemption clamps ISOLATE to ALERT
    rec2 = manager.execute_transaction(Action.ISOLATE, "192.168.10.1", flow_id=2, step=2)
    assert rec2.state == TransactionState.COMMITTED
    assert rec2.enforced_action == Action.ALERT.name
    assert "CRITICAL_INFRASTRUCTURE_EXEMPTION" in (rec2.error_message or "")


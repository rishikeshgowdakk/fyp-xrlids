"""Unit tests for Phase 3J: Multi-Flow Soak + Concurrency + Shared-State Transaction Stress."""

from __future__ import annotations

import copy
import threading
import time
from datetime import datetime, timezone
import pytest

from xrlids.enforcement.concurrency import (
    ConcurrencyHarness,
    FlowSpec,
    MultiFlowTrafficGenerator,
    SoakWorkloadConfig,
    compute_percentiles,
)
from xrlids.enforcement.gate import (
    AuthorizationStatus,
    LabActivationAuthorization,
)
from xrlids.enforcement.lab import (
    ATTACKER_IP,
    ATTACKER_NS,
    LAB_BACKEND_ID,
    LAB_ENVIRONMENT_ID,
    LAB_SUBNET,
    VICTIM_IP,
    VICTIM_NS,
    HostNetworkBaseline,
    IsolatedLabEnvironment,
    NetnsActuatorBackend,
)
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.transaction import (
    ControlledResponseTransactionManager,
    RollbackResult,
    SimulatedActuatorBackend,
    StateSnapshot,
    TargetLockManager,
    TransactionRecord,
    TransactionState,
    TransactionWatchdog,
)
from xrlids.response.types import Action


@pytest.fixture
def lab_auth() -> LabActivationAuthorization:
    """Create a valid signed authorization for Phase 3J lab tests."""
    auth = LabActivationAuthorization(
        authorization_id="AUTH-CONCURRENCY-TEST-001",
        repository_commit_sha="test_sha_3j",
        lab_environment_id=LAB_ENVIRONMENT_ID,
        allowed_actuator_backend_id=LAB_BACKEND_ID,
        scope="LAB_ISOLATED_EVALUATION",
        issued_at=datetime.now(timezone.utc).isoformat(),
        expires_at="2099-12-31T23:59:59+00:00",
        status=AuthorizationStatus.ACTIVE.value,
    )
    auth.sign()
    return auth


def test_multiflow_traffic_generator_deterministic():
    """Verify MultiFlowTrafficGenerator produces deterministic flows and packet sequences."""
    cfg = SoakWorkloadConfig(duration_seconds=5.0, total_flows=30, random_seed=42)
    gen1 = MultiFlowTrafficGenerator(cfg)
    flows1 = gen1.generate_flow_specifications()
    pkts1 = gen1.generate_packets(flows1)

    gen2 = MultiFlowTrafficGenerator(cfg)
    flows2 = gen2.generate_flow_specifications()
    pkts2 = gen2.generate_packets(flows2)

    assert len(flows1) == 30
    assert len(flows2) == 30
    assert len(pkts1) == len(pkts2)
    assert len(pkts1) > 0

    # Verify deterministic fields
    for f1, f2 in zip(flows1, flows2):
        assert f1.flow_id == f2.flow_id
        assert f1.src_port == f2.src_port
        assert f1.dst_port == f2.dst_port
        assert f1.dst_ip == f2.dst_ip
        assert f1.is_attack == f2.is_attack
        assert f1.intended_action == f2.intended_action

    # Verify IP confinement to isolated lab subnet
    for p in pkts1:
        assert p.src_ip.startswith("10.200.1.")
        assert p.dst_ip.startswith("10.200.1.")


def test_target_lock_manager_concurrency_and_contention():
    """Verify TargetLockManager allows concurrent cross-target operations while serializing same-target."""
    mgr = TargetLockManager()
    t1_host = "10.200.1.3"
    t2_host = "10.200.1.4"

    # Parallel acquisition of different targets succeeds without wait
    acq1, wait1 = mgr.acquire_target(t1_host)
    acq2, wait2 = mgr.acquire_target(t2_host)
    assert acq1 is True and wait1 == 0.0
    assert acq2 is True and wait2 == 0.0

    # Same target in another thread blocks and records contention
    contended_acquired = False
    contended_wait = 0.0

    def background_acq():
        nonlocal contended_acquired, contended_wait
        contended_acquired, contended_wait = mgr.acquire_target(t1_host, timeout=2.0)
        if contended_acquired:
            mgr.release_target(t1_host)

    th = threading.Thread(target=background_acq)
    th.start()
    time.sleep(0.05)  # Ensure background thread has entered lock attempt

    # Release primary lock so background thread unblocks
    mgr.release_target(t1_host)
    mgr.release_target(t2_host)
    th.join()

    assert contended_acquired is True
    assert contended_wait > 0.0

    stats = mgr.get_contention_stats()
    assert stats["contention_counts"][t1_host] >= 1
    assert stats["total_contention_events"] >= 1


def test_transaction_uniqueness_and_lifecycle_timestamps(lab_auth):
    """Verify transaction records receive unique IDs and complete monotonic lifecycle timestamps."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-UNIQUE-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=lab_auth)
    manager = ControlledResponseTransactionManager(backend=backend)

    r1 = manager.execute_transaction(Action.RATE_LIMIT, "10.200.1.3", flow_id=1, step=1)
    r2 = manager.execute_transaction(Action.ISOLATE, "10.200.1.4", flow_id=2, step=2)

    assert r1.transaction_id != r2.transaction_id
    assert r1.state == TransactionState.COMMITTED
    assert r2.state == TransactionState.COMMITTED

    # Verify lifecycle timestamps
    for rec in (r1, r2):
        ts = rec.lifecycle_timestamps
        assert "transaction_created" in ts
        assert "authorization_started" in ts
        assert "authorization_passed" in ts
        assert "snapshot_created" in ts
        assert "safety_check_started" in ts
        assert "safety_check_passed" in ts
        assert "mutation_started" in ts
        assert "mutation_committed" in ts
        assert "post_verification_started" in ts
        assert "post_verification_passed" in ts
        assert "transaction_closed" in ts

        dur = rec.lifecycle_durations_ms
        assert "total_lifecycle_ms" in dur
        assert dur["total_lifecycle_ms"] >= 0.0

    manager.rollback_transaction(r1.transaction_id)
    manager.rollback_transaction(r2.transaction_id)
    env.cleanup()


def test_multi_victim_state_isolation_and_rollback_ordering(lab_auth):
    """Verify that multiple targets maintain isolated state and independent rollback ordering."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-ISO-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=lab_auth)
    manager = ControlledResponseTransactionManager(backend=backend)

    v1 = "10.200.1.3"
    v2 = "10.200.1.4"

    # Mutate both victims
    rec1 = manager.execute_transaction(Action.RATE_LIMIT, v1, params={"rate_mbps": 10.0})
    rec2 = manager.execute_transaction(Action.ISOLATE, v2)

    assert rec1.state == TransactionState.COMMITTED
    assert rec2.state == TransactionState.COMMITTED
    assert backend.verify_mutation(Action.RATE_LIMIT, v1) is True
    assert backend.verify_mutation(Action.ISOLATE, v2) is True

    # Rollback victim 1 first
    rb1 = manager.rollback_transaction(rec1.transaction_id)
    assert rb1.success is True
    # Victim 1 must be clean, Victim 2 must remain isolated!
    assert backend.verify_mutation(Action.RATE_LIMIT, v1) is False
    assert backend.verify_mutation(Action.ISOLATE, v2) is True

    # Rollback victim 2
    rb2 = manager.rollback_transaction(rec2.transaction_id)
    assert rb2.success is True
    assert backend.verify_mutation(Action.ISOLATE, v2) is False
    assert backend.verify_clean_state() is True

    env.cleanup()


def test_duplicate_transaction_handling(lab_auth):
    """Verify that duplicate concurrent transactions on an active target are rejected with ABORTED."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-DUP-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=lab_auth)
    manager = ControlledResponseTransactionManager(backend=backend)

    target = "10.200.1.3"
    # Commit first transaction
    rec1 = manager.execute_transaction(Action.RATE_LIMIT, target, allow_duplicates=True)
    assert rec1.state == TransactionState.COMMITTED

    # Simulate an active transaction in progress by populating active_targets
    manager._active_targets[target] = rec1.transaction_id
    rec_dup = manager.execute_transaction(Action.RATE_LIMIT, target, allow_duplicates=False)

    assert rec_dup.state == TransactionState.ABORTED
    assert "Duplicate transaction rejected" in (rec_dup.error_message or "")

    manager._active_targets.pop(target, None)
    manager.rollback_transaction(rec1.transaction_id)
    assert backend.verify_clean_state() is True
    env.cleanup()


def test_rollback_idempotency(lab_auth):
    """Verify that repeated rollback calls on the same transaction are idempotent (IDEMPOTENT_NOOP)."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-IDEMP-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=lab_auth)
    manager = ControlledResponseTransactionManager(backend=backend)

    target = "10.200.1.3"
    rec = manager.execute_transaction(Action.RATE_LIMIT, target)
    assert rec.state == TransactionState.COMMITTED

    # First rollback restores state
    rb1 = manager.rollback_transaction(rec.transaction_id)
    assert rb1.success is True
    assert rb1.final_safety_state == "RESTORED"

    # Second rollback is an idempotent NOOP
    rb2 = manager.rollback_transaction(rec.transaction_id)
    assert rb2.success is True
    assert rb2.final_safety_state == "IDEMPOTENT_NOOP"
    assert rb2.rollback_attempts == 2

    assert backend.verify_clean_state() is True
    env.cleanup()


def test_stale_snapshot_detection_aborts_mutation(lab_auth):
    """Verify that stale snapshot detection prevents unverified mutation."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-STALE-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=lab_auth)
    manager = ControlledResponseTransactionManager(backend=backend)

    manager.inject_stale_snapshot = True
    rec = manager.execute_transaction(Action.RATE_LIMIT, "10.200.1.3")
    manager.inject_stale_snapshot = False

    assert rec.state == TransactionState.ABORTED
    assert "Stale snapshot" in (rec.error_message or "")
    assert backend.verify_clean_state() is True
    env.cleanup()


def test_watchdog_concurrent_cleanup(lab_auth):
    """Verify TransactionWatchdog safely expires and rolls back transactions concurrently."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-WATCHDOG-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=lab_auth)
    manager = ControlledResponseTransactionManager(backend=backend)
    watchdog = TransactionWatchdog(tx_manager=manager)

    r1 = manager.execute_transaction(Action.RATE_LIMIT, "10.200.1.3", allow_duplicates=True)
    r2 = manager.execute_transaction(Action.RATE_LIMIT, "10.200.1.4", allow_duplicates=True)

    watchdog.register(r1.transaction_id, ttl_s=0.01)
    watchdog.register(r2.transaction_id, ttl_s=60.0)

    time.sleep(0.02)
    expired = watchdog.check_expired()
    assert r1.transaction_id in expired
    assert r2.transaction_id not in expired

    # r1 rolled back, r2 intact
    assert backend.verify_mutation(Action.RATE_LIMIT, "10.200.1.3") is False
    assert backend.verify_mutation(Action.RATE_LIMIT, "10.200.1.4") is True

    manager.rollback_transaction(r2.transaction_id)
    assert backend.verify_clean_state() is True
    env.cleanup()


def test_rollback_failure_triggers_permanent_safety_lock(lab_auth):
    """Verify that a failed rollback locks the manager into SAFETY_LOCKED, preventing future mutations."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-LOCK-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=lab_auth)
    backend.fail_apply = True
    backend.fail_rollback = True
    manager = ControlledResponseTransactionManager(backend=backend)

    rec = manager.execute_transaction(Action.RATE_LIMIT, "10.200.1.3")
    assert rec.state == TransactionState.SAFETY_LOCKED
    assert manager.is_safety_locked is True

    # Any subsequent transaction is rejected immediately
    rec2 = manager.execute_transaction(Action.ALLOW, "10.200.1.4")
    assert rec2.state == TransactionState.SAFETY_LOCKED
    assert "SAFETY_LOCKED" in (rec2.error_message or "")

    env.cleanup()


def test_concurrency_harness_scenarios_and_failure_matrix(lab_auth):
    """Verify ConcurrencyHarness executes Scenarios A-D, soak, and the 12 failure injections."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-HARNESS-001")
    env.create()
    harness = ConcurrencyHarness(lab_env=env, authorization=lab_auth)

    # Scenario A
    res_a = harness.run_scenario_a_sequential(count=4)
    assert res_a["committed_count"] == 4
    assert res_a["clean_state_verified"] is True

    # Scenario B
    res_b = harness.run_scenario_b_two_victims(count_per_victim=2)
    assert res_b["total_records"] == 4
    assert res_b["all_rollbacks_successful"] is True

    # Scenario C
    res_c = harness.run_scenario_c_many_victims(victims=["10.200.1.3", "10.200.1.4"], count_per_victim=2, concurrency=4)
    assert res_c["all_committed"] is True
    assert res_c["clean_state_verified"] is True

    # Scenario D
    res_d = harness.run_scenario_d_overlapping_one_victim(count=4)
    assert res_d["total_transactions"] == 4
    assert res_d["clean_state_verified"] is True

    # Failure Injection Matrix (12 scenarios)
    matrix = harness.run_failure_injection_matrix()
    assert len(matrix) == 12
    assert all(sc["passed"] for sc in matrix)

    env.cleanup()


def test_host_network_immutability_under_concurrency(lab_auth):
    """Verify that concurrent multi-flow transactions cause 0 host network mutations."""
    baseline_before = HostNetworkBaseline.capture()

    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-HOST-IMMUTABILITY-001")
    env.create()
    harness = ConcurrencyHarness(lab_env=env, authorization=lab_auth)

    # Run quick soak
    cfg = SoakWorkloadConfig(duration_seconds=1.0, total_flows=10, concurrency_level=4)
    soak_res = harness.run_soak_workload(cfg)
    assert soak_res["final_clean_state"] is True

    env.cleanup()

    unmodified, diff = baseline_before.verify_unmodified()
    assert unmodified is True, f"Host network was unexpectedly modified: {diff}"
    assert diff["is_unmodified"] is True

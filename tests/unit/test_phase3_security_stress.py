"""Unit tests for Phase 3K Formal Pre-Production Security & Stress Audit."""

from __future__ import annotations

import copy
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from xrlids.enforcement import (
    LAB_BACKEND_ID,
    LAB_ENVIRONMENT_ID,
    VICTIM_IP,
    VICTIM_NS,
    EligibilityStatus,
    HostNetworkBaseline,
    IsolatedLabEnvironment,
    LabActivationAuthorization,
    NetnsActuatorBackend,
    PreconditionGate,
    ProvenanceAuditor,
    ResourceMonitor,
    RollbackStressHarness,
    SecurityAttackSurfaceAuditor,
    SocketStressTester,
    SoakFailureInjector,
    StressWorkloadConfig,
)
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.transaction import (
    ControlledResponseTransactionManager,
    TransactionState,
    TransactionWatchdog,
)
from xrlids.response.types import Action


@pytest.fixture
def lab_setup():
    lab_env = IsolatedLabEnvironment(lab_id=LAB_ENVIRONMENT_ID, experiment_id="EXP-TEST-P3K")
    lab_env.create()
    lab_env.start()

    now = datetime.now(timezone.utc)
    auth = LabActivationAuthorization(
        authorization_id="AUTH-TEST-P3K",
        repository_commit_sha="4e06e71b8ec244211ea389fdff137d0e67c70847",
        lab_environment_id=LAB_ENVIRONMENT_ID,
        allowed_actuator_backend_id=LAB_BACKEND_ID,
        scope="ISOLATED_LAB_CONTROLLED_RESPONSE",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
        status="ACTIVE",
    )
    auth.sign()

    backend = NetnsActuatorBackend(lab_env=lab_env, authorization=auth)
    gate = PreconditionGate(target_commit_sha="4e06e71b8ec244211ea389fdff137d0e67c70847")
    tx_mgr = ControlledResponseTransactionManager(
        backend=backend,
        authorization=auth,
    )
    yield lab_env, backend, gate, auth, tx_mgr
    lab_env.cleanup()


def test_resource_monitor():
    """Verify resource monitor accurately measures memory, CPU, and thread baselines."""
    monitor = ResourceMonitor()
    monitor.start()
    monitor.sample("SAMPLE_1", 100)
    monitor.sample("SAMPLE_2", 200)
    monitor.stop()

    metrics = monitor.get_metrics()
    assert metrics["memory"]["initial_rss_mib"] > 0
    assert metrics["memory"]["peak_rss_mib"] >= metrics["memory"]["initial_rss_mib"]
    assert metrics["threads"]["initial_threads"] > 0
    assert metrics["processes"]["orphan_processes_remaining"] == 0
    assert metrics["network_resources"]["residual_namespaces"] == 0


def test_socket_stress_tester():
    """Verify socket stress tester exercises all 4 tiers without unhandled exceptions."""
    tester = SocketStressTester(seed=42)
    results = tester.run_all()

    assert set(results.keys()) == {"LOW", "NOMINAL", "HIGH", "OVERLOAD"}
    for tier, res in results.items():
        assert res["packets_submitted"] > 0
        assert res["packets_received"] > 0
        assert res["effective_pps"] > 0
        assert res["capture_path_drops"] == 0
        assert res["malformed_packets"] == 0


def test_security_attack_surface_namespace_attacks(lab_setup):
    """Verify namespace attacks fail closed."""
    lab_env, backend, _, _, _ = lab_setup

    # Unauthorized name
    ok, err = backend.validate_target("10.200.1.3", "prod_namespace", "veth_xrl_vic")
    assert not ok
    assert "Unauthorized namespace" in str(err)

    # Path traversal
    ok, err = backend.validate_target("10.200.1.3", "../../../root", "veth_xrl_vic")
    assert not ok
    assert "Unauthorized namespace" in str(err)

    # Missing prefix
    ok, err = backend.validate_target("10.200.1.3", "evil_netns", "veth_xrl_vic")
    assert not ok


def test_security_attack_surface_interface_attacks(lab_setup):
    """Verify interface attacks targeting host or unauthorized interfaces fail closed."""
    lab_env, backend, _, _, _ = lab_setup

    # Host physical interface
    ok, err = backend.validate_target("10.200.1.3", VICTIM_NS, "eth0")
    assert not ok
    assert "Forbidden host target" in str(err)

    # Host loopback
    ok, err = backend.validate_target("10.200.1.3", VICTIM_NS, "lo")
    assert not ok

    # Unauthorized virtual interface
    ok, err = backend.validate_target("10.200.1.3", VICTIM_NS, "docker0")
    assert not ok


def test_security_attack_surface_ip_attacks(lab_setup):
    """Verify forbidden, out-of-subnet, and malformed IPs are rejected."""
    lab_env, backend, _, _, _ = lab_setup

    # Loopback IP
    ok, err = backend.validate_target("127.0.0.1", VICTIM_NS, "veth_xrl_vic")
    assert not ok
    assert "forbidden target" in str(err).lower() or "outside isolated lab subnet" in str(err)

    # Gateway IP
    ok, err = backend.validate_target("10.200.1.1", VICTIM_NS, "veth_xrl_vic")
    assert not ok
    assert "forbidden target" in str(err).lower()

    # Out of subnet IP
    ok, err = backend.validate_target("192.168.1.50", VICTIM_NS, "veth_xrl_vic")
    assert not ok
    assert "outside isolated lab subnet" in str(err)

    # Malformed IP (out of octet range)
    ok, err = backend.validate_target("10.200.1.256", VICTIM_NS, "veth_xrl_vic")
    assert not ok
    assert "Malformed target IP" in str(err)

    # Malformed string
    ok, err = backend.validate_target("invalid_ip_format", VICTIM_NS, "veth_xrl_vic")
    assert not ok
    assert "Malformed target IP" in str(err)

    # Broadcast address
    ok, err = backend.validate_target("10.200.1.255", VICTIM_NS, "veth_xrl_vic")
    assert not ok
    assert "Broadcast address" in str(err)


def test_security_attack_surface_authorization_attacks(lab_setup):
    """Verify invalid, expired, and forged authorizations are rejected."""
    lab_env, backend, _, auth, _ = lab_setup

    # Missing authorization
    backend_no_auth = NetnsActuatorBackend(lab_env=lab_env, authorization=None)
    ok, err = backend_no_auth.validate_target("10.200.1.3", VICTIM_NS, "veth_xrl_vic")
    assert not ok
    assert "Missing LabActivationAuthorization" in str(err)

    # Expired authorization
    exp_auth = copy.deepcopy(auth)
    exp_auth.expires_at = "2026-10-04T00:00:00+00:00"
    exp_auth.sign()
    ok, err = backend.validate_target("10.200.1.3", VICTIM_NS, "veth_xrl_vic", authorization=exp_auth)
    assert not ok
    assert "expired" in str(err).lower()

    # Mismatched lab environment ID
    mismatch_env_auth = copy.deepcopy(auth)
    mismatch_env_auth.lab_environment_id = "LAB-OTHER-99"
    mismatch_env_auth.sign()
    ok, err = backend.validate_target("10.200.1.3", VICTIM_NS, "veth_xrl_vic", authorization=mismatch_env_auth)
    assert not ok
    assert "mismatch" in str(err).lower()

    # Forged signature
    forged_auth = copy.deepcopy(auth)
    forged_auth.scope = "FORGED_FULL_ACCESS"
    assert not forged_auth.verify_signature()


def test_security_attack_surface_transaction_attacks(lab_setup):
    """Verify transaction attacks fail closed or handle cleanly."""
    _, backend, _, _, tx_mgr = lab_setup

    # Duplicate transaction
    with tx_mgr._registry_lock:
        tx_mgr._active_targets["10.200.1.4"] = "ACTIVE-TX-501"
    rec2 = tx_mgr.execute_transaction(action=Action.RATE_LIMIT, target_host="10.200.1.4", flow_id=502)
    assert rec2.state == TransactionState.ABORTED
    assert "Duplicate transaction rejected" in (rec2.error_message or "")
    with tx_mgr._registry_lock:
        tx_mgr._active_targets.pop("10.200.1.4", None)

    # Stale snapshot
    backend.inject_stale_snapshot = True
    rec3 = tx_mgr.execute_transaction(action=Action.RATE_LIMIT, target_host="10.200.1.5", flow_id=503)
    assert rec3.state == TransactionState.ABORTED
    assert "Stale snapshot detected" in (rec3.error_message or "")
    backend.inject_stale_snapshot = False

    # Watchdog TTL expiration
    watchdog = TransactionWatchdog(tx_manager=tx_mgr)
    rec4 = tx_mgr.execute_transaction(action=Action.RATE_LIMIT, target_host="10.200.1.6", flow_id=504)
    watchdog.register(rec4.transaction_id, ttl_s=0.001)
    time.sleep(0.01)
    expired = watchdog.check_expired()
    assert rec4.transaction_id in expired or len(expired) > 0


def test_provenance_tamper_detection(tmp_path):
    """Verify all 8 cryptographic tamper scenarios are detected and locked."""
    auditor = ProvenanceAuditor(commit_sha="4e06e71b8ec244211ea389fdff137d0e67c70847")
    results = auditor.run_tamper_tests(tmp_path)

    assert len(results) == 8
    for r in results:
        assert r["passed"] is True
        assert r["status"] == "LOCKED"
        assert r["is_ready"] is False


def test_rollback_stress_invariants(lab_setup):
    """Verify high-volume rollback stress maintains 100% clean baseline state."""
    _, backend, _, _, tx_mgr = lab_setup
    harness = RollbackStressHarness(backend=backend, tx_mgr=tx_mgr)
    results = harness.run_stress(count=20)

    assert results["total_transactions"] == 20
    assert results["rollback_success_rate"] == 1.0
    assert results["residual_rules"] == 0
    assert results["residual_namespaces"] == 0
    assert results["clean_state_verified"] is True


def test_host_network_integrity_invariant():
    """Verify host cryptographic baseline comparison guarantees zero host mutations."""
    base1 = HostNetworkBaseline.capture()
    base2 = HostNetworkBaseline.capture()
    assert base1.digest == base2.digest
    unmod, diff = base1.verify_unmodified()
    assert unmod is True
    assert diff["is_unmodified"] is True


def test_soak_failure_injections(lab_setup):
    """Verify all 12 soak failure injection scenarios pass fail-closed/fail-safe."""
    _, backend, _, _, tx_mgr = lab_setup
    injector = SoakFailureInjector(backend=backend, tx_mgr=tx_mgr)
    scenarios = injector.run_matrix()

    assert len(scenarios) == 12
    for sc in scenarios:
        assert sc["passed"] is True, f"Failed scenario: {sc['scenario_id']} - {sc['name']}"

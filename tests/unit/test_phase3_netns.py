"""Unit tests for Phase 3I Isolated Lab Network Namespace & Controlled Response Loop."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import pytest

from xrlids.enforcement.gate import (
    AuthorizationStatus,
    LabActivationAuthorization,
)
from xrlids.enforcement.lab import (
    ATTACKER_IP,
    ATTACKER_NS,
    FORBIDDEN_HOST_TARGETS,
    LAB_BACKEND_ID,
    LAB_ENVIRONMENT_ID,
    LAB_SUBNET,
    VETH_ATTACKER,
    VETH_VICTIM,
    VICTIM_IP,
    VICTIM_NS,
    HostNetworkBaseline,
    IsolatedLabEnvironment,
    LabResourceManifest,
    NetnsActuatorBackend,
)
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.transaction import (
    ControlledResponseTransactionManager,
    TransactionState,
)
from xrlids.response.types import Action


@pytest.fixture
def valid_lab_auth() -> LabActivationAuthorization:
    """Create a valid authorization matching the lab environment and backend."""
    auth = LabActivationAuthorization(
        authorization_id="AUTH-LAB-TEST-001",
        repository_commit_sha="test_sha_001",
        lab_environment_id=LAB_ENVIRONMENT_ID,
        allowed_actuator_backend_id=LAB_BACKEND_ID,
        scope="LAB_ISOLATED_EVALUATION",
        issued_at=datetime.now(timezone.utc).isoformat(),
        expires_at="2099-12-31T23:59:59+00:00",
        status=AuthorizationStatus.ACTIVE.value,
    )
    auth.sign()
    return auth


def test_host_network_baseline_capture_and_verify():
    """Verify that HostNetworkBaseline captures state and correctly verifies unmodified status."""
    baseline = HostNetworkBaseline.capture()
    assert baseline.timestamp is not None
    assert len(baseline.digest) == 64
    assert isinstance(baseline.interfaces, list)
    assert isinstance(baseline.routes, list)
    assert len(baseline.interfaces) > 0  # At least loopback exists

    # Verification passes when no changes
    unmodified, diff = baseline.verify_unmodified()
    assert unmodified is True
    assert diff["is_unmodified"] is True
    assert diff["interface_count_match"] is True
    assert diff["route_count_match"] is True

    # Tampered baseline detects additions/removals
    tampered_baseline = copy.deepcopy(baseline)
    tampered_baseline.interfaces.append({"name": "rogue_veth0", "index": 9999})
    tampered_baseline.digest = "tampered_digest_00000000000000000000000000"
    unmodified, diff = tampered_baseline.verify_unmodified()
    assert unmodified is False
    assert diff["is_unmodified"] is False


def test_lab_resource_manifest():
    """Verify LabResourceManifest structure and initialization."""
    manifest = LabResourceManifest(
        experiment_id="EXP-TEST-001",
        lab_environment_id=LAB_ENVIRONMENT_ID,
        namespaces=[ATTACKER_NS, VICTIM_NS],
        interfaces=[VETH_ATTACKER, VETH_VICTIM],
        addresses={VETH_ATTACKER: f"{ATTACKER_IP}/24", VETH_VICTIM: f"{VICTIM_IP}/24"},
        routes=[{"netns": ATTACKER_NS, "dst": LAB_SUBNET, "dev": VETH_ATTACKER}],
    )
    d = manifest.to_dict()
    assert d["experiment_id"] == "EXP-TEST-001"
    assert d["lab_environment_id"] == LAB_ENVIRONMENT_ID
    assert ATTACKER_NS in d["namespaces"]
    assert VICTIM_NS in d["namespaces"]
    assert d["cleanup_state"] == "PENDING"


def test_isolated_lab_environment_lifecycle():
    """Verify IsolatedLabEnvironment creation, isolation verification, inspection, and cleanup."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-LIFECYCLE-001", ttl_seconds=300)
    assert env.manifest.cleanup_state == "PENDING"

    # Creation
    created = env.create()
    assert created is True
    assert env.manifest.cleanup_state == "PENDING"

    # Isolation verification
    isolated, diagnostics = env.verify_isolation()
    assert isolated is True
    assert diagnostics["isolation_verified"] is True
    assert diagnostics["host_network_unmodified"] is True
    assert diagnostics["interface_collision"] is False
    assert diagnostics["route_collision"] is False

    # State inspection
    state = env.inspect()
    assert ATTACKER_NS in state
    assert VICTIM_NS in state

    # TTL watchdog check (active)
    expired = env.check_ttl_watchdog()
    assert expired is False

    # Cleanup idempotency
    cleaned = env.cleanup()
    assert cleaned is True
    assert env.manifest.cleanup_state == "CLEANED"
    assert env.is_active is False

    # Second cleanup is a no-op and returns True
    assert env.cleanup() is True


def test_isolated_lab_traffic_generation():
    """Verify synthetic controlled packet generation in IsolatedLabEnvironment."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-TRAFFIC-001")
    env.create()

    packets = env.generate_controlled_traffic(packet_count=50, profile="SYN_FLOOD_BURST")
    assert len(packets) == 50
    for pkt in packets:
        assert pkt.src_ip == ATTACKER_IP
        assert pkt.dst_ip == VICTIM_IP
        assert pkt.protocol == 6  # TCP
        assert pkt.syn is True or pkt.ack is True
        assert pkt.packet_length > 0

    nominal_pkts = env.generate_controlled_traffic(packet_count=20, profile="NOMINAL_TCP")
    assert len(nominal_pkts) == 20
    for pkt in nominal_pkts:
        assert pkt.src_ip in (ATTACKER_IP, VICTIM_IP)
        assert pkt.dst_ip in (ATTACKER_IP, VICTIM_IP)

    env.cleanup()


def test_netns_actuator_backend_rejects_forbidden_host_targets(valid_lab_auth):
    """Verify NetnsActuatorBackend strictly rejects host targets."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-TARGETS-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)

    for forbidden in FORBIDDEN_HOST_TARGETS:
        with pytest.raises(ValueError, match="FORBIDDEN"):
            backend.snapshot(forbidden, "RATE_LIMIT")

        with pytest.raises(ValueError, match="FORBIDDEN"):
            backend.apply_mutation("RATE_LIMIT", forbidden)

    env.cleanup()


def test_netns_actuator_backend_rejects_foreign_subnets(valid_lab_auth):
    """Verify NetnsActuatorBackend rejects targets outside the isolated lab subnet."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-SUBNET-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)

    foreign_ips = ["192.168.1.1", "172.16.0.1", "8.8.8.8", "127.0.0.1", "10.200.2.1"]
    for ip in foreign_ips:
        with pytest.raises(ValueError, match="outside isolated lab subnet"):
            backend.snapshot(ip, "RATE_LIMIT")

        with pytest.raises(ValueError, match="outside isolated lab subnet"):
            backend.apply_mutation("RATE_LIMIT", ip)

    env.cleanup()


def test_netns_actuator_backend_authorization_enforcement():
    """Verify NetnsActuatorBackend rejects operations when authorization is missing or invalid."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-AUTH-001")
    env.create()

    # Missing authorization
    backend_no_auth = NetnsActuatorBackend(lab_env=env, authorization=None)
    with pytest.raises(PermissionError, match="authorization is missing"):
        backend_no_auth.snapshot(ATTACKER_IP, "RATE_LIMIT")

    # Mismatched lab environment authorization
    mismatched_auth = LabActivationAuthorization(
        authorization_id="AUTH-WRONG-LAB",
        repository_commit_sha="test_sha",
        lab_environment_id="WRONG-LAB-ID",
        allowed_actuator_backend_id=LAB_BACKEND_ID,
        scope="LAB_ISOLATED_EVALUATION",
        issued_at=datetime.now(timezone.utc).isoformat(),
        expires_at="2099-12-31T23:59:59+00:00",
        status=AuthorizationStatus.ACTIVE.value,
    )
    backend_wrong_lab = NetnsActuatorBackend(lab_env=env, authorization=mismatched_auth)
    with pytest.raises(PermissionError, match="authorized lab mismatch"):
        backend_wrong_lab.snapshot(ATTACKER_IP, "RATE_LIMIT")

    # Expired authorization
    expired_auth = LabActivationAuthorization(
        authorization_id="AUTH-EXPIRED",
        repository_commit_sha="test_sha",
        lab_environment_id=LAB_ENVIRONMENT_ID,
        allowed_actuator_backend_id=LAB_BACKEND_ID,
        scope="LAB_ISOLATED_EVALUATION",
        issued_at="2020-01-01T00:00:00+00:00",
        expires_at="2020-01-01T01:00:00+00:00",
        status=AuthorizationStatus.ACTIVE.value,
    )
    backend_expired = NetnsActuatorBackend(lab_env=env, authorization=expired_auth)
    with pytest.raises(PermissionError, match="authorization has expired"):
        backend_expired.snapshot(ATTACKER_IP, "RATE_LIMIT")

    env.cleanup()


def test_netns_actuator_backend_mutation_and_rollback(valid_lab_auth):
    """Verify snapshot, apply_mutation, verify_mutation, rollback, and verify_clean_state."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-MUTATION-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)

    # 1. Snapshot
    snapshot = backend.snapshot(ATTACKER_IP, "RATE_LIMIT")
    assert snapshot.target_host == ATTACKER_IP
    assert snapshot.action == "RATE_LIMIT"
    assert snapshot.validate() is True

    # 2. Apply mutation
    success = backend.apply_mutation("RATE_LIMIT", ATTACKER_IP)
    assert success is True
    assert backend.verify_mutation("RATE_LIMIT", ATTACKER_IP) is True
    assert backend.verify_clean_state() is False

    # 3. Rollback
    rb_res = backend.rollback(snapshot)
    assert rb_res.success is True
    assert rb_res.failure_reason is None
    assert backend.verify_mutation("RATE_LIMIT", ATTACKER_IP) is False
    assert backend.verify_clean_state() is True

    env.cleanup()


def test_netns_actuator_transaction_manager_integration(valid_lab_auth):
    """Verify full transaction lifecycle using ControlledResponseTransactionManager and NetnsActuatorBackend."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-TX-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)
    safety_gate = DeterministicSafetyGate()
    tx_manager = ControlledResponseTransactionManager(
        backend=backend,
        safety_gate=safety_gate,
    )

    rec = tx_manager.execute_transaction(Action.RATE_LIMIT, ATTACKER_IP)
    assert rec.state == TransactionState.COMMITTED
    assert backend.verify_mutation(Action.RATE_LIMIT, ATTACKER_IP) is True
    assert backend.verify_clean_state() is False

    # Rollback transaction
    rb = tx_manager.rollback_transaction(rec.transaction_id)
    assert rb.success is True
    assert backend.verify_clean_state() is True

    env.cleanup()


def test_netns_actuator_failure_injections(valid_lab_auth):
    """Verify transaction safety under failure injections (snapshot, apply, verify, rollback)."""
    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-FAIL-001")
    env.create()

    # 1. Failure in snapshot
    backend1 = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)
    backend1.fail_snapshot = True
    tx_manager1 = ControlledResponseTransactionManager(backend=backend1)
    rec1 = tx_manager1.execute_transaction(Action.RATE_LIMIT, ATTACKER_IP)
    assert rec1.state == TransactionState.ABORTED
    assert "snapshot" in (rec1.error_message or "").lower()

    # 2. Failure in apply
    backend2 = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)
    backend2.fail_apply = True
    tx_manager2 = ControlledResponseTransactionManager(backend=backend2)
    rec2 = tx_manager2.execute_transaction(Action.RATE_LIMIT, ATTACKER_IP)
    assert rec2.state == TransactionState.ROLLED_BACK

    # 3. Failure in verify
    backend3 = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)
    backend3.fail_verify = True
    tx_manager3 = ControlledResponseTransactionManager(backend=backend3)
    rec3 = tx_manager3.execute_transaction(Action.RATE_LIMIT, ATTACKER_IP)
    assert rec3.state == TransactionState.ROLLED_BACK

    # 4. Failure in rollback triggers LOCKED state
    backend4 = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)
    backend4.fail_apply = True
    backend4.fail_rollback = True
    tx_manager4 = ControlledResponseTransactionManager(backend=backend4)
    rec4 = tx_manager4.execute_transaction(Action.RATE_LIMIT, ATTACKER_IP)
    assert rec4.state == TransactionState.SAFETY_LOCKED
    assert tx_manager4.is_safety_locked is True

    env.cleanup()


def test_end_to_end_zero_host_mutation_invariant(valid_lab_auth):
    """Verify that after full lab execution, host baseline is mathematically identical (0 mutations)."""
    baseline_before = HostNetworkBaseline.capture()

    env = IsolatedLabEnvironment(experiment_id="EXP-TEST-ZERO-MUTATION-001")
    env.create()
    backend = NetnsActuatorBackend(lab_env=env, authorization=valid_lab_auth)
    tx_manager = ControlledResponseTransactionManager(backend=backend)

    # Generate traffic and run transaction
    env.generate_controlled_traffic(packet_count=100, profile="SYN_FLOOD_BURST")
    rec = tx_manager.execute_transaction(Action.RATE_LIMIT, ATTACKER_IP)
    assert rec.state == TransactionState.COMMITTED

    # Rollback transaction
    rb = tx_manager.rollback_transaction(rec.transaction_id)
    assert rb.success is True

    env.cleanup()

    # Verify host baseline
    unmodified, diff = baseline_before.verify_unmodified()
    assert unmodified is True, f"Host network was unexpectedly modified: {diff}"
    assert diff["is_unmodified"] is True

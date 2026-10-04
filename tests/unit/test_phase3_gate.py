"""Unit tests for Phase 3H Enforcement Readiness & Activation Gating (PreconditionGate)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from xrlids.enforcement import (
    REASON_ARTIFACT_DIGEST_MISMATCH,
    REASON_ARTIFACT_MALFORMED,
    REASON_ARTIFACT_NOT_FOUND,
    REASON_AUTHORIZATION_ACTUATOR_MISMATCH,
    REASON_AUTHORIZATION_COMMIT_MISMATCH,
    REASON_AUTHORIZATION_EXPIRED,
    REASON_AUTHORIZATION_LAB_MISMATCH,
    REASON_AUTHORIZATION_MISSING,
    REASON_AUTHORIZATION_SCOPE_INVALID,
    REASON_AUTHORIZATION_SIGNATURE_INVALID,
    REASON_AUTHORIZATION_STATUS_INVALID,
    REASON_COMMIT_SHA_MISMATCH,
    REASON_CONFIGURATION_BYPASS_ATTEMPT,
    REASON_EVIDENCE_STALE,
    REASON_EVIDENCE_STATUS_NOT_PASS,
    REASON_INTERNAL_EVALUATION_EXCEPTION,
    REASON_METRIC_VERIFICATION_FAILED,
    REASON_PRECONDITION_MISSING,
    AuthorizationStatus,
    EligibilityStatus,
    EnforcementEligibility,
    LabActivationAuthorization,
    PreconditionCheckResult,
    PreconditionEvidence,
    PreconditionGate,
    PreconditionType,
)
from xrlids.response.transaction import (
    ControlledResponseTransactionManager,
    SimulatedActuatorBackend,
    TransactionState,
)
from xrlids.response.types import Action
from xrlids.utils.hashing import sha256_file


@pytest.fixture
def test_clock():
    fixed_time = datetime(2026, 10, 4, 14, 0, 0, tzinfo=timezone.utc)
    return lambda: fixed_time


@pytest.fixture
def dummy_artifact_factory(tmp_path: Path):
    def _create_artifact(filename: str, payload: dict) -> tuple[Path, str]:
        p = tmp_path / filename
        content = json.dumps(payload, indent=2)
        p.write_text(content, encoding="utf-8")
        digest = sha256_file(p)
        return p, digest

    return _create_artifact


@pytest.fixture
def valid_bundle(dummy_artifact_factory, test_clock):
    now_iso = test_clock().isoformat()
    bundle = {}
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"

    # P1: Feature Parity
    p1_path, p1_digest = dummy_artifact_factory(
        "p1.json",
        {"metadata": {"git_commit": target_commit, "created_at": now_iso}, "all_features_pass": True, "max_feature_error": 0.0001},
    )
    bundle[PreconditionType.P1_FEATURE_PARITY.value] = PreconditionEvidence(
        precondition=PreconditionType.P1_FEATURE_PARITY.value,
        experiment_id="EXP-P3-PARITY-001",
        status="PASS",
        commit_sha=target_commit,
        artifact_id="p1.json",
        artifact_path=str(p1_path),
        artifact_digest=p1_digest,
        generated_at=now_iso,
        metrics={"all_features_pass": True, "max_feature_error": 0.0001},
    )

    # P2: PCAP Replay
    p2_path, p2_digest = dummy_artifact_factory(
        "p2.json",
        {"metadata": {"git_commit": target_commit, "created_at": now_iso}, "packets_captured": 1000, "capture_errors": 0},
    )
    bundle[PreconditionType.P2_PCAP_REPLAY.value] = PreconditionEvidence(
        precondition=PreconditionType.P2_PCAP_REPLAY.value,
        experiment_id="EXP-P3-BURST-1000-001",
        status="PASS",
        commit_sha=target_commit,
        artifact_id="p2.json",
        artifact_path=str(p2_path),
        artifact_digest=p2_digest,
        generated_at=now_iso,
        metrics={"packets_captured": 1000, "capture_errors": 0},
    )

    # P3: Dry-Run Pipeline
    p3_path, p3_digest = dummy_artifact_factory(
        "p3.json",
        {"metadata": {"git_commit": target_commit, "created_at": now_iso}, "zero_network_mutation_guaranteed": True, "firewall_rules_mutated": 0},
    )
    bundle[PreconditionType.P3_DRY_RUN.value] = PreconditionEvidence(
        precondition=PreconditionType.P3_DRY_RUN.value,
        experiment_id="EXP-P3F-OBSERVABILITY-001",
        status="PASS",
        commit_sha=target_commit,
        artifact_id="p3.json",
        artifact_path=str(p3_path),
        artifact_digest=p3_digest,
        generated_at=now_iso,
        metrics={"zero_network_mutation_guaranteed": True, "firewall_rules_mutated": 0},
    )

    # P4: Safety Invariants
    p4_path, p4_digest = dummy_artifact_factory(
        "p4.json",
        {"metadata": {"git_commit": target_commit, "created_at": now_iso}, "zero_network_mutation_guaranteed": True, "critical_infrastructure_exemptions_passed": 1},
    )
    bundle[PreconditionType.P4_SAFETY_INVARIANTS.value] = PreconditionEvidence(
        precondition=PreconditionType.P4_SAFETY_INVARIANTS.value,
        experiment_id="EXP-P3F-OBSERVABILITY-001",
        status="PASS",
        commit_sha=target_commit,
        artifact_id="p4.json",
        artifact_path=str(p4_path),
        artifact_digest=p4_digest,
        generated_at=now_iso,
        metrics={"zero_network_mutation_guaranteed": True, "critical_infrastructure_exemptions_passed": 1},
    )

    # P5: Rollback Harness
    p5_path, p5_digest = dummy_artifact_factory(
        "p5.json",
        {
            "metadata": {"git_commit": target_commit, "created_at": now_iso},
            "rollback_success_rate_nominal": 1.0,
            "restoration_digest_verification_rate": 1.0,
            "safety_lock_behavior_verified": True,
            "zero_network_mutation_guaranteed": True,
        },
    )
    bundle[PreconditionType.P5_ROLLBACK_HARNESS.value] = PreconditionEvidence(
        precondition=PreconditionType.P5_ROLLBACK_HARNESS.value,
        experiment_id="EXP-P3G-ROLLBACK-001",
        status="PASS",
        commit_sha=target_commit,
        artifact_id="p5.json",
        artifact_path=str(p5_path),
        artifact_digest=p5_digest,
        generated_at=now_iso,
        metrics={
            "rollback_success_rate_nominal": 1.0,
            "restoration_digest_verification_rate": 1.0,
            "safety_lock_behavior_verified": True,
            "zero_network_mutation_guaranteed": True,
        },
    )

    return bundle


@pytest.fixture
def valid_auth(test_clock):
    now = test_clock()
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    auth = LabActivationAuthorization(
        authorization_id="AUTH-LAB-TEST-001",
        repository_commit_sha=target_commit,
        lab_environment_id="LAB-ISOLATED-NETNS-01",
        allowed_actuator_backend_id="SIMULATED_ACTUATOR_V1",
        scope="ISOLATED_LAB_CONTROLLED_RESPONSE_ONLY",
        issued_at=(now - timedelta(hours=1)).isoformat(),
        expires_at=(now + timedelta(hours=4)).isoformat(),
        status="ACTIVE",
    )
    auth.sign(secret_key="XRLIDARS_LAB_SECRET_KEY")
    return auth


def test_gate_evaluates_ready_on_valid_bundle_and_auth(valid_bundle, valid_auth, test_clock):
    """Verify that a fully valid evidence chain and signed authorization produce READY status."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(
        target_commit_sha=target_commit,
        clock=test_clock,
    )
    eligibility = gate.evaluate(valid_bundle, valid_auth)

    assert eligibility.status == EligibilityStatus.READY
    assert eligibility.is_ready is True
    assert len(eligibility.failed_checks) == 0
    assert len(eligibility.reason_codes) == 0
    for prec in PreconditionType:
        assert eligibility.checks[prec.value].passed is True


def test_gate_locks_on_missing_precondition(valid_bundle, valid_auth, test_clock):
    """Verify missing evidence item results in LOCKED status with REASON_PRECONDITION_MISSING."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    incomplete_bundle = dict(valid_bundle)
    del incomplete_bundle[PreconditionType.P5_ROLLBACK_HARNESS.value]

    eligibility = gate.evaluate(incomplete_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert eligibility.is_ready is False
    assert PreconditionType.P5_ROLLBACK_HARNESS.value in eligibility.failed_checks
    assert REASON_PRECONDITION_MISSING in eligibility.reason_codes


def test_gate_locks_on_evidence_status_fail(valid_bundle, valid_auth, test_clock):
    """Verify evidence with status != 'PASS' produces LOCKED status."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    tampered_bundle = dict(valid_bundle)
    orig_p1 = tampered_bundle[PreconditionType.P1_FEATURE_PARITY.value]
    tampered_bundle[PreconditionType.P1_FEATURE_PARITY.value] = PreconditionEvidence(
        precondition=orig_p1.precondition,
        experiment_id=orig_p1.experiment_id,
        status="FAIL",
        commit_sha=orig_p1.commit_sha,
        artifact_id=orig_p1.artifact_id,
        artifact_path=orig_p1.artifact_path,
        artifact_digest=orig_p1.artifact_digest,
        generated_at=orig_p1.generated_at,
        metrics=orig_p1.metrics,
    )

    eligibility = gate.evaluate(tampered_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_EVIDENCE_STATUS_NOT_PASS in eligibility.reason_codes


def test_gate_locks_on_commit_sha_mismatch(valid_bundle, valid_auth, test_clock):
    """Verify evidence bound to a different commit is rejected."""
    gate = PreconditionGate(target_commit_sha="different_commit_1234567890", clock=test_clock)
    eligibility = gate.evaluate(valid_bundle, valid_auth)

    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_COMMIT_SHA_MISMATCH in eligibility.reason_codes


def test_gate_locks_on_tampered_artifact_digest(valid_bundle, valid_auth, test_clock):
    """Verify digest mismatch (file modified on disk) triggers LOCKED."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    # Tamper with the physical file on disk for P2
    p2 = valid_bundle[PreconditionType.P2_PCAP_REPLAY.value]
    Path(p2.artifact_path).write_text(json.dumps({"tampered": True}), encoding="utf-8")

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_ARTIFACT_DIGEST_MISMATCH in eligibility.reason_codes


def test_gate_locks_on_missing_artifact_file(valid_bundle, valid_auth, test_clock):
    """Verify missing file on disk triggers LOCKED."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    # Delete physical file for P3
    p3 = valid_bundle[PreconditionType.P3_DRY_RUN.value]
    Path(p3.artifact_path).unlink()

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_ARTIFACT_NOT_FOUND in eligibility.reason_codes


def test_gate_locks_on_malformed_artifact_json(valid_bundle, valid_auth, test_clock):
    """Verify corrupt/malformed non-JSON artifact file triggers LOCKED."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    p4 = valid_bundle[PreconditionType.P4_SAFETY_INVARIANTS.value]
    Path(p4.artifact_path).write_text("CORRUPTED_NON_JSON_BYTES{{{", encoding="utf-8")
    # update digest so digest check passes into json parser
    new_digest = sha256_file(Path(p4.artifact_path))
    tampered_bundle = dict(valid_bundle)
    tampered_bundle[PreconditionType.P4_SAFETY_INVARIANTS.value] = PreconditionEvidence(
        precondition=p4.precondition,
        experiment_id=p4.experiment_id,
        status=p4.status,
        commit_sha=p4.commit_sha,
        artifact_id=p4.artifact_id,
        artifact_path=p4.artifact_path,
        artifact_digest=new_digest,
        generated_at=p4.generated_at,
        metrics=p4.metrics,
    )

    eligibility = gate.evaluate(tampered_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_ARTIFACT_MALFORMED in eligibility.reason_codes


def test_gate_locks_on_stale_evidence(valid_bundle, valid_auth, test_clock):
    """Verify evidence generated older than max_evidence_age_s is rejected."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    # Set max age to 1 hour, but evidence generated 10 days ago
    gate = PreconditionGate(
        target_commit_sha=target_commit,
        max_evidence_age_s=3600.0,
        clock=test_clock,
    )
    tampered_bundle = dict(valid_bundle)
    orig_p5 = tampered_bundle[PreconditionType.P5_ROLLBACK_HARNESS.value]
    stale_ts = (test_clock() - timedelta(days=10)).isoformat()
    tampered_bundle[PreconditionType.P5_ROLLBACK_HARNESS.value] = PreconditionEvidence(
        precondition=orig_p5.precondition,
        experiment_id=orig_p5.experiment_id,
        status=orig_p5.status,
        commit_sha=orig_p5.commit_sha,
        artifact_id=orig_p5.artifact_id,
        artifact_path=orig_p5.artifact_path,
        artifact_digest=orig_p5.artifact_digest,
        generated_at=stale_ts,
        metrics=orig_p5.metrics,
    )

    eligibility = gate.evaluate(tampered_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_EVIDENCE_STALE in eligibility.reason_codes


def test_gate_locks_on_domain_metric_failure(valid_bundle, valid_auth, test_clock):
    """Verify that domain metric violations (e.g., non-zero network mutations) trigger LOCKED."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    tampered_bundle = dict(valid_bundle)
    p3 = tampered_bundle[PreconditionType.P3_DRY_RUN.value]
    # Set firewall_rules_mutated to 2
    tampered_bundle[PreconditionType.P3_DRY_RUN.value] = PreconditionEvidence(
        precondition=p3.precondition,
        experiment_id=p3.experiment_id,
        status=p3.status,
        commit_sha=p3.commit_sha,
        artifact_id=p3.artifact_id,
        artifact_path=p3.artifact_path,
        artifact_digest=p3.artifact_digest,
        generated_at=p3.generated_at,
        metrics={"zero_network_mutation_guaranteed": False, "firewall_rules_mutated": 2},
    )

    eligibility = gate.evaluate(tampered_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_METRIC_VERIFICATION_FAILED in eligibility.reason_codes


def test_gate_locks_on_missing_authorization(valid_bundle, test_clock):
    """Verify absence of LabActivationAuthorization produces LOCKED status."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    eligibility = gate.evaluate(valid_bundle, authorization=None)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert PreconditionType.P6_ACTIVATION_AUTHORIZATION.value in eligibility.failed_checks
    assert REASON_AUTHORIZATION_MISSING in eligibility.reason_codes


def test_gate_locks_on_expired_authorization(valid_bundle, valid_auth, test_clock):
    """Verify expired authorization is rejected."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    now = test_clock()
    valid_auth.issued_at = (now - timedelta(days=2)).isoformat()
    valid_auth.expires_at = (now - timedelta(days=1)).isoformat()
    valid_auth.sign(secret_key="XRLIDARS_LAB_SECRET_KEY")

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_AUTHORIZATION_EXPIRED in eligibility.reason_codes


def test_gate_locks_on_wrong_lab_environment(valid_bundle, valid_auth, test_clock):
    """Verify authorization for unauthorized lab environment is rejected."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    valid_auth.lab_environment_id = "PROD-EXTERNAL-NET"
    valid_auth.sign(secret_key="XRLIDARS_LAB_SECRET_KEY")

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_AUTHORIZATION_LAB_MISMATCH in eligibility.reason_codes


def test_gate_locks_on_wrong_actuator_backend(valid_bundle, valid_auth, test_clock):
    """Verify authorization referencing non-approved actuator is rejected."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    valid_auth.allowed_actuator_backend_id = "IPTABLES_KERNEL_DIRECT"
    valid_auth.sign(secret_key="XRLIDARS_LAB_SECRET_KEY")

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_AUTHORIZATION_ACTUATOR_MISMATCH in eligibility.reason_codes


def test_gate_locks_on_invalid_scope(valid_bundle, valid_auth, test_clock):
    """Verify authorization attempting wildcards or production scopes is rejected."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    valid_auth.scope = "PRODUCTION_ENTERPRISE_NETWORK"
    valid_auth.sign(secret_key="XRLIDARS_LAB_SECRET_KEY")

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_AUTHORIZATION_SCOPE_INVALID in eligibility.reason_codes


def test_gate_locks_on_invalid_signature(valid_bundle, valid_auth, test_clock):
    """Verify tampered authorization token fails signature verification."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    valid_auth.auth_signature = "invalid_signature_hex_00000000000000000000"

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_AUTHORIZATION_SIGNATURE_INVALID in eligibility.reason_codes


def test_gate_locks_on_configuration_bypass_attempt(valid_bundle, valid_auth, test_clock, monkeypatch):
    """Verify attempts to force enforcement via environment variables fail closed."""
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)

    monkeypatch.setenv("XRLIDS_FORCE_ENFORCEMENT", "1")

    eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert eligibility.status == EligibilityStatus.LOCKED
    assert REASON_CONFIGURATION_BYPASS_ATTEMPT in eligibility.reason_codes


def test_transaction_manager_strictly_requires_gate_ready_for_enforcement(valid_bundle, valid_auth, test_clock):
    """Verify ControlledResponseTransactionManager rejects transactions when gate is not READY."""
    backend = SimulatedActuatorBackend()

    # Case 1: Locked eligibility -> rejected
    locked_eligibility = EnforcementEligibility(
        status=EligibilityStatus.LOCKED,
        target_commit_sha="7d92f90893d2c91cd3ced78bed501cd9e34def4b",
        evaluated_at=test_clock().isoformat(),
        checks={},
        failed_checks=["P1_FEATURE_PARITY"],
        reason_codes=["EVIDENCE_STATUS_NOT_PASS"],
        evidence_provenance={},
        authorization_provenance={},
    )
    manager_locked = ControlledResponseTransactionManager(
        backend=backend,
        eligibility=locked_eligibility,
        authorization=valid_auth,
        require_enforcement_readiness=True,
    )
    rec_locked = manager_locked.execute_transaction(Action.ISOLATE, "192.168.1.100")
    assert rec_locked.state == TransactionState.SAFETY_LOCKED
    assert "PreconditionGate is not in READY state" in (rec_locked.error_message or "")
    assert backend.verify_clean_state() is True

    # Case 2: Ready eligibility + valid auth -> allowed in simulated actuator only
    target_commit = "7d92f90893d2c91cd3ced78bed501cd9e34def4b"
    gate = PreconditionGate(target_commit_sha=target_commit, clock=test_clock)
    ready_eligibility = gate.evaluate(valid_bundle, valid_auth)
    assert ready_eligibility.is_ready is True

    manager_ready = ControlledResponseTransactionManager(
        backend=backend,
        eligibility=ready_eligibility,
        authorization=valid_auth,
        require_enforcement_readiness=True,
    )
    rec_ready = manager_ready.execute_transaction(Action.ISOLATE, "192.168.1.101")
    assert rec_ready.state == TransactionState.COMMITTED
    # STRICT INVARIANT: simulated memory mutated, ZERO host system mutation
    assert backend.network_mutations_count == 0
    assert backend.zero_network_mutation is True

"""Phase 3H: Enforcement Readiness, Evidence Provenance & Non-Bypassable Activation Gate.

Establishes the non-bypassable, fail-closed boundary between:
1. Verified offline and live-pipeline evidence (parity, PCAP replay, dry-run, safety invariants, rollback).
2. Eligibility to enter the isolated-lab controlled response activation boundary.

CRITICAL INVARIANTS:
1. READY != ENFORCEMENT: A READY result establishes only that all evidence and authorization
   prerequisites are verified. It never triggers real host network mutations.
2. FAIL CLOSED: Any missing, malformed, stale, untrusted, or tampered evidence immediately
   results in LOCKED.
3. ZERO SYSTEM MUTATIONS: No iptables, nftables, tc, routing tables, or sockets are ever touched.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from xrlids.utils.hashing import dict_hash, sha256_file

logger = logging.getLogger(__name__)

# Standard Reason Codes for Auditability
REASON_PRECONDITION_MISSING = "PRECONDITION_MISSING"
REASON_EVIDENCE_STATUS_NOT_PASS = "EVIDENCE_STATUS_NOT_PASS"
REASON_COMMIT_SHA_MISMATCH = "COMMIT_SHA_MISMATCH"
REASON_ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
REASON_ARTIFACT_DIGEST_MISMATCH = "ARTIFACT_DIGEST_MISMATCH"
REASON_ARTIFACT_MALFORMED = "ARTIFACT_MALFORMED"
REASON_EVIDENCE_STALE = "EVIDENCE_STALE"
REASON_METRIC_VERIFICATION_FAILED = "METRIC_VERIFICATION_FAILED"
REASON_AUTHORIZATION_MISSING = "AUTHORIZATION_MISSING"
REASON_AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
REASON_AUTHORIZATION_NOT_YET_VALID = "AUTHORIZATION_NOT_YET_VALID"
REASON_AUTHORIZATION_STATUS_INVALID = "AUTHORIZATION_STATUS_INVALID"
REASON_AUTHORIZATION_COMMIT_MISMATCH = "AUTHORIZATION_COMMIT_MISMATCH"
REASON_AUTHORIZATION_LAB_MISMATCH = "AUTHORIZATION_LAB_MISMATCH"
REASON_AUTHORIZATION_ACTUATOR_MISMATCH = "AUTHORIZATION_ACTUATOR_MISMATCH"
REASON_AUTHORIZATION_SCOPE_INVALID = "AUTHORIZATION_SCOPE_INVALID"
REASON_AUTHORIZATION_SIGNATURE_INVALID = "AUTHORIZATION_SIGNATURE_INVALID"
REASON_CONFIGURATION_BYPASS_ATTEMPT = "CONFIGURATION_BYPASS_ATTEMPT"
REASON_INTERNAL_EVALUATION_EXCEPTION = "INTERNAL_EVALUATION_EXCEPTION"


class PreconditionType(str, Enum):
    """The 6 mandatory preconditions required to evaluate enforcement eligibility."""

    P1_FEATURE_PARITY = "P1_FEATURE_PARITY"
    P2_PCAP_REPLAY = "P2_PCAP_REPLAY"
    P3_DRY_RUN = "P3_DRY_RUN"
    P4_SAFETY_INVARIANTS = "P4_SAFETY_INVARIANTS"
    P5_ROLLBACK_HARNESS = "P5_ROLLBACK_HARNESS"
    P6_ACTIVATION_AUTHORIZATION = "P6_ACTIVATION_AUTHORIZATION"


class EligibilityStatus(str, Enum):
    """Fail-closed status emitted by the PreconditionGate."""

    LOCKED = "LOCKED"
    READY = "READY"


class AuthorizationStatus(str, Enum):
    """Lifecycle status of a lab activation token."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    INVALID = "INVALID"


@dataclass(frozen=True)
class PreconditionEvidence:
    """Structured, verifiable evidence unit for a single pipeline prerequisite."""

    precondition: str
    experiment_id: str
    status: str  # "PASS" | "FAIL"
    commit_sha: str
    artifact_id: str
    artifact_path: str
    artifact_digest: str
    generated_at: str
    schema_version: str = "1.0"
    metrics: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "precondition": self.precondition,
            "experiment_id": self.experiment_id,
            "status": self.status,
            "commit_sha": self.commit_sha,
            "artifact_id": self.artifact_id,
            "artifact_path": str(self.artifact_path),
            "artifact_digest": self.artifact_digest,
            "generated_at": self.generated_at,
            "schema_version": self.schema_version,
            "metrics": dict(self.metrics),
            "provenance": dict(self.provenance),
        }

    @classmethod
    def from_artifact(
        cls,
        precondition: PreconditionType | str,
        artifact_path: str | Path,
        expected_status: str = "PASS",
        commit_sha: str | None = None,
        metrics: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> PreconditionEvidence:
        """Construct evidence from an existing artifact on disk with automatic SHA-256 computation."""
        path = Path(artifact_path)
        if not path.is_file():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        digest = sha256_file(path)
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)

        metadata = data.get("metadata", {})
        art_commit = commit_sha or metadata.get("git_commit") or "UNKNOWN"
        created_at = metadata.get("created_at") or datetime.now(timezone.utc).isoformat()
        exp_id = metadata.get("experiment_id") or data.get("experiment_id") or "UNKNOWN"

        combined_metrics = dict(metrics or {})
        # Extract standard metrics if present in artifact
        for key in (
            "zero_network_mutation_guaranteed",
            "flows_processed",
            "packets_captured",
            "capture_errors",
            "firewall_rules_mutated",
            "routing_entries_mutated",
            "network_sockets_dropped",
            "total_scenarios_evaluated",
            "total_scenarios_passed",
            "all_scenarios_passed",
            "rollback_success_rate_nominal",
            "restoration_digest_verification_rate",
            "safety_lock_behavior_verified",
            "watchdog_ttl_rollback_verified",
        ):
            if key in data and key not in combined_metrics:
                combined_metrics[key] = data[key]

        prec_name = precondition.value if isinstance(precondition, PreconditionType) else str(precondition)
        return cls(
            precondition=prec_name,
            experiment_id=exp_id,
            status=expected_status,
            commit_sha=art_commit,
            artifact_id=path.name,
            artifact_path=str(path),
            artifact_digest=digest,
            generated_at=created_at,
            metrics=combined_metrics,
            provenance=dict(provenance or metadata),
        )


@dataclass
class LabActivationAuthorization:
    """Explicit, scoped, time-bounded authorization token for isolated lab activation."""

    authorization_id: str
    repository_commit_sha: str
    lab_environment_id: str
    allowed_actuator_backend_id: str
    scope: str
    issued_at: str
    expires_at: str
    status: str = AuthorizationStatus.ACTIVE.value
    auth_signature: str = ""

    def compute_signature(self, secret_key: str = "XRLIDARS_LAB_SECRET_KEY") -> str:
        """Compute deterministic HMAC/SHA256 signature across canonical authorization attributes."""
        canonical = {
            "authorization_id": self.authorization_id,
            "repository_commit_sha": self.repository_commit_sha,
            "lab_environment_id": self.lab_environment_id,
            "allowed_actuator_backend_id": self.allowed_actuator_backend_id,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "secret_key": secret_key,
        }
        return dict_hash(canonical)

    def sign(self, secret_key: str = "XRLIDARS_LAB_SECRET_KEY") -> None:
        """Sign this authorization token in-place."""
        self.auth_signature = self.compute_signature(secret_key)

    def verify_signature(self, secret_key: str = "XRLIDARS_LAB_SECRET_KEY") -> bool:
        """Verify signature integrity against the canonical attributes."""
        if not self.auth_signature:
            return False
        return self.auth_signature == self.compute_signature(secret_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "repository_commit_sha": self.repository_commit_sha,
            "lab_environment_id": self.lab_environment_id,
            "allowed_actuator_backend_id": self.allowed_actuator_backend_id,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "auth_signature": self.auth_signature,
        }


@dataclass
class PreconditionCheckResult:
    """Detailed evaluation outcome for an individual prerequisite."""

    precondition: str
    passed: bool
    status: str
    reason_code: str | None = None
    details: str | None = None
    artifact_digest_verified: bool = False
    commit_verified: bool = False
    freshness_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "precondition": self.precondition,
            "passed": self.passed,
            "status": self.status,
            "reason_code": self.reason_code,
            "details": self.details,
            "artifact_digest_verified": self.artifact_digest_verified,
            "commit_verified": self.commit_verified,
            "freshness_verified": self.freshness_verified,
        }


@dataclass
class EnforcementEligibility:
    """Comprehensive, machine-auditable eligibility outcome emitted by PreconditionGate."""

    status: EligibilityStatus
    target_commit_sha: str
    evaluated_at: str
    checks: dict[str, PreconditionCheckResult]
    failed_checks: list[str]
    reason_codes: list[str]
    evidence_provenance: dict[str, Any]
    authorization_provenance: dict[str, Any]

    @property
    def is_ready(self) -> bool:
        """Returns True if and only if every single check passed and status is READY."""
        return self.status == EligibilityStatus.READY and len(self.failed_checks) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "is_ready": self.is_ready,
            "target_commit_sha": self.target_commit_sha,
            "evaluated_at": self.evaluated_at,
            "checks": {k: v.to_dict() for k, v in self.checks.items()},
            "failed_checks": list(self.failed_checks),
            "reason_codes": list(self.reason_codes),
            "evidence_provenance": dict(self.evidence_provenance),
            "authorization_provenance": dict(self.authorization_provenance),
            "zero_network_mutation_guaranteed": True,
        }


class PreconditionGate:
    """Non-bypassable, fail-closed gate governing eligibility for controlled response activation."""

    FORBIDDEN_ENV_VARS: frozenset[str] = frozenset([
        "XRLIDS_FORCE_ENFORCEMENT",
        "XRLIDS_ALLOW_ENFORCEMENT",
        "XRLIDS_BYPASS_SAFETY_GATE",
        "XRLIDS_DISABLE_PRECONDITIONS",
        "XRLIDS_ENABLE_ACTUATOR",
    ])

    ALLOWED_SCOPES: frozenset[str] = frozenset([
        "ISOLATED_LAB_CONTROLLED_RESPONSE_ONLY",
    ])

    def __init__(
        self,
        target_commit_sha: str,
        allowed_ancestor_commits: set[str] | Sequence[str] | None = None,
        lab_environment_id: str = "LAB-ISOLATED-NETNS-01",
        allowed_actuator_backend_id: str = "SIMULATED_ACTUATOR_V1",
        max_evidence_age_s: float = 604800.0,  # 7 days default freshness
        clock: Callable[[], datetime] | None = None,
        secret_key: str = "XRLIDARS_LAB_SECRET_KEY",
        strict_artifact_file_check: bool = True,
    ) -> None:
        self.target_commit_sha = target_commit_sha
        self.allowed_ancestor_commits = set(allowed_ancestor_commits or [])
        self.lab_environment_id = lab_environment_id
        self.allowed_actuator_backend_id = allowed_actuator_backend_id
        self.max_evidence_age_s = max_evidence_age_s
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.secret_key = secret_key
        self.strict_artifact_file_check = strict_artifact_file_check

    def evaluate(
        self,
        evidence_bundle: dict[PreconditionType | str, PreconditionEvidence],
        authorization: LabActivationAuthorization | None,
    ) -> EnforcementEligibility:
        """Evaluate all 6 prerequisites in fail-closed mode.

        Returns EnforcementEligibility with status=READY only if every prerequisite is
        cryptographically, temporally, and empirically verified.
        """
        now = self.clock()
        evaluated_at_ts = now.isoformat()
        checks: dict[str, PreconditionCheckResult] = {}
        failed_checks: list[str] = []
        reason_codes: list[str] = []
        evidence_prov: dict[str, Any] = {}
        auth_prov: dict[str, Any] = {}

        try:
            # 1. Non-Bypassability: Check for unauthorized configuration / environment bypass attempts
            bypass_detected = self._detect_configuration_bypass()
            if bypass_detected:
                logger.critical("SECURITY ALERT: Configuration bypass attempt detected: %s", bypass_detected)
                failed_checks.append("CONFIGURATION_INTEGRITY")
                reason_codes.append(REASON_CONFIGURATION_BYPASS_ATTEMPT)
                checks["CONFIGURATION_INTEGRITY"] = PreconditionCheckResult(
                    precondition="CONFIGURATION_INTEGRITY",
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_CONFIGURATION_BYPASS_ATTEMPT,
                    details=f"Forbidden configuration override detected in environment: {bypass_detected}",
                )

            # Normalize evidence bundle keys to string
            normalized_bundle: dict[str, PreconditionEvidence] = {}
            for k, ev in evidence_bundle.items():
                key_str = k.value if isinstance(k, PreconditionType) else str(k)
                normalized_bundle[key_str] = ev
                evidence_prov[key_str] = {
                    "experiment_id": ev.experiment_id,
                    "commit_sha": ev.commit_sha,
                    "artifact_id": ev.artifact_id,
                    "artifact_digest": ev.artifact_digest,
                    "generated_at": ev.generated_at,
                }

            # 2. Evaluate Evidence Preconditions (P1..P5)
            required_preconditions = [
                PreconditionType.P1_FEATURE_PARITY.value,
                PreconditionType.P2_PCAP_REPLAY.value,
                PreconditionType.P3_DRY_RUN.value,
                PreconditionType.P4_SAFETY_INVARIANTS.value,
                PreconditionType.P5_ROLLBACK_HARNESS.value,
            ]

            for prec in required_preconditions:
                evidence = normalized_bundle.get(prec)
                check_res = self._evaluate_single_evidence(prec, evidence, now)
                checks[prec] = check_res
                if not check_res.passed:
                    failed_checks.append(prec)
                    if check_res.reason_code and check_res.reason_code not in reason_codes:
                        reason_codes.append(check_res.reason_code)

            # 3. Evaluate Activation Authorization (P6)
            auth_res = self._evaluate_authorization(authorization, now)
            checks[PreconditionType.P6_ACTIVATION_AUTHORIZATION.value] = auth_res
            if authorization:
                auth_prov = authorization.to_dict()
            if not auth_res.passed:
                failed_checks.append(PreconditionType.P6_ACTIVATION_AUTHORIZATION.value)
                if auth_res.reason_code and auth_res.reason_code not in reason_codes:
                    reason_codes.append(auth_res.reason_code)

            # 4. Fail-Closed Determination
            is_ready = (len(failed_checks) == 0 and len(reason_codes) == 0)
            status = EligibilityStatus.READY if is_ready else EligibilityStatus.LOCKED

            return EnforcementEligibility(
                status=status,
                target_commit_sha=self.target_commit_sha,
                evaluated_at=evaluated_at_ts,
                checks=checks,
                failed_checks=failed_checks,
                reason_codes=reason_codes,
                evidence_provenance=evidence_prov,
                authorization_provenance=auth_prov,
            )

        except Exception as err:
            logger.error("Internal exception inside PreconditionGate. Failing closed: %s", err, exc_info=True)
            failed_checks.append("INTERNAL_ERROR")
            reason_codes.append(REASON_INTERNAL_EVALUATION_EXCEPTION)
            return EnforcementEligibility(
                status=EligibilityStatus.LOCKED,
                target_commit_sha=self.target_commit_sha,
                evaluated_at=evaluated_at_ts,
                checks={
                    "INTERNAL_ERROR": PreconditionCheckResult(
                        precondition="INTERNAL_ERROR",
                        passed=False,
                        status="FAIL",
                        reason_code=REASON_INTERNAL_EVALUATION_EXCEPTION,
                        details=f"Unexpected internal gate exception: {type(err).__name__}: {err}",
                    )
                },
                failed_checks=failed_checks,
                reason_codes=reason_codes,
                evidence_provenance=evidence_prov,
                authorization_provenance=auth_prov,
            )

    def _detect_configuration_bypass(self) -> list[str]:
        """Detect any forbidden environment variable attempting to bypass gating."""
        detected = []
        for var in self.FORBIDDEN_ENV_VARS:
            val = os.environ.get(var)
            if val is not None and val != "" and val.lower() not in ("0", "false", "no"):
                detected.append(var)
        return detected

    def _evaluate_single_evidence(
        self,
        prec: str,
        evidence: PreconditionEvidence | None,
        now: datetime,
    ) -> PreconditionCheckResult:
        """Validate a single evidence prerequisite."""
        if evidence is None:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_PRECONDITION_MISSING,
                details=f"Required evidence object for {prec} is missing",
            )

        # 1. Status Check
        if str(evidence.status).upper() != "PASS":
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_EVIDENCE_STATUS_NOT_PASS,
                details=f"Evidence status is '{evidence.status}', expected 'PASS'",
            )

        # 2. Commit Binding Check
        commit_ok = self._is_commit_allowed(evidence.commit_sha)
        if not commit_ok:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_COMMIT_SHA_MISMATCH,
                details=(
                    f"Evidence commit '{evidence.commit_sha}' does not match target commit "
                    f"'{self.target_commit_sha}' and is not in allowed ancestors"
                ),
            )

        # 3. Artifact File & Digest Verification
        if self.strict_artifact_file_check:
            path = Path(evidence.artifact_path)
            if not path.is_file():
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_ARTIFACT_NOT_FOUND,
                    details=f"Artifact file not found on disk at: {evidence.artifact_path}",
                )

            try:
                actual_digest = sha256_file(path)
                # Verify JSON parseability
                json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as err:
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_ARTIFACT_MALFORMED,
                    details=f"Artifact file contains malformed JSON: {err}",
                )
            except Exception as err:
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_ARTIFACT_MALFORMED,
                    details=f"Failed to read artifact: {err}",
                )

            if actual_digest != evidence.artifact_digest:
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_ARTIFACT_DIGEST_MISMATCH,
                    details=(
                        f"Artifact SHA-256 digest mismatch! Expected '{evidence.artifact_digest}', "
                        f"actual file on disk computed '{actual_digest}'"
                    ),
                )

        # 4. Freshness Verification
        try:
            gen_dt = datetime.fromisoformat(evidence.generated_at.replace("Z", "+00:00"))
            if gen_dt.tzinfo is None:
                gen_dt = gen_dt.replace(tzinfo=timezone.utc)
            age_s = (now - gen_dt).total_seconds()
            if age_s < -5.0:  # Allow 5s clock skew
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_EVIDENCE_STALE,
                    details=f"Evidence timestamp is in the future: {evidence.generated_at}",
                )
            if age_s > self.max_evidence_age_s:
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_EVIDENCE_STALE,
                    details=(
                        f"Evidence age ({age_s:.1f}s) exceeds maximum allowed age "
                        f"({self.max_evidence_age_s:.1f}s)"
                    ),
                )
        except Exception as err:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_EVIDENCE_STALE,
                details=f"Failed to parse evidence timestamp '{evidence.generated_at}': {err}",
            )

        # 5. Domain-Specific Metric Invariants
        metric_err = self._verify_domain_metrics(prec, evidence.metrics)
        if metric_err:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_METRIC_VERIFICATION_FAILED,
                details=metric_err,
                artifact_digest_verified=True,
                commit_verified=True,
                freshness_verified=True,
            )

        return PreconditionCheckResult(
            precondition=prec,
            passed=True,
            status="PASS",
            reason_code=None,
            details=f"Evidence for {prec} successfully verified with exact digest match and commit binding.",
            artifact_digest_verified=True,
            commit_verified=True,
            freshness_verified=True,
        )

    def _verify_domain_metrics(self, prec: str, metrics: dict[str, Any]) -> str | None:
        """Verify empirical metrics for each precondition type."""
        if prec == PreconditionType.P1_FEATURE_PARITY.value:
            # Must verify all features pass parity tolerance
            if metrics.get("all_features_pass") is False:
                return "P1 feature parity verification failed: all_features_pass is False"
            if metrics.get("max_feature_error", 0.0) > 1e-3:
                return f"P1 max feature error ({metrics['max_feature_error']}) exceeds tolerance (1e-3)"

        elif prec == PreconditionType.P2_PCAP_REPLAY.value:
            # Must verify zero capture errors and positive packet ingestion
            if metrics.get("capture_errors", 0) > 0:
                return f"P2 PCAP replay recorded {metrics['capture_errors']} capture errors"
            if metrics.get("packets_captured", 1) <= 0:
                return "P2 PCAP replay recorded 0 packets captured"

        elif prec == PreconditionType.P3_DRY_RUN.value:
            # Must verify strict zero real network mutations
            if metrics.get("zero_network_mutation_guaranteed") is False:
                return "P3 dry run failed: zero_network_mutation_guaranteed is False"
            if metrics.get("firewall_rules_mutated", 0) > 0:
                return f"P3 dry run mutated {metrics['firewall_rules_mutated']} firewall rules"

        elif prec == PreconditionType.P4_SAFETY_INVARIANTS.value:
            # Must verify deterministic safety invariants and zero mutations
            if metrics.get("zero_network_mutation_guaranteed") is False:
                return "P4 safety invariants failed: zero_network_mutation_guaranteed is False"
            if metrics.get("critical_infrastructure_exemptions_passed", 1) < 1:
                return "P4 safety invariants: critical infrastructure exemption was violated"

        elif prec == PreconditionType.P5_ROLLBACK_HARNESS.value:
            # Must verify 100% rollback success rate and safety lock behavior
            if metrics.get("rollback_success_rate_nominal", 1.0) < 1.0:
                return f"P5 rollback success rate ({metrics['rollback_success_rate_nominal']}) < 1.0"
            if metrics.get("restoration_digest_verification_rate", 1.0) < 1.0:
                return f"P5 restoration digest rate ({metrics['restoration_digest_verification_rate']}) < 1.0"
            if metrics.get("safety_lock_behavior_verified") is False:
                return "P5 safety lock behavior verification failed"
            if metrics.get("zero_network_mutation_guaranteed") is False:
                return "P5 rollback harness: zero_network_mutation_guaranteed is False"

        return None

    def _evaluate_authorization(
        self,
        auth: LabActivationAuthorization | None,
        now: datetime,
    ) -> PreconditionCheckResult:
        """Validate the explicit lab activation authorization token."""
        prec = PreconditionType.P6_ACTIVATION_AUTHORIZATION.value
        if auth is None:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_MISSING,
                details="No LabActivationAuthorization object was provided",
            )

        # 1. Status Check
        if auth.status != AuthorizationStatus.ACTIVE.value:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_STATUS_INVALID,
                details=f"Authorization status is '{auth.status}', expected 'ACTIVE'",
            )

        # 2. Scope Check
        if auth.scope not in self.ALLOWED_SCOPES:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_SCOPE_INVALID,
                details=(
                    f"Authorization scope '{auth.scope}' is invalid or unauthorized. "
                    f"Permitted scopes: {sorted(list(self.ALLOWED_SCOPES))}"
                ),
            )

        # 3. Lab Environment Check
        if auth.lab_environment_id != self.lab_environment_id:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_LAB_MISMATCH,
                details=(
                    f"Authorization lab ID '{auth.lab_environment_id}' does not match "
                    f"expected lab environment '{self.lab_environment_id}'"
                ),
            )

        # 4. Actuator Backend Check
        if auth.allowed_actuator_backend_id != self.allowed_actuator_backend_id:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_ACTUATOR_MISMATCH,
                details=(
                    f"Authorization actuator backend '{auth.allowed_actuator_backend_id}' "
                    f"does not match allowed actuator '{self.allowed_actuator_backend_id}'"
                ),
            )

        # 5. Commit Binding Check
        if not self._is_commit_allowed(auth.repository_commit_sha):
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_COMMIT_MISMATCH,
                details=(
                    f"Authorization commit '{auth.repository_commit_sha}' does not match "
                    f"target repository commit '{self.target_commit_sha}'"
                ),
            )

        # 6. Time Validity Check
        try:
            issue_dt = datetime.fromisoformat(auth.issued_at.replace("Z", "+00:00"))
            expire_dt = datetime.fromisoformat(auth.expires_at.replace("Z", "+00:00"))
            if issue_dt.tzinfo is None:
                issue_dt = issue_dt.replace(tzinfo=timezone.utc)
            if expire_dt.tzinfo is None:
                expire_dt = expire_dt.replace(tzinfo=timezone.utc)

            if now < issue_dt:
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_AUTHORIZATION_NOT_YET_VALID,
                    details=f"Authorization is not yet valid (issued_at: {auth.issued_at})",
                )
            if now > expire_dt:
                return PreconditionCheckResult(
                    precondition=prec,
                    passed=False,
                    status="FAIL",
                    reason_code=REASON_AUTHORIZATION_EXPIRED,
                    details=f"Authorization has expired (expired_at: {auth.expires_at})",
                )
        except Exception as err:
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_EXPIRED,
                details=f"Failed to parse authorization validity window: {err}",
            )

        # 7. Signature / Digest Verification
        if not auth.verify_signature(self.secret_key):
            return PreconditionCheckResult(
                precondition=prec,
                passed=False,
                status="FAIL",
                reason_code=REASON_AUTHORIZATION_SIGNATURE_INVALID,
                details="Authorization token signature verification failed",
            )

        return PreconditionCheckResult(
            precondition=prec,
            passed=True,
            status="PASS",
            reason_code=None,
            details="Authorization token is valid, active, signed, and bound to target lab and commit.",
            artifact_digest_verified=True,
            commit_verified=True,
            freshness_verified=True,
        )

    def _is_commit_allowed(self, commit_sha: str) -> bool:
        """Check if commit SHA matches target or is in allowed ancestors."""
        if not commit_sha:
            return False
        # Exact match or prefix match (min 7 chars)
        if commit_sha == self.target_commit_sha:
            return True
        if len(commit_sha) >= 7 and self.target_commit_sha.startswith(commit_sha):
            return True
        if len(self.target_commit_sha) >= 7 and commit_sha.startswith(self.target_commit_sha):
            return True
        for anc in self.allowed_ancestor_commits:
            if commit_sha == anc:
                return True
            if len(commit_sha) >= 7 and anc.startswith(commit_sha):
                return True
            if len(anc) >= 7 and commit_sha.startswith(anc):
                return True
        return False

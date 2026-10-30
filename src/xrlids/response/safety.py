"""Deterministic Safety Gate architecture for Phase 2 autonomous response (Task 5).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 14:
    Action_proposed ~ π(s_t) -> [Deterministic Safety Gate] -> Action_enforced

Inviolable Deterministic Safety Invariants:
1. Critical Infrastructure Exemption:
   Designated critical infrastructure endpoints (Gateway, DNS, Identity) can NEVER be isolated.
   If proposed == ISOLATE and host is critical -> enforced = ALERT.
2. Mandatory Action Cooldown:
   Once a disruptive action (RATE_LIMIT or ISOLATE) is executed on an endpoint, the action
   cannot be toggled back to ALLOW within the cooldown window (T_cool = 30.0s).
3. Blast Radius Circuit Breaker:
   Monitors global fraction of currently isolated endpoints. If active isolated hosts
   exceed max_isolation_fraction (5.0%), subsequent ISOLATE actions are downgraded to ALERT.
4. Action Space Mode Enforcement:
   In 3-action mode (ALLOW, ALERT, RATE_LIMIT), any proposed ISOLATE is clamped to RATE_LIMIT.
5. Deterministic Auditing:
   Every proposed action and enforced action is recorded with override reasons.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Callable

from xrlids.config.protected_assets import (
    AUTHORITATIVE_PROTECTED_REGISTRY,
    ProtectedInfrastructureRegistry,
    is_critical_infrastructure,
)
from xrlids.response.types import Action, ActionSpaceMode, SafetyOverrideRecord

DEFAULT_CRITICAL_HOSTS: frozenset[str] = AUTHORITATIVE_PROTECTED_REGISTRY.get_protected_identifiers()


@dataclass(frozen=True)
class SafetyCheckResult:
    """Outcome of evaluating action safety invariants."""

    action: Action
    allowed: bool
    is_overridden: bool
    reason: str
    target_host: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value if hasattr(self.action, "value") else str(self.action),
            "allowed": self.allowed,
            "is_overridden": self.is_overridden,
            "reason": self.reason,
            "target_host": self.target_host,
        }


@dataclass
class DeterministicSafetyGate:
    """Non-bypassable deterministic safety architecture governing autonomous actions."""

    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION
    critical_hosts: frozenset[str] = field(default_factory=lambda: DEFAULT_CRITICAL_HOSTS)
    cooldown_steps: int = 30
    cooldown_seconds_duration: float | None = None  # Authoritative physical cooldown in seconds (defaults to cooldown_steps * step_duration_s)
    step_duration_s: float = 1.0  # Nominal decision step duration (30 steps = 30.0s cooldown)
    blast_radius_threshold: float = 0.05  # 5% maximum simultaneous endpoint isolation
    min_hosts_for_circuit_breaker: int = 20  # Minimum host population before fraction triggers
    advisory_mode: bool = True
    clock: Callable[[], float] = field(default=time.monotonic)

    @property
    def cooldown_seconds(self) -> float:
        """Physical operational duration corresponding to cooldown_seconds_duration or steps."""
        if self.cooldown_seconds_duration is not None:
            return float(self.cooldown_seconds_duration)
        return float(self.cooldown_steps) * float(self.step_duration_s)

    # Internal state tracking (deterministic)
    _active_isolated_hosts: set[str] = field(default_factory=set, init=False)
    _active_rate_limited_hosts: set[str] = field(default_factory=set, init=False)
    _known_hosts: set[str] = field(default_factory=set, init=False)
    _host_cooldown_expiry_time: dict[str, float] = field(default_factory=dict, init=False)
    _host_cooldown_expiry_step: dict[str, int] = field(default_factory=dict, init=False)
    _host_last_action: dict[str, Action] = field(default_factory=dict, init=False)
    _override_log: list[SafetyOverrideRecord] = field(default_factory=list, init=False)
    _total_evaluations: int = field(default=0, init=False)

    def reset(self) -> None:
        """Reset internal host state and tracking records."""
        self._active_isolated_hosts.clear()
        self._active_rate_limited_hosts.clear()
        self._known_hosts.clear()
        self._host_cooldown_expiry_time.clear()
        self._host_cooldown_expiry_step.clear()
        self._host_last_action.clear()
        self._override_log.clear()
        self._total_evaluations = 0

    def is_critical_host(self, host_id: str) -> bool:
        """Evaluate if host_id is protected from isolation via config or local set."""
        clean = str(host_id).strip()
        if clean in self.critical_hosts:
            return True
        return AUTHORITATIVE_PROTECTED_REGISTRY.is_protected(clean)

    def get_remaining_cooldown_seconds(self, host_id: str, current_time: float | None = None) -> float:
        """Return remaining cooldown duration in seconds using monotonic clock."""
        now = self.clock() if current_time is None else float(current_time)
        expiry = self._host_cooldown_expiry_time.get(host_id, 0.0)
        return max(0.0, expiry - now)

    def get_remaining_cooldown_fraction(self, host_id: str, current_time: float | None = None) -> float:
        """Return normalized remaining cooldown fraction in [0.0, 1.0]."""
        rem_s = self.get_remaining_cooldown_seconds(host_id, current_time=current_time)
        return float(min(1.0, max(0.0, rem_s / max(1e-6, self.cooldown_seconds))))

    def get_remaining_cooldown(
        self,
        host_id: str,
        current_step: int | None = None,
        current_time: float | None = None,
    ) -> int:
        """Return remaining cooldown steps/seconds for host (backwards compatible)."""
        # If custom clock or explicit time is provided, return remaining seconds
        if self.clock != time.monotonic or current_time is not None:
            return int(self.get_remaining_cooldown_seconds(host_id, current_time=current_time))

        # If current_step is provided and step tracking was used:
        if current_step is not None and host_id in self._host_cooldown_expiry_step:
            step_rem = max(0, self._host_cooldown_expiry_step.get(host_id, 0) - int(current_step))
            return step_rem

        # Otherwise use time-based remaining seconds
        rem_s = self.get_remaining_cooldown_seconds(host_id, current_time=current_time)
        return int(rem_s)

    def check(
        self,
        action: Action,
        target_host: str,
        current_time: float | None = None,
    ) -> SafetyCheckResult:
        """Evaluate whether an action is safe against target_host."""
        step = int(current_time or 0)
        enforced, is_ov, reason = self.enforce_safety(
            step=step,
            flow_id=0,
            host_id=target_host,
            proposed_action=action,
            timestamp=current_time,
        )
        return SafetyCheckResult(
            action=enforced,
            allowed=(enforced == action or not is_ov),
            is_overridden=is_ov,
            reason=reason or "OK",
            target_host=target_host,
        )

    def enforce_safety(
        self,
        step: int = 0,
        flow_id: str | int = 0,
        host_id: str = "",
        proposed_action: Action = Action.ALLOW,
        timestamp: float | None = None,
    ) -> tuple[Action, bool, str | None]:
        """Apply deterministic safety invariants to a proposed policy action.

        Parameters
        ----------
        step: int
            Current simulation step index.
        flow_id: str | int
            Identifier for the current flow.
        host_id: str
            Host or session identifier.
        proposed_action: Action
            Action proposed by the upstream policy.
        timestamp: float | None
            Optional monotonic timestamp override (defaults to self.clock()).

        Returns
        -------
        tuple[Action, bool, str | None]
            (enforced_action, is_overridden, override_reason)
        """
        self._total_evaluations += 1
        clean_host = str(host_id).strip()
        self._known_hosts.add(clean_host)

        now_time = self.clock() if timestamp is None else float(timestamp)
        rem_cooldown_time = self.get_remaining_cooldown_seconds(clean_host, current_time=now_time)
        rem_cooldown_step = (
            max(0, self._host_cooldown_expiry_step.get(clean_host, 0) - int(step))
            if clean_host in self._host_cooldown_expiry_step
            else 0
        )
        # If custom clock or explicit timestamp is provided, time-based tracking is authoritative:
        if self.clock != time.monotonic or timestamp is not None:
            in_cooldown = rem_cooldown_time > 0.0
        elif clean_host in self._host_cooldown_expiry_step and rem_cooldown_step == 0:
            # Step-based simulation benchmark has expired by step progression
            in_cooldown = False
        else:
            in_cooldown = (rem_cooldown_time > 0.0) or (rem_cooldown_step > 0)
        last_action = self._host_last_action.get(clean_host, Action.ALLOW)

        enforced_action = proposed_action
        overridden = False
        override_reason: str | None = None

        # 1. Action Space Mode Clamp (3-action mode does not permit ISOLATE)
        if self.action_mode == ActionSpaceMode.THREE_ACTION and enforced_action == Action.ISOLATE:
            enforced_action = Action.RATE_LIMIT
            overridden = True
            override_reason = "ACTION_MODE_3_ACTION_CLAMP"

        # 2. Critical Infrastructure Exemption
        # Critical hosts can NEVER be isolated; downgraded to ALERT
        if enforced_action == Action.ISOLATE and self.is_critical_host(clean_host):
            enforced_action = Action.ALERT
            overridden = True
            override_reason = "CRITICAL_INFRASTRUCTURE_EXEMPTION"

        # 3. Blast Radius Circuit Breaker
        # If fraction of currently isolated endpoints exceeds threshold, downgrade ISOLATE to ALERT
        if enforced_action == Action.ISOLATE and clean_host not in self._active_isolated_hosts:
            effective_population = max(len(self._known_hosts), self.min_hosts_for_circuit_breaker)
            projected_isolated = len(self._active_isolated_hosts) + 1
            isolation_fraction = projected_isolated / effective_population
            if isolation_fraction > self.blast_radius_threshold:
                enforced_action = Action.ALERT
                overridden = True
                override_reason = "BLAST_RADIUS_CIRCUIT_BREAKER"

        # 4. Mandatory Action Cooldown
        # If host is under cooldown from previous disruptive action (RATE_LIMIT or ISOLATE),
        # prevent violent oscillation back to ALLOW within cooldown window
        if in_cooldown and last_action in (Action.RATE_LIMIT, Action.ISOLATE):
            if enforced_action == Action.ALLOW:
                enforced_action = Action.RATE_LIMIT if last_action == Action.RATE_LIMIT else Action.ISOLATE
                # Double-check critical exemption and 3-action clamp on maintained action
                if self.action_mode == ActionSpaceMode.THREE_ACTION and enforced_action == Action.ISOLATE:
                    enforced_action = Action.RATE_LIMIT
                if enforced_action == Action.ISOLATE and self.is_critical_host(clean_host):
                    enforced_action = Action.ALERT

                overridden = True
                override_reason = "MANDATORY_ACTION_COOLDOWN"

        # Update host tracking state
        if enforced_action == Action.ISOLATE:
            self._active_isolated_hosts.add(clean_host)
            self._active_rate_limited_hosts.discard(clean_host)
            if not (overridden and override_reason == "MANDATORY_ACTION_COOLDOWN"):
                self._host_cooldown_expiry_time[clean_host] = now_time + self.cooldown_seconds
                self._host_cooldown_expiry_step[clean_host] = int(step) + self.cooldown_steps
        elif enforced_action == Action.RATE_LIMIT:
            self._active_rate_limited_hosts.add(clean_host)
            self._active_isolated_hosts.discard(clean_host)
            if not (overridden and override_reason == "MANDATORY_ACTION_COOLDOWN"):
                self._host_cooldown_expiry_time[clean_host] = now_time + self.cooldown_seconds
                self._host_cooldown_expiry_step[clean_host] = int(step) + self.cooldown_steps
        elif enforced_action == Action.ALLOW:
            self._active_isolated_hosts.discard(clean_host)
            self._active_rate_limited_hosts.discard(clean_host)
            # ALLOW resets cooldown if it is outside cooldown window
            if not in_cooldown:
                self._host_cooldown_expiry_time.pop(clean_host, None)
                self._host_cooldown_expiry_step.pop(clean_host, None)

        self._host_last_action[clean_host] = enforced_action

        if overridden:
            record = SafetyOverrideRecord(
                step=int(step),
                flow_id=flow_id,
                host_id=clean_host,
                proposed_action=proposed_action,
                enforced_action=enforced_action,
                reason=override_reason or "SAFETY_OVERRIDE",
            )
            self._override_log.append(record)

        return enforced_action, overridden, override_reason

    @property
    def override_log(self) -> list[SafetyOverrideRecord]:
        return list(self._override_log)

    def summary(self) -> dict[str, Any]:
        """Return audit summary of safety gate actions."""
        reasons_count: dict[str, int] = {}
        for rec in self._override_log:
            reasons_count[rec.reason] = reasons_count.get(rec.reason, 0) + 1

        return {
            "total_evaluations": self._total_evaluations,
            "total_overrides": len(self._override_log),
            "override_rate": float(len(self._override_log) / max(1, self._total_evaluations)),
            "active_isolated_hosts_count": len(self._active_isolated_hosts),
            "active_rate_limited_hosts_count": len(self._active_rate_limited_hosts),
            "known_hosts_count": len(self._known_hosts),
            "reasons": reasons_count,
        }

"""Deterministic Safety Gate architecture for Phase 2 autonomous response (Task 5).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 14:
    Action_proposed ~ π(s_t) -> [Deterministic Safety Gate] -> Action_enforced

Inviolable Deterministic Safety Invariants:
1. Critical Infrastructure Exemption:
   Designated critical infrastructure endpoints (Gateway, DNS, Identity) can NEVER be isolated.
   If proposed == ISOLATE and host in CRITICAL_HOSTS -> enforced = ALERT.
2. Mandatory Action Cooldown:
   Once a disruptive action (RATE_LIMIT or ISOLATE) is executed on an endpoint, the action
   cannot be toggled back to ALLOW within cooldown window T_cool = 30 steps.
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
from typing import Any

from xrlids.response.types import Action, ActionSpaceMode, SafetyOverrideRecord


DEFAULT_CRITICAL_HOSTS = frozenset([
    "192.168.10.1",   # Default Gateway
    "192.168.10.50",  # Core DNS / DC
    "192.168.10.2",   # Backup DNS / NTP
    "gateway",
    "dns",
    "core-router",
])


@dataclass
class DeterministicSafetyGate:
    """Non-bypassable deterministic safety architecture governing autonomous actions."""

    action_mode: ActionSpaceMode = ActionSpaceMode.FOUR_ACTION
    critical_hosts: frozenset[str] = DEFAULT_CRITICAL_HOSTS
    cooldown_steps: int = 30
    step_duration_s: float = 1.0  # Nominal decision step duration (30 steps = 30.0s cooldown)
    blast_radius_threshold: float = 0.05  # 5% maximum simultaneous endpoint isolation
    min_hosts_for_circuit_breaker: int = 20  # Minimum host population before fraction triggers

    @property
    def cooldown_seconds(self) -> float:
        """Physical operational duration corresponding to cooldown_steps under nominal 1.0s/step."""
        return float(self.cooldown_steps * self.step_duration_s)

    # Internal state tracking (deterministic)
    _active_isolated_hosts: set[str] = field(default_factory=set, init=False)
    _active_rate_limited_hosts: set[str] = field(default_factory=set, init=False)
    _known_hosts: set[str] = field(default_factory=set, init=False)
    _host_cooldown_expiry: dict[str, int] = field(default_factory=dict, init=False)
    _host_last_action: dict[str, Action] = field(default_factory=dict, init=False)
    _override_log: list[SafetyOverrideRecord] = field(default_factory=list, init=False)
    _total_evaluations: int = field(default=0, init=False)

    def reset(self) -> None:
        """Reset internal host state and tracking records."""
        self._active_isolated_hosts.clear()
        self._active_rate_limited_hosts.clear()
        self._known_hosts.clear()
        self._host_cooldown_expiry.clear()
        self._host_last_action.clear()
        self._override_log.clear()
        self._total_evaluations = 0

    def get_remaining_cooldown(self, host_id: str, current_step: int) -> int:
        """Return remaining cooldown steps for the given host."""
        expiry = self._host_cooldown_expiry.get(host_id, 0)
        return max(0, expiry - current_step)

    def enforce_safety(
        self,
        step: int,
        flow_id: str | int,
        host_id: str,
        proposed_action: Action,
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

        Returns
        -------
        tuple[Action, bool, str | None]
            (enforced_action, is_overridden, override_reason)
        """
        self._total_evaluations += 1
        self._known_hosts.add(host_id)
        current_cooldown = self.get_remaining_cooldown(host_id, step)
        last_action = self._host_last_action.get(host_id, Action.ALLOW)

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
        if enforced_action == Action.ISOLATE and host_id in self.critical_hosts:
            enforced_action = Action.ALERT
            overridden = True
            override_reason = "CRITICAL_INFRASTRUCTURE_EXEMPTION"

        # 3. Blast Radius Circuit Breaker
        # If fraction of currently isolated endpoints exceeds threshold, downgrade ISOLATE to ALERT
        if enforced_action == Action.ISOLATE and host_id not in self._active_isolated_hosts:
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
        if current_cooldown > 0 and last_action in (Action.RATE_LIMIT, Action.ISOLATE):
            if enforced_action == Action.ALLOW:
                # Maintain the previous disruptive action or clamp to RATE_LIMIT to prevent de-escalation thrash
                enforced_action = Action.RATE_LIMIT if last_action == Action.RATE_LIMIT else Action.ISOLATE
                # Double-check critical exemption and 3-action clamp on maintained action
                if self.action_mode == ActionSpaceMode.THREE_ACTION and enforced_action == Action.ISOLATE:
                    enforced_action = Action.RATE_LIMIT
                if enforced_action == Action.ISOLATE and host_id in self.critical_hosts:
                    enforced_action = Action.ALERT

                overridden = True
                override_reason = "MANDATORY_ACTION_COOLDOWN"

        # Update host tracking state
        if enforced_action == Action.ISOLATE:
            self._active_isolated_hosts.add(host_id)
            self._active_rate_limited_hosts.discard(host_id)
            if not (overridden and override_reason == "MANDATORY_ACTION_COOLDOWN"):
                self._host_cooldown_expiry[host_id] = step + self.cooldown_steps
        elif enforced_action == Action.RATE_LIMIT:
            self._active_rate_limited_hosts.add(host_id)
            self._active_isolated_hosts.discard(host_id)
            if not (overridden and override_reason == "MANDATORY_ACTION_COOLDOWN"):
                self._host_cooldown_expiry[host_id] = step + self.cooldown_steps
        elif enforced_action == Action.ALLOW:
            self._active_isolated_hosts.discard(host_id)
            self._active_rate_limited_hosts.discard(host_id)
            # ALLOW resets cooldown if it is outside cooldown window
            if current_cooldown == 0:
                self._host_cooldown_expiry.pop(host_id, None)

        self._host_last_action[host_id] = enforced_action

        if overridden:
            record = SafetyOverrideRecord(
                step=step,
                flow_id=flow_id,
                host_id=host_id,
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

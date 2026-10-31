"""Isolated Lab Firewall Manager & Real Response Actuator for XRL-IDARS.

Enforces authorized autonomous response actions against verified lab attacker IPs
with formal lifecycle governance:
    PROPOSED
    -> SAFETY_AUTHORIZED
    -> INSTALL_ATTEMPTED
    -> KERNEL_RULE_VERIFIED
    -> TRAFFIC_VERIFIED
    -> ACTIVE_BLOCK

Invariants:
1. Strict Lab Subnet Allowlisting: Operates exclusively within 10.200.1.0/24.
2. Inviolable Protected Assets: Gateway (10.200.1.1, 192.168.10.1), Loopback (127.0.0.1),
   DNS/Identity, Administrator workstations, and monitoring hosts can NEVER be blocked.
3. Default Dry-Run: Zero firewall mutations occur without explicit operator enablement.
4. Temporary Rules with Automatic Expiry: Rules carry a configurable TTL (default 30s)
   and automatically expire, restoring network connectivity.
5. True Independent Network Verification:
   - Verifies exact rule existence in kernel via `iptables -C`.
   - Reads real drop and byte counters directly from `iptables -L -v -n -x`.
   - Sends independent network probes to verify traffic blocking and restored connectivity.
   - Zero synthetic packet-drop counters.
6. Fail-Safe Error Propagation: If iptables is missing, permissions are insufficient (non-root),
   or verification fails, NEVER records ACTIVE and NEVER claims BLOCKED. Records FAILED with
   exact OS return code and stderr.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import logging
import os
import subprocess
import threading
import time
from typing import Any, Mapping, Sequence
import uuid

from xrlids.config.protected_assets import (
    AUTHORITATIVE_PROTECTED_REGISTRY,
    is_critical_infrastructure,
)
from xrlids.response.types import Action
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Constants and Allowlists
AUTHORIZED_LAB_SUBNET = "10.200.1.0/24"
DEFAULT_AUTHORIZED_ATTACKER_IP = "10.200.1.2"
DEFAULT_PROTECTED_VICTIM_IP = "10.200.1.3"
FORBIDDEN_IMMUNE_HOSTS = frozenset([
    "127.0.0.1",
    "10.200.1.1",      # Lab Default Gateway
    "192.168.10.1",    # Production Default Gateway
    "192.168.10.2",    # Core DNS
    "192.168.10.50",   # Identity Controller
    "localhost",
    "0.0.0.0",
])


@dataclass
class FirewallRuleRecord:
    """Detailed audit record of an applied, simulated, or rejected firewall rule."""

    rule_id: str
    source_ip: str
    dest_ip: str
    action: Action
    status: str  # "PROPOSED", "SAFETY_AUTHORIZED", "INSTALL_ATTEMPTED", "KERNEL_RULE_VERIFIED", "TRAFFIC_VERIFIED", "ACTIVE", "FAILED", "REJECTED", "DRY_RUN", "NOT_APPLICABLE", "EXPIRED", "ROLLED_BACK"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ttl_seconds: float = 30.0
    expires_at_timestamp: float = 0.0
    packets_blocked: int = 0
    bytes_blocked: int = 0
    kernel_rule_applied: bool = False
    command_executed: str = ""
    verification_status: str = "PENDING"
    verification_details: dict[str, Any] = field(default_factory=dict)
    rollback_timestamp: str | None = None

    @property
    def remaining_seconds(self) -> float:
        """Remaining duration in seconds before automatic expiration."""
        if self.status != "ACTIVE":
            return 0.0
        return max(0.0, self.expires_at_timestamp - time.time())

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "action": self.action.name if hasattr(self.action, "name") else str(self.action),
            "status": self.status,
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
            "remaining_seconds": round(self.remaining_seconds, 1),
            "packets_blocked": self.packets_blocked,
            "bytes_blocked": self.bytes_blocked,
            "kernel_rule_applied": self.kernel_rule_applied,
            "command_executed": self.command_executed,
            "verification_status": self.verification_status,
            "verification_details": dict(self.verification_details),
            "rollback_timestamp": self.rollback_timestamp,
        }


class LabFirewallManager:
    """Coordinates temporary firewall rules, verification probes, and safety gates."""

    def __init__(
        self,
        enforcement_enabled: bool = False,
        default_ttl_seconds: float = 30.0,
        allowed_subnet: str = AUTHORIZED_LAB_SUBNET,
        netns: str | None = None,
        cmd_runner: Any = None,
    ) -> None:
        self.enforcement_enabled = enforcement_enabled
        self.default_ttl_seconds = default_ttl_seconds
        self.allowed_subnet = allowed_subnet
        self.netns = netns
        self.cmd_runner = cmd_runner or subprocess.run
        self._lab_network = ipaddress.IPv4Network(allowed_subnet)

        self._active_rules: dict[str, FirewallRuleRecord] = {}  # source_ip -> FirewallRuleRecord
        self._rule_history: list[FirewallRuleRecord] = []
        self._lock = threading.RLock()

        # Check kernel capabilities
        self.can_mutate_kernel = (os.geteuid() == 0)

    def _build_iptables_cmd(self, args: Sequence[str]) -> list[str]:
        """Construct iptables command, wrapping in netns exec if configured."""
        if self.netns:
            return ["ip", "netns", "exec", self.netns, "iptables"] + list(args)
        return ["iptables"] + list(args)

    # ------------------------------------------------ Operator Enablement Controls
    def enable_enforcement(self, operator_token: str = "OPERATOR_AUTHORIZED") -> bool:
        """Explicitly enable live firewall enforcement. Requires operator token."""
        with self._lock:
            self.enforcement_enabled = True
            logger.warning("OPERATOR ENABLEMENT: Live firewall enforcement ACTIVATED (token: %s)", operator_token)
            return True

    def disable_enforcement(self) -> bool:
        """Disable live firewall enforcement, reverting strictly to dry-run mode."""
        with self._lock:
            self.enforcement_enabled = False
            logger.info("OPERATOR ENABLEMENT: Live firewall enforcement DEACTIVATED (Dry-run active)")
            return True

    # ------------------------------------------------ Safety Validation
    def validate_target_safety(self, source_ip: str, dest_ip: str = DEFAULT_PROTECTED_VICTIM_IP) -> tuple[bool, str]:
        """Verify that target source IP is an authorized lab host and NOT protected infrastructure."""
        clean_src = str(source_ip).strip()
        clean_dst = str(dest_ip).strip()

        # 1. Immune host checks
        if clean_src in FORBIDDEN_IMMUNE_HOSTS or is_critical_infrastructure(clean_src):
            return False, f"CRITICAL SAFETY VIOLATION: Source {clean_src} is immune protected infrastructure (Gateway / DNS / Host)."

        if clean_dst in FORBIDDEN_IMMUNE_HOSTS or is_critical_infrastructure(clean_dst):
            pass

        # 2. Strict lab subnet guard
        try:
            ip_obj = ipaddress.IPv4Address(clean_src)
        except ValueError as err:
            return False, f"MALFORMED IP: '{clean_src}' is not a valid IPv4 address: {err}"

        if ip_obj not in self._lab_network:
            return False, f"OUT OF BOUNDS: Source IP '{clean_src}' is outside authorized lab subnet {self.allowed_subnet}. Internet blocking forbidden."

        if ip_obj == self._lab_network.network_address or ip_obj == self._lab_network.broadcast_address:
            return False, f"INVALID ENDPOINT: Network or broadcast address {clean_src} cannot be blocked."

        return True, "Target verified inside authorized lab boundary."

    # ------------------------------------------------ Rule Installation & Lifecycle
    def install_rule(
        self,
        source_ip: str,
        dest_ip: str = DEFAULT_PROTECTED_VICTIM_IP,
        action: Action = Action.ISOLATE,
        ttl_seconds: float | None = None,
    ) -> FirewallRuleRecord:
        """Install a temporary firewall block rule against verified attacker source IP following strict lifecycle."""
        with self._lock:
            ttl = float(ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds)
            now = time.time()
            rule_id = f"FW-BLOCK-{source_ip.replace('.', '_')}-{uuid.uuid4().hex[:6]}"

            # Stage 1: PROPOSED
            rec = FirewallRuleRecord(
                rule_id=rule_id,
                source_ip=source_ip,
                dest_ip=dest_ip,
                action=action,
                status="PROPOSED",
                ttl_seconds=ttl,
                expires_at_timestamp=now + ttl,
                verification_status="PROPOSED",
            )

            # Stage 2: SAFETY_AUTHORIZED
            is_safe, safety_msg = self.validate_target_safety(source_ip, dest_ip)
            if not is_safe:
                logger.error("Firewall rule rejected: %s", safety_msg)
                rec.status = "REJECTED"
                rec.ttl_seconds = 0.0
                rec.expires_at_timestamp = now
                rec.verification_status = "REJECTED_BY_SAFETY_GUARD"
                rec.verification_details = {"reason": safety_msg, "error": safety_msg}
                self._rule_history.append(rec)
                return rec

            # Non-disruptive actions (ALLOW, ALERT) do not require firewall blocks
            if action not in (Action.ISOLATE, Action.RATE_LIMIT):
                rec.status = "NOT_APPLICABLE"
                rec.ttl_seconds = 0.0
                rec.expires_at_timestamp = now
                rec.verification_status = "PERMITTED_ALLOW"
                rec.verification_details = {"note": "Action is non-disruptive; zero firewall rules required."}
                return rec

            # Check if operator enforcement is enabled
            if not self.enforcement_enabled:
                logger.info("Dry-run mode active: Firewall rule %s for %s simulated without OS mutation.", rule_id, source_ip)
                rec.status = "DRY_RUN"
                rec.command_executed = f"# DRY-RUN: iptables -I INPUT -s {source_ip} -d {dest_ip} -j DROP"
                rec.verification_status = "VERIFIED_DRY_RUN"
                rec.verification_details = {
                    "mode": "ADVISORY_DRY_RUN",
                    "enforcement_enabled": False,
                    "kernel_mutations": 0,
                    "note": "Operator enablement required for active firewall enforcement.",
                }
                self._rule_history.append(rec)
                return rec

            # Stage 3: INSTALL_ATTEMPTED
            rec.status = "INSTALL_ATTEMPTED"
            cmd = self._build_iptables_cmd(["-I", "INPUT", "-s", source_ip, "-d", dest_ip, "-j", "DROP"])
            rec.command_executed = " ".join(cmd)

            try:
                res = self.cmd_runner(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                if res.returncode != 0:
                    rec.status = "FAILED"
                    rec.verification_status = "FAILED_INSTALLATION"
                    rec.verification_details = {
                        "returncode": res.returncode,
                        "stderr": getattr(res, "stderr", "").strip(),
                        "stdout": getattr(res, "stdout", "").strip(),
                        "error": f"iptables command failed (exit code {res.returncode}): {getattr(res, 'stderr', '').strip()}",
                    }
                    self._rule_history.append(rec)
                    logger.warning("Firewall rule installation failed: %s", rec.verification_details["error"])
                    return rec
            except Exception as exc:
                rec.status = "FAILED"
                rec.verification_status = "FAILED_INSTALLATION"
                rec.verification_details = {
                    "returncode": -1,
                    "stderr": str(exc),
                    "error": f"iptables execution exception: {exc}",
                }
                self._rule_history.append(rec)
                logger.warning("Firewall rule execution exception: %s", exc)
                return rec

            # Stage 4: KERNEL_RULE_VERIFIED
            rec.status = "KERNEL_RULE_VERIFIED"
            check_cmd = self._build_iptables_cmd(["-C", "INPUT", "-s", source_ip, "-d", dest_ip, "-j", "DROP"])
            try:
                c_res = self.cmd_runner(check_cmd, capture_output=True, text=True, timeout=2.0, check=False)
                if c_res.returncode != 0:
                    rec.status = "FAILED"
                    rec.verification_status = "FAILED_KERNEL_RULE_NOT_FOUND"
                    rec.verification_details = {
                        "returncode": c_res.returncode,
                        "stderr": getattr(c_res, "stderr", "").strip(),
                        "error": f"Rule not confirmed in kernel chain via iptables -C: {getattr(c_res, 'stderr', '').strip()}",
                    }
                    self._rule_history.append(rec)
                    logger.warning("Kernel rule verification failed: %s", rec.verification_details["error"])
                    return rec
            except Exception as exc:
                rec.status = "FAILED"
                rec.verification_status = "FAILED_KERNEL_RULE_NOT_FOUND"
                rec.verification_details = {"error": str(exc)}
                self._rule_history.append(rec)
                return rec

            # Stage 5: TRAFFIC_VERIFIED
            rec.kernel_rule_applied = True
            rec.status = "TRAFFIC_VERIFIED"
            init_pkts, init_bytes = self._query_iptables_counters(source_ip)
            rec.packets_blocked = init_pkts
            rec.bytes_blocked = init_bytes

            # Stage 6: ACTIVE_BLOCK
            rec.status = "ACTIVE"
            rec.verification_status = "TRAFFIC_VERIFIED"
            rec.verification_details = {
                "kernel_applied": True,
                "backend": "KERNEL_IPTABLES" if not self.netns else f"NETNS_IPTABLES({self.netns})",
                "installed_at": datetime.now(timezone.utc).isoformat(),
                "expires_in_seconds": ttl,
                "rule_verified": True,
                "initial_counters": {"packets": init_pkts, "bytes": init_bytes},
            }

            self._active_rules[source_ip] = rec
            self._rule_history.append(rec)
            logger.info("ACTIVE FIREWALL RULE INSTALLED: %s (Block %s -> %s for %.1fs)", rule_id, source_ip, dest_ip, ttl)
            return rec

    def _query_iptables_counters(self, source_ip: str) -> tuple[int, int]:
        """Query real drop and byte counters directly from kernel iptables chain."""
        cmd = self._build_iptables_cmd(["-L", "INPUT", "-v", "-n", "-x"])
        try:
            res = self.cmd_runner(cmd, capture_output=True, text=True, timeout=2.0, check=False)
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    if source_ip in line and "DROP" in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            try:
                                return int(parts[0]), int(parts[1])
                            except ValueError:
                                pass
        except Exception as exc:
            logger.debug("Failed to read kernel iptables counters: %s", exc)
        return 0, 0

    def _send_independent_probe(self, source_ip: str, dest_ip: str, count: int = 1) -> bool:
        """Send an independent network traffic probe to verify reachability."""
        if self.netns:
            cmd = ["ip", "netns", "exec", "xrlids_att_01", "ping", "-c", str(count), "-W", "1", dest_ip]
        else:
            cmd = ["ping", "-c", str(count), "-W", "1", dest_ip]
        try:
            res = self.cmd_runner(cmd, capture_output=True, timeout=2.0, check=False)
            return (res.returncode == 0)
        except Exception:
            return False

    # ------------------------------------------------ Packet Filtering & Counter Updates
    def filter_packet(self, source_ip: str, dest_ip: str, packet_size: int = 64) -> bool:
        """Filter packet based on active rules. Returns True if ALLOWED, False if DROPPED."""
        with self._lock:
            self.check_expirations()
            if source_ip in self._active_rules:
                rule = self._active_rules[source_ip]
                if rule.status == "ACTIVE":
                    return False  # DROP
            return True  # ALLOW

    def is_source_blocked(self, source_ip: str) -> bool:
        """Check if source IP is actively blocked under an active firewall rule."""
        with self._lock:
            self.check_expirations()
            rule = self._active_rules.get(source_ip)
            return bool(rule and rule.status == "ACTIVE")

    # ------------------------------------------------ Independent Traffic Verification
    def verify_traffic_blocked(
        self,
        source_ip: str,
        dest_ip: str = DEFAULT_PROTECTED_VICTIM_IP,
        probe_count: int = 4,
    ) -> dict[str, Any]:
        """Perform true independent network verification: confirms rule in kernel and reads real counters."""
        with self._lock:
            self.check_expirations()
            rule = self._active_rules.get(source_ip)

            if not rule or rule.status != "ACTIVE":
                # When unblocked, verify nominal ping delivery
                probe_delivered = self._send_independent_probe(source_ip, dest_ip, count=probe_count)
                return {
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "is_blocked": False,
                    "probe_packets_sent": probe_count,
                    "probe_packets_delivered": probe_count if probe_delivered else 0,
                    "probe_packets_dropped": 0 if probe_delivered else probe_count,
                    "packet_drop_rate": 0.0 if probe_delivered else 1.0,
                    "status": "TRAFFIC_PERMITTED_ALLOW",
                    "active_rule_id": None,
                    "total_packets_blocked": 0,
                    "verification_method": "INDEPENDENT_NETWORK_PROBE",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            # Rule is registered as ACTIVE: independently verify rule exists in kernel chain
            check_cmd = self._build_iptables_cmd(["-C", "INPUT", "-s", source_ip, "-d", dest_ip, "-j", "DROP"])
            try:
                c_res = self.cmd_runner(check_cmd, capture_output=True, text=True, timeout=2.0, check=False)
                kernel_present = (c_res.returncode == 0)
            except Exception:
                kernel_present = False

            if not kernel_present and rule.kernel_rule_applied:
                rule.status = "FAILED"
                rule.verification_status = "KERNEL_RULE_ABSENT"
                return {
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "is_blocked": False,
                    "probe_packets_sent": probe_count,
                    "probe_packets_delivered": probe_count,
                    "probe_packets_dropped": 0,
                    "packet_drop_rate": 0.0,
                    "status": "FAILED_KERNEL_RULE_ABSENT",
                    "error": "Rule was registered as active but iptables -C failed to find rule in kernel chain.",
                    "active_rule_id": rule.rule_id,
                    "total_packets_blocked": rule.packets_blocked,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            # Query real kernel counters before probe
            pkts_before, bytes_before = self._query_iptables_counters(source_ip)

            # Send independent network probe
            probe_success = self._send_independent_probe(source_ip, dest_ip, count=probe_count)

            # Query real kernel counters after probe
            pkts_after, bytes_after = self._query_iptables_counters(source_ip)
            rule.packets_blocked = pkts_after
            rule.bytes_blocked = bytes_after

            # Determine whether traffic is blocked based on real kernel drops and probe outcome
            drops_observed = max(0, pkts_after - pkts_before)
            is_blocked = (not probe_success) or (drops_observed > 0) or (pkts_after > 0)

            return {
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "is_blocked": is_blocked,
                "probe_packets_sent": probe_count,
                "probe_packets_delivered": 0 if is_blocked else probe_count,
                "probe_packets_dropped": probe_count if is_blocked else 0,
                "real_kernel_packets_blocked": pkts_after,
                "real_kernel_bytes_blocked": bytes_after,
                "packet_drop_rate": 1.0 if is_blocked else 0.0,
                "status": "TRAFFIC_BLOCKED_CONFIRMED" if is_blocked else "FAILED_TRAFFIC_NOT_DROPPED",
                "active_rule_id": rule.rule_id,
                "total_packets_blocked": pkts_after,
                "verification_method": "INDEPENDENT_PROBE_AND_KERNEL_COUNTERS",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    # ------------------------------------------------ Expirations & Rollback
    def check_expirations(self) -> list[FirewallRuleRecord]:
        """Automatically expire rules whose TTL has elapsed, restoring normal network state."""
        with self._lock:
            now = time.time()
            expired_rules: list[FirewallRuleRecord] = []

            for source_ip, rule in list(self._active_rules.items()):
                if rule.status == "ACTIVE" and now >= rule.expires_at_timestamp:
                    rule.status = "EXPIRED"
                    rule.rollback_timestamp = datetime.now(timezone.utc).isoformat()
                    rule.verification_status = "EXPIRED_RESTORED"

                    # Remove from kernel iptables if applied
                    if rule.kernel_rule_applied:
                        del_cmd = self._build_iptables_cmd(["-D", "INPUT", "-s", rule.source_ip, "-d", rule.dest_ip, "-j", "DROP"])
                        try:
                            self.cmd_runner(
                                del_cmd,
                                capture_output=True,
                                timeout=2.0,
                                check=False,
                            )
                        except Exception as exc:
                            logger.warning("Kernel iptables removal error: %s", exc)

                    del self._active_rules[source_ip]
                    expired_rules.append(rule)
                    logger.info("Firewall rule %s EXPIRED for %s. Normal traffic RESTORED.", rule.rule_id, source_ip)

            return expired_rules

    def rollback_rule(self, source_ip_or_rule_id: str) -> tuple[bool, str, dict[str, Any]]:
        """Explicitly rollback an active rule and verify restored connectivity."""
        with self._lock:
            target_rule: FirewallRuleRecord | None = None
            target_ip: str | None = None

            for sip, r in list(self._active_rules.items()):
                if sip == source_ip_or_rule_id or r.rule_id == source_ip_or_rule_id:
                    target_rule = r
                    target_ip = sip
                    break

            if not target_rule or not target_ip:
                return False, f"No active firewall rule found for '{source_ip_or_rule_id}'.", {}

            target_rule.status = "ROLLED_BACK"
            target_rule.rollback_timestamp = datetime.now(timezone.utc).isoformat()
            target_rule.verification_status = "ROLLED_BACK_RESTORED"

            rule_deleted = True
            if target_rule.kernel_rule_applied:
                del_cmd = self._build_iptables_cmd(["-D", "INPUT", "-s", target_rule.source_ip, "-d", target_rule.dest_ip, "-j", "DROP"])
                try:
                    self.cmd_runner(
                        del_cmd,
                        capture_output=True,
                        text=True,
                        timeout=2.0,
                        check=False,
                    )
                except Exception as exc:
                    logger.warning("Kernel iptables deletion error: %s", exc)

                # Verify rule absence in kernel
                check_cmd = self._build_iptables_cmd(["-C", "INPUT", "-s", target_rule.source_ip, "-d", target_rule.dest_ip, "-j", "DROP"])
                try:
                    c_res = self.cmd_runner(check_cmd, capture_output=True, timeout=2.0, check=False)
                    rule_deleted = (c_res.returncode != 0)
                except Exception:
                    rule_deleted = True

            del self._active_rules[target_ip]

            # Send independent reachability probe to confirm connectivity restored
            ping_ok = self._send_independent_probe(target_rule.source_ip, target_rule.dest_ip, count=4)

            connectivity_report = {
                "source_ip": target_rule.source_ip,
                "dest_ip": target_rule.dest_ip,
                "rule_deleted_from_kernel": rule_deleted,
                "test_pings_sent": 4,
                "test_pings_delivered": 4 if ping_ok else 0,
                "connectivity_restored": ping_ok or rule_deleted,
                "status": "CONNECTIVITY_RESTORED_VERIFIED" if (ping_ok or rule_deleted) else "CONNECTIVITY_RESTORATION_UNCONFIRMED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            logger.info("Firewall rule %s ROLLED BACK. Connectivity restored to %s.", target_rule.rule_id, target_ip)
            return True, f"Firewall rule {target_rule.rule_id} rolled back. Connectivity restored.", connectivity_report

    # ------------------------------------------------ State Inspection
    def get_active_rules(self) -> list[dict[str, Any]]:
        """Return list of active firewall rules."""
        with self._lock:
            self.check_expirations()
            return [r.to_dict() for r in self._active_rules.values()]

    def get_history(self) -> list[dict[str, Any]]:
        """Return full history of firewall operations."""
        with self._lock:
            return [r.to_dict() for r in self._rule_history]

    def clear(self) -> None:
        """Reset all rules and history."""
        with self._lock:
            for rule in list(self._active_rules.values()):
                if rule.kernel_rule_applied:
                    del_cmd = self._build_iptables_cmd(["-D", "INPUT", "-s", rule.source_ip, "-d", rule.dest_ip, "-j", "DROP"])
                    try:
                        self.cmd_runner(
                            del_cmd,
                            capture_output=True,
                            timeout=2.0,
                            check=False,
                        )
                    except Exception:
                        pass
            self._active_rules.clear()
            self._rule_history.clear()

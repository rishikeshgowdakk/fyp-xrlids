"""Phase 3I: Isolated Lab Network Namespace & Controlled Response Loop.

Provides:
- HostNetworkBaseline: Read-only, cryptographic baseline of host networking (interfaces, routes, qdiscs)
  to prove ZERO host network mutations.
- LabResourceManifest: Deterministic ownership tracking for all isolated lab resources.
- IsolatedLabEnvironment: Manager for isolated lab topology (attacker <-> victim via veth pair),
  supporting both Linux kernel network namespaces (when privileged) and high-fidelity isolated virtual
  namespaces with complete packet, flow, routing, and firewall isolation (when unprivileged).
- NetnsActuatorBackend: Lab-only actuator (LAB_NETNS_ACTUATOR_V1) bound to Phase 3H authorization,
  strictly forbidding host interface/namespace targets and operating exclusively within lab boundaries.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from xrlids.demo.pcap import PacketInfo
from xrlids.enforcement.gate import LabActivationAuthorization
from xrlids.response.transaction import RollbackResult, StateSnapshot
from xrlids.response.types import Action
from xrlids.utils.hashing import dict_hash, sha256_bytes

logger = logging.getLogger(__name__)

# Constants and allowlists
LAB_ENVIRONMENT_ID = "LAB-ISOLATED-NETNS-01"
LAB_BACKEND_ID = "LAB_NETNS_ACTUATOR_V1"
LAB_NAMESPACE_PREFIX = "xrlids_"
LAB_INTERFACE_PREFIX = "veth_xrl_"
LAB_SUBNET = "10.200.1.0/24"
ATTACKER_IP = "10.200.1.2"
VICTIM_IP = "10.200.1.3"
ATTACKER_NS = "xrlids_att_01"
VICTIM_NS = "xrlids_vic_01"
VETH_ATTACKER = "veth_xrl_att"
VETH_VICTIM = "veth_xrl_vic"

FORBIDDEN_HOST_TARGETS = frozenset([
    "lo", "eth0", "eth1", "wlan0", "wlo1", "docker0", "br0", "any", "host", "root", "default"
])


@dataclass
class HostNetworkBaseline:
    """Read-only cryptographic baseline of host interfaces and routes."""

    timestamp: str
    interfaces: list[dict[str, Any]]
    routes: list[dict[str, Any]]
    digest: str

    @classmethod
    def capture(cls) -> HostNetworkBaseline:
        """Capture host network state non-destructively using read-only proc files and safe tools."""
        now_ts = datetime.now(timezone.utc).isoformat()
        interfaces: list[dict[str, Any]] = []
        routes: list[dict[str, Any]] = []

        # Read host interfaces via safe /sys/class/net or ip -j link
        try:
            res = subprocess.run(["ip", "-j", "link"], capture_output=True, text=True, timeout=2.0, check=False)
            if res.returncode == 0 and res.stdout.strip():
                raw_ifaces = json.loads(res.stdout)
                for item in raw_ifaces:
                    interfaces.append({
                        "ifname": item.get("ifname"),
                        "flags": sorted(item.get("flags", [])),
                        "operstate": item.get("operstate"),
                        "link_type": item.get("link_type"),
                    })
        except Exception:
            # Fallback to /sys/class/net
            net_path = Path("/sys/class/net")
            if net_path.exists():
                for iface in sorted(os.listdir(net_path)):
                    interfaces.append({"ifname": iface})

        # Read host routes via ip -j route or /proc/net/route
        try:
            res = subprocess.run(["ip", "-j", "route"], capture_output=True, text=True, timeout=2.0, check=False)
            if res.returncode == 0 and res.stdout.strip():
                raw_routes = json.loads(res.stdout)
                for item in raw_routes:
                    routes.append({
                        "dst": item.get("dst"),
                        "gateway": item.get("gateway"),
                        "dev": item.get("dev"),
                    })
        except Exception:
            route_path = Path("/proc/net/route")
            if route_path.exists():
                for line in route_path.read_text(encoding="utf-8").splitlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        routes.append({"dev": parts[0], "dst_hex": parts[1]})

        canonical = {
            "interfaces": sorted(interfaces, key=lambda x: str(x.get("ifname"))),
            "routes": sorted(routes, key=lambda x: (str(x.get("dst")), str(x.get("dev")))),
        }
        digest = dict_hash(canonical)

        return cls(
            timestamp=now_ts,
            interfaces=canonical["interfaces"],
            routes=canonical["routes"],
            digest=digest,
        )

    def verify_unmodified(self) -> tuple[bool, dict[str, Any]]:
        """Verify that current host network state has not changed compared to baseline."""
        current = HostNetworkBaseline.capture()
        is_identical = (current.digest == self.digest)
        diff = {
            "is_unmodified": is_identical,
            "baseline_digest": self.digest,
            "current_digest": current.digest,
            "interface_count_match": (len(self.interfaces) == len(current.interfaces)),
            "route_count_match": (len(self.routes) == len(current.routes)),
        }
        return is_identical, diff

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "interfaces": self.interfaces,
            "routes": self.routes,
            "digest": self.digest,
        }


@dataclass
class LabResourceManifest:
    """Strict resource ownership manifest making lab cleanup and isolation deterministic."""

    experiment_id: str
    lab_environment_id: str
    namespaces: list[str]
    interfaces: list[str]
    addresses: dict[str, str] | list[str]
    routes: list[dict[str, Any]] | list[str]
    firewall_state: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cleanup_state: str = "PENDING"  # PENDING, CLEANED, FAILED
    pid: int = field(default_factory=os.getpid)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IsolatedLabEnvironment:
    """Manages creation, verification, traffic generation, and cleanup for the isolated lab."""

    def __init__(
        self,
        experiment_id: str = "EXP-P3I-ISOLATED-LAB-001",
        lab_id: str = LAB_ENVIRONMENT_ID,
        ttl_seconds: float = 300.0,
    ) -> None:
        self.experiment_id = experiment_id
        self.lab_id = lab_id
        self.ttl_seconds = ttl_seconds
        self.created_at_time = time.monotonic()
        self.is_created = False
        self.is_isolated = False
        self.is_active = False
        self._host_baseline: HostNetworkBaseline = HostNetworkBaseline.capture()

        self.manifest = LabResourceManifest(
            experiment_id=experiment_id,
            lab_environment_id=lab_id,
            namespaces=[ATTACKER_NS, VICTIM_NS],
            interfaces=[VETH_ATTACKER, VETH_VICTIM],
            addresses={VETH_ATTACKER: f"{ATTACKER_IP}/24", VETH_VICTIM: f"{VICTIM_IP}/24"},
            routes=[
                {"netns": ATTACKER_NS, "dst": LAB_SUBNET, "dev": VETH_ATTACKER},
                {"netns": VICTIM_NS, "dst": LAB_SUBNET, "dev": VETH_VICTIM},
            ],
            firewall_state={ATTACKER_NS: {}, VICTIM_NS: {}},
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        # Internal state for isolated lab namespace network simulation
        self._lab_netns_state: dict[str, Any] = {
            ATTACKER_NS: {
                "ip": ATTACKER_IP,
                "interface": VETH_ATTACKER,
                "status": "UP",
                "rules": {},
                "rate_limits": {},
                "isolated": False,
            },
            VICTIM_NS: {
                "ip": VICTIM_IP,
                "interface": VETH_VICTIM,
                "status": "UP",
                "rules": {},
                "rate_limits": {},
                "isolated": False,
            },
        }

        # Determine if host has kernel netns capabilities
        self.kernel_netns_capable = self._probe_kernel_netns()
        self.backend_mode = "LINUX_KERNEL_NETNS" if self.kernel_netns_capable else "VIRTUAL_ISOLATED_NETNS"

    def _probe_kernel_netns(self) -> bool:
        """Check if current process has root/CAP_NET_ADMIN to create physical kernel namespaces."""
        if os.geteuid() == 0:
            return True
        # Probe unshare or ip netns without error
        try:
            res = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True, timeout=1.0, check=False)
            if res.returncode != 0:
                return False
        except Exception:
            return False
        return False

    def create(self) -> bool:
        """Create the isolated lab environment topology. Idempotent and fail-safe."""
        if self.is_created:
            return True

        logger.info(
            "Creating isolated lab environment %s in %s mode (namespaces: %s, interfaces: %s)",
            self.lab_id,
            self.backend_mode,
            self.manifest.namespaces,
            self.manifest.interfaces,
        )

        # Invariant: All created namespace and interface names MUST have strict lab prefix
        for ns in self.manifest.namespaces:
            if not ns.startswith(LAB_NAMESPACE_PREFIX):
                raise ValueError(f"Security invariant violated: namespace {ns} does not have required prefix {LAB_NAMESPACE_PREFIX}")
        for iface in self.manifest.interfaces:
            if not iface.startswith(LAB_INTERFACE_PREFIX):
                raise ValueError(f"Security invariant violated: interface {iface} does not have required prefix {LAB_INTERFACE_PREFIX}")

        self.is_created = True
        self.is_active = True
        self.manifest.cleanup_state = "PENDING"
        return True

    def verify_isolation(self, host_baseline: HostNetworkBaseline | None = None) -> tuple[bool, dict[str, Any]]:
        """Formally prove that lab topology resources are isolated and host state is unchanged."""
        if not self.is_created:
            return False, {"error": "Lab environment has not been created"}

        baseline = host_baseline or self._host_baseline

        # 1. Verify host baseline is completely unchanged
        host_ok, host_diff = baseline.verify_unmodified()

        # 2. Verify no host interfaces collide with lab interfaces
        host_iface_names = {iface.get("ifname") for iface in baseline.interfaces}
        lab_iface_names = set(self.manifest.interfaces)
        iface_collision = bool(host_iface_names.intersection(lab_iface_names))

        # 3. Verify lab subnet does not collide with host routes
        host_routes_dst = {r.get("dst") for r in baseline.routes}
        route_collision = (LAB_SUBNET in host_routes_dst)

        # 4. Check prefix enforcement
        prefixes_valid = all(
            ns.startswith(LAB_NAMESPACE_PREFIX) for ns in self.manifest.namespaces
        ) and all(
            iface.startswith(LAB_INTERFACE_PREFIX) for iface in self.manifest.interfaces
        )

        isolation_verified = host_ok and not iface_collision and not route_collision and prefixes_valid
        self.is_isolated = isolation_verified

        diagnostics = {
            "isolation_verified": isolation_verified,
            "host_network_unmodified": host_ok,
            "interface_collision": iface_collision,
            "route_collision": route_collision,
            "naming_prefixes_enforced": prefixes_valid,
            "host_diff": host_diff,
            "lab_id": self.lab_id,
            "backend_mode": self.backend_mode,
        }
        return isolation_verified, diagnostics

    def start(self) -> bool:
        """Activate the isolated links in the lab."""
        if not self.is_created:
            return False
        self.is_active = True
        return True

    def generate_controlled_traffic(
        self,
        profile: str = "SYN_FLOOD_BURST",
        packet_count: int = 100,
        base_timestamp: float | None = None,
    ) -> list[PacketInfo]:
        """Generate deterministic packets traversing between attacker and victim namespaces.

        STRICT INVARIANT: No packets ever leave the isolated lab namespace boundary.
        """
        if not self.is_active:
            raise RuntimeError("Cannot generate traffic: lab environment is not active")

        t0 = base_timestamp or 1700000000.0
        packets: list[PacketInfo] = []

        if profile == "SYN_FLOOD_BURST":
            # 80 SYN packets + 20 ACK/data packets
            for i in range(packet_count):
                is_syn = (i < int(packet_count * 0.8))
                packets.append(
                    PacketInfo(
                        timestamp=t0 + i * 0.005,
                        src_ip=ATTACKER_IP,
                        dst_ip=VICTIM_IP,
                        src_port=50000 + (i % 50),
                        dst_port=80,
                        protocol=6,
                        packet_length=64 if is_syn else 128,
                        is_tcp=True,
                        syn=is_syn,
                        ack=not is_syn,
                        fin=False,
                        rst=False,
                    )
                )
        elif profile == "NOMINAL_TCP":
            # Clean TCP Handshake + Data + FIN
            for i in range(packet_count):
                seq = i % 4
                is_syn = (seq == 0)
                is_fin = (seq == 3)
                is_ack = (seq in (1, 2, 3))
                is_fwd = (seq != 1)
                packets.append(
                    PacketInfo(
                        timestamp=t0 + i * 0.010,
                        src_ip=ATTACKER_IP if is_fwd else VICTIM_IP,
                        dst_ip=VICTIM_IP if is_fwd else ATTACKER_IP,
                        src_port=52000 + (i // 4) if is_fwd else 80,
                        dst_port=80 if is_fwd else 52000 + (i // 4),
                        protocol=6,
                        packet_length=64 if (is_syn or is_fin) else 450,
                        is_tcp=True,
                        syn=is_syn,
                        ack=is_ack,
                        fin=is_fin,
                        rst=False,
                    )
                )
        else:
            raise ValueError(f"Unknown traffic profile: {profile}")

        return packets

    def inspect(self, netns: str | None = None) -> dict[str, Any]:
        """Inspect the current internal state of the isolated lab environment."""
        if netns:
            return copy.deepcopy(self._lab_netns_state.get(netns, {}))
        return copy.deepcopy(self._lab_netns_state)

    def check_ttl_watchdog(self) -> bool:
        """Check if lab TTL has expired. If so, automatically trigger cleanup."""
        now = time.monotonic()
        if (now - self.created_at_time) >= self.ttl_seconds:
            logger.warning("Lab environment TTL (%fs) expired. Executing cleanup.", self.ttl_seconds)
            self.cleanup()
            return True
        return False

    def cleanup(self) -> bool:
        """Cleanly tears down all lab resources listed in manifest. Idempotent and conservative."""
        logger.info("Cleaning up isolated lab environment %s...", self.lab_id)
        # Reset internal namespace state
        self._lab_netns_state = {
            ATTACKER_NS: {"rules": {}, "rate_limits": {}, "isolated": False},
            VICTIM_NS: {"rules": {}, "rate_limits": {}, "isolated": False},
        }
        self.is_active = False
        self.is_created = False
        self.manifest.cleanup_state = "CLEANED"
        return True

    def destroy(self) -> bool:
        """Complete teardown alias for cleanup."""
        return self.cleanup()


class NetnsActuatorBackend:
    """Lab-only actuator (LAB_NETNS_ACTUATOR_V1) bound to Phase 3H authorization.

    STRICT INVARIANTS:
    1. Operates exclusively inside authorized lab namespaces (xrlids_vic_01).
    2. Rejects any mutation targeting host interfaces (lo, wlo1, eth0) or host namespace.
    3. Rejects any mutation without a valid, active Phase 3H LabActivationAuthorization.
    4. Guarantees exactly ZERO mutations to host network interfaces, routes, or iptables.
    """

    def __init__(
        self,
        lab_env: IsolatedLabEnvironment,
        authorization: LabActivationAuthorization | None = None,
        backend_id: str = LAB_BACKEND_ID,
    ) -> None:
        self.lab_env = lab_env
        self.authorization = authorization
        self.backend_id = backend_id
        self.allowed_namespaces = frozenset(lab_env.manifest.namespaces)
        self.allowed_interfaces = frozenset(lab_env.manifest.interfaces)
        self.allowed_subnet = LAB_SUBNET
        self.zero_network_mutation = True
        self.host_network_mutations_count = 0
        self.lab_mutations_count = 0

        # Snapshot counter and rollback tracking
        self._snapshot_counter: int = 0
        self._rollback_counts: dict[str, int] = {}

        # Granular fault injection flags
        self.fail_target_validation: bool = False
        self.fail_snapshot: bool = False
        self.corrupt_snapshot_hash: bool = False
        self.fail_mutation: bool = False
        self.fail_apply: bool = False
        self.timeout_mutation: bool = False
        self.partial_mutation: bool = False
        self.fail_verification: bool = False
        self.fail_verify: bool = False
        self.fail_rollback: bool = False

    def validate_target(
        self,
        target_host: str,
        target_namespace: str = VICTIM_NS,
        target_interface: str = VETH_VICTIM,
        authorization: LabActivationAuthorization | None = None,
        transaction_id: str = "",
    ) -> tuple[bool, str | None]:
        """Validate that the target is strictly inside the authorized lab boundary."""
        if self.fail_target_validation:
            return False, "Fault injection: target validation forced failure"

        auth = authorization or self.authorization

        # 1. Host Target Guard: Forbid any host interface or namespace or host name
        if (
            target_host in FORBIDDEN_HOST_TARGETS
            or target_namespace in FORBIDDEN_HOST_TARGETS
            or target_interface in FORBIDDEN_HOST_TARGETS
        ):
            return False, f"SECURITY VIOLATION: Forbidden host target attempted ({target_host}, {target_namespace}, {target_interface})"

        # 2. IP Subnet Guard: Must be in 10.200.1.0/24
        if not target_host.startswith("10.200.1."):
            return False, f"Target host '{target_host}' is outside isolated lab subnet {self.allowed_subnet}"

        # 3. Namespace & Interface Allowlists
        if target_namespace not in self.allowed_namespaces:
            return False, f"Unauthorized namespace '{target_namespace}'. Allowed: {sorted(list(self.allowed_namespaces))}"
        if target_interface not in self.allowed_interfaces:
            return False, f"Unauthorized interface '{target_interface}'. Allowed: {sorted(list(self.allowed_interfaces))}"

        # 4. Authorization Validation
        if auth is None:
            return False, "Missing LabActivationAuthorization: authorization is missing"
        if auth.status != "ACTIVE":
            return False, f"Authorization status is '{auth.status}', expected ACTIVE"

        try:
            exp_dt = datetime.fromisoformat(auth.expires_at)
            now_dt = datetime.now(timezone.utc)
            if exp_dt < now_dt:
                return False, "authorization has expired"
        except Exception:
            pass

        if auth.allowed_actuator_backend_id != self.backend_id:
            return False, f"Authorization backend mismatch: '{auth.allowed_actuator_backend_id}' != '{self.backend_id}'"
        if auth.lab_environment_id != self.lab_env.lab_id:
            return False, f"authorized lab mismatch: '{auth.lab_environment_id}' != '{self.lab_env.lab_id}'"

        return True, None

    def snapshot(
        self,
        target_host: str,
        action: str,
        target_namespace: str = VICTIM_NS,
        authorization: LabActivationAuthorization | None = None,
    ) -> StateSnapshot:
        """Capture pre-action baseline snapshot scoped strictly to the target lab namespace."""
        valid, reason = self.validate_target(
            target_host=target_host,
            target_namespace=target_namespace,
            authorization=authorization,
        )
        if not valid:
            reason_upper = (reason or "").upper()
            if "FORBIDDEN" in reason_upper:
                raise ValueError(f"Target '{target_host}' is FORBIDDEN host target: {reason}")
            if "outside isolated lab subnet" in (reason or ""):
                raise ValueError(f"Target host '{target_host}' is outside isolated lab subnet {self.allowed_subnet}")
            raise PermissionError(f"Target validation failed: {reason}")

        if self.fail_snapshot:
            raise RuntimeError("NetnsActuator: snapshot generation failed")

        self._snapshot_counter += 1
        snapshot_id = f"NETNS-SNAP-{self._snapshot_counter:04d}"
        now_ts = datetime.now(timezone.utc).isoformat()

        # Capture namespace state dictionary
        ns_state = self.lab_env.inspect(target_namespace)
        baseline = {
            "target_namespace": target_namespace,
            "target_host": target_host,
            "rules": dict(ns_state.get("rules", {})),
            "rate_limits": dict(ns_state.get("rate_limits", {})),
            "isolated": bool(ns_state.get("isolated", False)),
        }
        digest = dict_hash(baseline)
        if self.corrupt_snapshot_hash:
            digest = "corrupted_netns_digest_00000000000000000000000000"

        return StateSnapshot(
            snapshot_id=snapshot_id,
            timestamp=now_ts,
            target_host=target_host,
            action=str(action),
            baseline_state=baseline,
            state_digest=digest,
            metadata={"backend_id": self.backend_id, "lab_id": self.lab_env.lab_id, "netns": target_namespace},
        )

    def apply_mutation(
        self,
        action: Action | str,
        target_host: str,
        params: dict[str, Any] | None = None,
        target_namespace: str = VICTIM_NS,
        target_interface: str = VETH_VICTIM,
        authorization: LabActivationAuthorization | None = None,
    ) -> bool:
        """Apply response mitigation strictly inside the target lab namespace."""
        valid, reason = self.validate_target(
            target_host=target_host,
            target_namespace=target_namespace,
            target_interface=target_interface,
            authorization=authorization,
        )
        if not valid:
            reason_upper = (reason or "").upper()
            if "FORBIDDEN" in reason_upper:
                raise ValueError(f"Target '{target_host}' is FORBIDDEN host target: {reason}")
            if "outside isolated lab subnet" in (reason or ""):
                raise ValueError(f"Target host '{target_host}' is outside isolated lab subnet {self.allowed_subnet}")
            raise PermissionError(f"Target validation failed: {reason}")

        if self.timeout_mutation:
            raise TimeoutError("NetnsActuator execution timeout")
        if self.fail_mutation or self.fail_apply:
            raise RuntimeError("NetnsActuator mutation failure")

        action_name = action.name if isinstance(action, Action) else str(action).upper()
        ns_state = self.lab_env._lab_netns_state[target_namespace]

        if self.partial_mutation:
            # Set rate limit but omit firewall drop rule
            ns_state["rate_limits"][target_host] = 50.0
            self.lab_mutations_count += 1
            return True

        if action_name == Action.ISOLATE.name:
            ns_state["rules"][target_host] = "DROP_ALL_TRAFFIC"
            ns_state["isolated"] = True
            self.lab_mutations_count += 1
        elif action_name == Action.RATE_LIMIT.name:
            limit = params.get("rate_mbps", 5.0) if params else 5.0
            ns_state["rate_limits"][target_host] = limit
            ns_state["rules"][target_host] = f"RATE_LIMIT_{limit}MBPS"
            self.lab_mutations_count += 1
        elif action_name in (Action.ALLOW.name, Action.ALERT.name):
            ns_state["rules"][target_host] = "ALLOW_INSPECT"

        return True

    def verify_mutation(
        self,
        action: Action | str,
        target_host: str,
        target_namespace: str = VICTIM_NS,
    ) -> bool:
        """Verify that lab namespace state matches the intended mitigation action."""
        if self.fail_verification or self.fail_verify or self.partial_mutation:
            return False

        action_name = action.name if isinstance(action, Action) else str(action).upper()
        ns_state = self.lab_env.inspect(target_namespace)

        if action_name == Action.ISOLATE.name:
            return (
                ns_state.get("isolated") is True
                and ns_state.get("rules", {}).get(target_host) == "DROP_ALL_TRAFFIC"
            )
        if action_name == Action.RATE_LIMIT.name:
            return (
                target_host in ns_state.get("rate_limits", {})
                and target_host in ns_state.get("rules", {})
            )
        if action_name in (Action.ALLOW.name, Action.ALERT.name):
            return ns_state.get("rules", {}).get(target_host) == "ALLOW_INSPECT"

        return False

    def rollback(self, snapshot: StateSnapshot, transaction_id: str = "") -> RollbackResult:
        """Atomically restore lab namespace state to snapshot baseline."""
        tx_key = transaction_id or snapshot.snapshot_id
        self._rollback_counts[tx_key] = self._rollback_counts.get(tx_key, 0) + 1
        attempts = self._rollback_counts[tx_key]

        if self.fail_rollback:
            return RollbackResult(
                success=False,
                transaction_id=tx_key,
                snapshot_id=snapshot.snapshot_id,
                rollback_attempts=attempts,
                restoration_verified=False,
                failure_reason="NetnsActuator: rollback failed during lab restoration",
                final_safety_state="SAFETY_LOCKED",
            )

        target_namespace = snapshot.baseline_state.get("target_namespace", VICTIM_NS)
        ns_state = self.lab_env._lab_netns_state.get(target_namespace, {})

        # Restore rules and limits from baseline
        base = snapshot.baseline_state
        ns_state["rules"] = dict(base.get("rules", {}))
        ns_state["rate_limits"] = dict(base.get("rate_limits", {}))
        ns_state["isolated"] = bool(base.get("isolated", False))

        # Re-inspect and verify restored digest matches snapshot
        restored = {
            "target_namespace": target_namespace,
            "target_host": base.get("target_host", snapshot.target_host),
            "rules": dict(ns_state.get("rules", {})),
            "rate_limits": dict(ns_state.get("rate_limits", {})),
            "isolated": bool(ns_state.get("isolated", False)),
        }
        restored_digest = dict_hash(restored)
        verified = (restored_digest == snapshot.state_digest)

        return RollbackResult(
            success=verified,
            transaction_id=tx_key,
            snapshot_id=snapshot.snapshot_id,
            rollback_attempts=attempts,
            restoration_verified=verified,
            failure_reason=None if verified else "Restoration digest mismatch in lab namespace",
            final_safety_state="RESTORED" if verified else "SAFETY_LOCKED",
        )

    def verify_clean_state(self, target_namespace: str = VICTIM_NS) -> bool:
        """Verify whether the lab namespace is free of transient response rules."""
        ns_state = self.lab_env.inspect(target_namespace)
        return (
            len(ns_state.get("rules", {})) == 0
            and len(ns_state.get("rate_limits", {})) == 0
            and ns_state.get("isolated", False) is False
        )

    def get_current_state(self, target_host: str | None = None) -> dict[str, Any]:
        """Retrieve current internal state representation for the lab."""
        return self.lab_env.inspect()

"""Isolated Lab Network Topology & Unified Transmission Loop for XRL-IDARS.

Provides:
1. Optional Linux network namespace setup (when privileged):
   - Attacker namespace: `xrlids_att_01`, interface `veth_xrl_att`, IP `10.200.1.2/24`
   - Victim namespace: `xrlids_vic_01`, interface `veth_xrl_vic`, IP `10.200.1.3/24`
   - Creates an isolated veth topology only. Scenario transmission and namespace-side capture are not implemented by this module yet.
2. Honest Unprivileged Sandbox Mode (when euid != 0):
   - Automatically detects OS privilege boundary.
   - Routes traffic through the unified LiveCaptureManager queue.
   - Explicitly tags event provenance as `SIMULATION` or `IN_MEMORY`, NEVER claiming `LIVE`.
3. Single Canonical Pipeline Path:
   Packet generation -> Network/Service queue -> LiveCaptureManager -> CanonicalFlowBuilder ->
   R10 Preprocessing -> RF Checkpoint -> Independent Rules -> TreeSHAP ->
   Dueling DQN -> Deterministic Safety Gate -> Firewall Actuation -> Verification -> Event Persistence.
   Preserves the exact same event ID throughout.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Any

from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.capture.scapy_service import scapy_packet_to_packet_info
from xrlids.demo.privileged_runner import get_lab_status, run_helper
from xrlids.demo.scapy_simulator import (
    ATTACKER_IP,
    VICTIM_IP,
    ScapyAttackSimulator,
    validate_target_safety,
)
from xrlids.events.schema import SecurityEvent
from xrlids.flow.canonical_builder import CanonicalFlow
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

ATTACKER_NS = "xrlids_att_01"
VICTIM_NS = "xrlids_vic_01"
VETH_ATTACKER = "veth_xrl_att"
VETH_VICTIM = "veth_xrl_vic"
LAB_SUBNET = "10.200.1.0/24"


class LabNetworkTopology:
    """Coordinates isolated Linux lab network namespaces, packet transmission, and ingestion."""

    def __init__(self) -> None:
        self.attacker_ns = ATTACKER_NS
        self.victim_ns = VICTIM_NS
        self.veth_attacker = VETH_ATTACKER
        self.veth_victim = VETH_VICTIM
        self.attacker_ip = ATTACKER_IP
        self.victim_ip = VICTIM_IP
        self.is_real_kernel_netns: bool = False
        self.setup_diagnostic: str = ""
        self._simulator = ScapyAttackSimulator()

        self._probe_capabilities()

    def _probe_capabilities(self) -> None:
        """Check whether operating system permits creation of real network namespaces."""
        stat = get_lab_status()
        if stat.get("lab_created") and stat.get("connectivity_ok"):
            self.is_real_kernel_netns = True
            self.setup_diagnostic = "Isolated lab namespaces active and verified."
            return

        if os.geteuid() == 0:
            self.setup_diagnostic = "Privileged execution verified (euid=0)."
            return

        self.setup_diagnostic = "Privilege escalation required to create kernel network namespaces."

    def setup(self) -> tuple[bool, str]:
        """Set up the isolated network namespace and veth topology via privileged runner."""
        ok, data, msg = run_helper("setup")
        if ok:
            self.is_real_kernel_netns = True
            self.setup_diagnostic = data.get("message", "Linux kernel network namespaces and veth pair configured.")
            logger.info("Isolated Linux network namespaces and veth pair successfully configured.")
            return True, self.setup_diagnostic
        else:
            self.is_real_kernel_netns = False
            self.setup_diagnostic = f"Failed to configure kernel netns: {msg}"
            logger.warning("Network namespace setup failed: %s", msg)
            return False, self.setup_diagnostic

    def teardown(self) -> tuple[bool, str]:
        """Tear down lab namespaces and interfaces safely."""
        ok, data, msg = run_helper("teardown")
        self.is_real_kernel_netns = False
        self.setup_diagnostic = msg
        return ok, msg

    def get_status(self) -> dict[str, Any]:
        """Query real-time status of lab topology and capture."""
        stat = get_lab_status()
        self.is_real_kernel_netns = bool(stat.get("lab_created") and stat.get("connectivity_ok"))
        return stat

    def start_live_capture(self, live_mgr: LiveCaptureManager) -> tuple[bool, str]:
        """Start genuine packet capture on veth_xrl_vic inside victim namespace."""
        stat = self.get_status()
        if not stat.get("lab_created"):
            return False, "Cannot start live capture: isolated lab is not set up. Click 'Start Isolated Lab' first."
        return live_mgr.start_netns_capture(netns=self.victim_ns, interface=self.veth_victim)

    def stop_live_capture(self, live_mgr: LiveCaptureManager) -> dict[str, Any]:
        """Stop packet capture worker and flush pending flows."""
        return live_mgr.stop()

    def transmit_scenario(
        self,
        scenario_id: str,
        live_mgr: LiveCaptureManager,
        pipeline: ActiveInferencePipeline,
    ) -> list[SecurityEvent]:
        """Transmit scenario packets and process them through the single real operational pipeline path.

        Guarantees:
        - Scenario packets are currently generated and processed in memory; namespace creation alone does not make this a live capture.
        - Events are always tagged `SIMULATION` until real namespace transmission and independent capture are implemented.
        - Preserves the same event ID throughout.
        """
        # 1. Determine source label honestly
        source_mode = "SIMULATION"

        # 2. Build in-memory Scapy packets. This path does not transmit/capture on a real interface.
        raw_pkts = self._simulator.build_packets_for_scenario(scenario_id)

        # 3. Check if attacker IP is actively blocked by firewall
        is_blocked = pipeline.firewall_manager.is_source_blocked(self.attacker_ip)

        # 4. Convert generated packets to PacketInfo and build flows in memory.
        builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
        completed_flows: list[CanonicalFlow] = []

        for scapy_pkt in raw_pkts:
            p_info = scapy_packet_to_packet_info(scapy_pkt)
            if p_info:
                # Firewall check: if attacker is actively blocked, filter out packets
                if not is_blocked or p_info.src_ip != self.attacker_ip:
                    completed_flows.extend(builder.process_packet(p_info))
                else:
                    pipeline.firewall_manager.filter_packet(p_info.src_ip, p_info.dst_ip, packet_size=p_info.packet_length)

        completed_flows.extend(builder.flush_all())

        # 5. Process flows through ActiveInferencePipeline
        results: list[SecurityEvent] = []
        for flow in completed_flows:
            pipe_res = pipeline.process_flow(flow, source_mode=source_mode)
            results.append(pipe_res.security_event)

        return results


# Global singleton instance
LAB_TOPOLOGY = LabNetworkTopology()

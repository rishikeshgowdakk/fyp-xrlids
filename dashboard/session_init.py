"""Session state initializer for XRL-IDARS Streamlit dashboard."""

from __future__ import annotations

from pathlib import Path
import sys
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

import streamlit as st

from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline


def ensure_session_state() -> tuple[EventManager, ActiveInferencePipeline, LiveCaptureManager]:
    """Ensure global session state is initialized and seeded with baseline demonstration data."""
    if "event_manager" not in st.session_state:
        st.session_state.event_manager = EventManager()
    if "pipeline" not in st.session_state:
        st.session_state.pipeline = ActiveInferencePipeline(
            event_manager=st.session_state.event_manager,
            explain_all=True,
        )
    if "live_manager" not in st.session_state:
        st.session_state.live_manager = LiveCaptureManager(
            pipeline=st.session_state.pipeline,
            event_manager=st.session_state.event_manager,
        )
    if "replayed_flows" not in st.session_state:
        st.session_state.replayed_flows = []

    event_mgr: EventManager = st.session_state.event_manager
    pipeline: ActiveInferencePipeline = st.session_state.pipeline
    live_mgr: LiveCaptureManager = st.session_state.live_manager

    # Auto-seed if empty
    if len(event_mgr.get_all_events()) == 0:
        try:
            # Check live capability on default loopback interface
            live_mgr.start("lo")
        except Exception:
            pass

        try:
            from xrlids.capture.scapy_service import (
                ScapyCaptureConfig,
                ScapyCaptureService,
                scapy_packet_to_packet_info,
            )
            from xrlids.demo.scapy_simulator import ScapyAttackSimulator
            from xrlids.flow.canonical_builder import CanonicalFlowBuilder

            pcap_path = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"
            if pcap_path.exists():
                cfg = ScapyCaptureConfig(pcap_path=pcap_path, queue_size=1000)
                srv = ScapyCaptureService(cfg)
                srv.start()
                fb = CanonicalFlowBuilder(idle_timeout_s=120.0)
                t0 = time.time()
                while srv.is_running or not srv._queue.empty():
                    pkt = srv.get_packet(timeout=0.05)
                    if pkt is not None:
                        for fl in fb.process_packet(pkt):
                            pipeline.process_flow(fl)
                            st.session_state.replayed_flows.append(fl)
                    if time.time() - t0 > 2.0:
                        break
                srv.stop()
                for fl in fb.flush_all():
                    pipeline.process_flow(fl)
                    st.session_state.replayed_flows.append(fl)

            sim = ScapyAttackSimulator()
            raw_pkts = sim.build_packets_for_scenario("scenario_c_syn_burst")
            fb_syn = CanonicalFlowBuilder(idle_timeout_s=120.0)
            for rp in raw_pkts:
                p_info = scapy_packet_to_packet_info(rp)
                if p_info:
                    for fl in fb_syn.process_packet(p_info):
                        pipeline.process_flow(fl)
                        st.session_state.replayed_flows.append(fl)
            for fl in fb_syn.flush_all():
                pipeline.process_flow(fl)
                st.session_state.replayed_flows.append(fl)
        except Exception:
            pass

    return event_mgr, pipeline, live_mgr

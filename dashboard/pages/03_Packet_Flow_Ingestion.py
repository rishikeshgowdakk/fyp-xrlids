"""Page 3: Packet & Flow Ingestion."""

from __future__ import annotations

from pathlib import Path
import sys
import time
import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from dashboard.session_init import ensure_session_state
from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.capture.scapy_service import ScapyCaptureConfig, ScapyCaptureService
from xrlids.events.manager import EventManager
from xrlids.flow.canonical_builder import CanonicalFlow, CanonicalFlowBuilder
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline

st.set_page_config(page_title="Packet & Flow Ingestion - XRL-IDARS", page_icon="📥", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()

st.title("📥 Packet & Flow Ingestion")
st.markdown("Control packet ingestion, stream PCAP replays through the **Canonical 5-Tuple Flow Builder**, and inspect real-time feature extraction under the strict $R_{10}$ contract.")

st.divider()

col_cfg, col_stats = st.columns([1, 1])

with col_cfg:
    st.subheader("Ingestion Source Configuration")
    query_mode = st.query_params.get("mode", "")
    default_idx = 0
    if query_mode == "pcap":
        default_idx = 1
    elif query_mode == "sample":
        default_idx = 2

    source_type = st.radio(
        "Select Ingestion Mode",
        ["Live Interface Sniffing (Scapy)", "PCAP File Replay", "Sample Traffic Generator (Demo)"],
        index=default_idx,
        horizontal=True,
    )

    if source_type == "Live Interface Sniffing (Scapy)":
        st.info("🌐 **Mode: LIVE INTERFACE SNIFFING** — Captures packets from local network interfaces via Scapy raw sockets. Administrative privileges (`CAP_NET_RAW` / `sudo`) are required to open raw promiscuous sockets on physical interfaces.")

        has_perm, perm_msg = live_mgr.check_permissions()
        if has_perm:
            st.success(f"Permissions Verified: {perm_msg}")
        else:
            st.warning(f"Live Sniffer Status: **BLOCKED** — {perm_msg}. In unprivileged environments, use PCAP File Replay or Sample Traffic Generator.")

        available_ifaces = live_mgr.get_available_interfaces()
        selected_iface = st.selectbox("Network Interface", available_ifaces, index=0)
        selected_filter = st.text_input("BPF Filter Expression", value="ip")

        c_start, c_stop = st.columns(2)
        with c_start:
            start_btn = st.button(
                "▶️ Start Live Capture Daemon",
                disabled=live_mgr.is_running or not has_perm,
                type="primary",
                use_container_width=True,
            )
            if start_btn:
                success, msg = live_mgr.start(interface=selected_iface, bpf_filter=selected_filter)
                if success:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

        with c_stop:
            stop_btn = st.button(
                "⏹️ Stop Live Capture Daemon",
                disabled=not live_mgr.is_running,
                use_container_width=True,
            )
            if stop_btn:
                stats = live_mgr.stop()
                st.info(f"Capture stopped. Processed {stats['packets_captured']} packets.")
                st.rerun()

    elif source_type == "PCAP File Replay":
        st.info("📂 **Mode: PCAP FILE REPLAY** — Streams authentic pre-recorded packet traces through the canonical flow engine.")
        default_pcap = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"
        pcap_path = st.text_input("PCAP File Path", value=str(default_pcap))

        c1, c2 = st.columns(2)
        with c1:
            max_packets = st.number_input("Max Packets to Replay (0 = all)", min_value=0, max_value=100000, value=200, step=50)
        with c2:
            auto_evaluate = st.checkbox("Auto-Evaluate via Active Pipeline", value=True)

        if st.button("▶️ Start PCAP Ingestion & Replay", type="primary", use_container_width=True):
            target_file = Path(pcap_path)
            if not target_file.exists():
                st.error(f"PCAP file not found: {target_file}")
            else:
                flow_builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
                cfg = ScapyCaptureConfig(pcap_path=target_file, queue_size=5000)
                service = ScapyCaptureService(cfg)

                with st.spinner("Replaying packets through canonical flow engine..."):
                    t0 = time.perf_counter()
                    completed_flows: list[CanonicalFlow] = []

                    def on_flow_done(f: CanonicalFlow) -> None:
                        completed_flows.append(f)
                        if auto_evaluate:
                            pipeline.process_flow(f)

                    pkt_count = 0
                    limit = int(max_packets) if max_packets > 0 else 100000
                    service.start()
                    t_start = time.time()
                    while service.is_running or not service._queue.empty():
                        pkt = service.get_packet(timeout=0.1)
                        if pkt is not None:
                            pkt_count += 1
                            newly_completed = flow_builder.process_packet(pkt)
                            for f in newly_completed:
                                on_flow_done(f)
                            if pkt_count >= limit:
                                break
                        if time.time() - t_start > 15.0:
                            break
                    service.stop()

                    # Flush remaining active flows
                    flushed = flow_builder.flush_all()
                    for f in flushed:
                        on_flow_done(f)

                    elapsed = time.perf_counter() - t0
                    st.session_state.replayed_flows = completed_flows
                    st.success(f"Processed {pkt_count} packets into {len(completed_flows)} completed flows in {elapsed*1000:.1f} ms!")

    else:
        st.info("🧪 **Mode: SAMPLE TRAFFIC GENERATOR** — Synthesizes controlled calibrated packets in-memory for testing and demonstration. [EXPLICITLY MARKED AS SAMPLE TRAFFIC].")
        from xrlids.demo.scapy_simulator import SCENARIOS, generate_scenario_packets

        scenario_choice = st.selectbox(
            "Select Calibrated Scenario",
            list(SCENARIOS.keys()),
            format_func=lambda k: f"{SCENARIOS[k]['title']} ({SCENARIOS[k]['category']})",
        )
        st.caption(SCENARIOS[scenario_choice]["description"])
        auto_eval_sample = st.checkbox("Auto-Evaluate via Active Pipeline", value=True, key="eval_sample")

        if st.button("🚀 Generate & Process Sample Packets", type="primary", use_container_width=True):
            with st.spinner("Generating Scapy packets and assembling flows..."):
                t0 = time.perf_counter()
                pkts = generate_scenario_packets(scenario_choice)
                flow_builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
                completed_flows: list[CanonicalFlow] = []

                for pkt in pkts:
                    newly_completed = flow_builder.process_packet(pkt)
                    for f in newly_completed:
                        completed_flows.append(f)
                        if auto_eval_sample:
                            pipeline.process_flow(f)

                flushed = flow_builder.flush_all()
                for f in flushed:
                    completed_flows.append(f)
                    if auto_eval_sample:
                        pipeline.process_flow(f)

                elapsed = time.perf_counter() - t0
                st.session_state.replayed_flows = completed_flows
                st.success(f"Generated {len(pkts)} sample packets and assembled {len(completed_flows)} completed flows in {elapsed*1000:.1f} ms!")

with col_stats:
    st.subheader("Ingestion & Flow Engine Statistics")
    live_stats = live_mgr.get_stats()
    m1, m2, m3 = st.columns(3)
    m1.metric("Packets Captured", live_stats["packets_captured"])
    m2.metric("Dropped / Errors", f"{live_stats['packets_dropped']} / {live_stats['capture_errors']}")
    m3.metric("Throughput", f"{live_stats['packets_per_sec']} pkt/s")

    m4, m5, m6 = st.columns(3)
    m4.metric("Active Flows", live_stats["active_flows"])
    m5.metric("Completed Flows", len(st.session_state.replayed_flows) or live_stats["completed_flows"])
    m6.metric("Timeout Setting", f"{int(live_mgr.idle_timeout_s)}s")

    st.markdown("#### Flow Construction Invariants")
    st.markdown("""
    - **Canonical 5-Tuple Key:** Ordered lexicographically `(min(IP), max(IP), ...)` ensuring forward and reverse packets belong to the exact same bidirectional flow entity.
    - **Termination Criteria:** Immediate emission on TCP `FIN` or `RST` handshake teardown, or sliding inactivity timeout $\\ge 120$ seconds.
    - **Schema Enforcement:** Strict floating-point contract rejecting `NaN`, `+Inf`, and out-of-order feature columns.
    """)

st.divider()

st.subheader("Assembled Flow Table & Extracted $R_{10}$ Features")
displayed_flows = st.session_state.replayed_flows or live_mgr.completed_flows
if displayed_flows:
    table_rows = []
    for f in displayed_flows:
        table_rows.append({
            "Flow ID": f.key.flow_id,
            "Source IP": f.key.src_ip,
            "Src Port": f.key.src_port,
            "Dest IP": f.key.dst_ip,
            "Dst Port": f.key.dst_port,
            "Proto": f.key.protocol,
            "Duration (ms)": round(f.features.get("flow_duration_ms", 0.0), 2),
            "Pkt Rate (/s)": round(f.features.get("flow_packets_per_s", 0.0), 2),
            "Byte Rate (/s)": round(f.features.get("flow_bytes_per_s", 0.0), 2),
            "Mean Pkt Len": round(f.features.get("packet_length_mean", 0.0), 2),
            "SYN": int(f.features.get("syn_count", 0)),
            "ACK": int(f.features.get("ack_count", 0)),
            "RST": int(f.features.get("rst_count", 0)),
            "FIN": int(f.features.get("fin_count", 0)),
        })
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
else:
    st.info("No completed flows in memory. Start Live Capture, run PCAP File Replay, or generate Sample Packets above.")

"""Page 2: Live Ingestion & Flow Processing (Phase 12).

Provides interactive controls and inspection for:
- PCAP File Replay & Streaming Ingestion
- Real-time Scapy Live Interface Sniffing (with privilege detection)
- Canonical 5-Tuple Bidirectional Flow Construction
- Schema Validation and Flow Feature Inspection
"""

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

from xrlids.capture.scapy_service import ScapyCaptureService
from xrlids.events.manager import EventManager
from xrlids.flow.canonical_builder import CanonicalFlowBuilder
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline

st.set_page_config(page_title="Live Ingestion - XRL-IDARS", page_icon="📡", layout="wide")

# Ensure session state
if "event_manager" not in st.session_state:
    st.session_state.event_manager = EventManager()
if "pipeline" not in st.session_state:
    st.session_state.pipeline = ActiveInferencePipeline(event_manager=st.session_state.event_manager)
if "replayed_flows" not in st.session_state:
    st.session_state.replayed_flows = []

pipeline: ActiveInferencePipeline = st.session_state.pipeline
event_mgr: EventManager = st.session_state.event_manager

st.title("📡 Live Ingestion & Flow Construction")
st.markdown("""
Monitor and control packet capture, stream PCAP replays through the **Canonical 5-Tuple Flow Builder**,
and inspect real-time feature extraction under the strict $R_{10}$ contract.
""")

st.divider()

col_cfg, col_stats = st.columns([1, 1])

with col_cfg:
    st.subheader("🛠️ Ingestion Source Configuration")
    source_type = st.radio("Select Ingestion Mode", ["PCAP File Replay", "Live Interface Sniffing (Scapy)"], horizontal=True)

    if source_type == "PCAP File Replay":
        default_pcap = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"
        pcap_path = st.text_input("PCAP File Path", value=str(default_pcap))
        
        c1, c2 = st.columns(2)
        with c1:
            max_packets = st.number_input("Max Packets to Replay (0 = all)", min_value=0, max_value=100000, value=200, step=50)
        with c2:
            auto_evaluate = st.checkbox("Auto-Evaluate via Active Pipeline", value=True)

        if st.button("▶️ Start PCAP Ingestion & Replay", type="primary"):
            target_file = Path(pcap_path)
            if not target_file.exists():
                st.error(f"PCAP file not found: {target_file}")
            else:
                flow_builder = CanonicalFlowBuilder(flow_timeout_seconds=120.0)
                service = ScapyCaptureService(flow_builder=flow_builder)
                
                with st.spinner("Replaying packets through canonical flow assembler..."):
                    t0 = time.perf_counter()
                    completed_flows = []
                    
                    def on_flow_done(f):
                        completed_flows.append(f)
                        if auto_evaluate:
                            pipeline.process_flow(
                                features=f.features,
                                source_ip=f.key.src_ip,
                                dest_ip=f.key.dst_ip,
                                flow_id=f.key.flow_id,
                                timestamp=f.start_time,
                            )

                    stats = service.replay_pcap(
                        target_file,
                        on_flow_complete=on_flow_done,
                        max_packets=int(max_packets) if max_packets > 0 else None,
                    )
                    
                    # Flush remaining active flows
                    flushed = flow_builder.flush_all()
                    for f in flushed:
                        completed_flows.append(f)
                        if auto_evaluate:
                            pipeline.process_flow(
                                features=f.features,
                                source_ip=f.key.src_ip,
                                dest_ip=f.key.dst_ip,
                                flow_id=f.key.flow_id,
                                timestamp=f.start_time,
                            )
                    
                    elapsed = time.perf_counter() - t0
                    st.session_state.replayed_flows = completed_flows
                    st.success(f"Successfully processed {stats['packets_processed']} packets into {len(completed_flows)} completed flows in {elapsed*1000:.1f} ms!")

    else:
        st.info("Live capture uses Scapy socket sniffing. Administrative privileges (`CAP_NET_RAW` / `sudo`) are required to open raw promiscuous sockets on physical interfaces.")
        cap_service = ScapyCaptureService()
        has_perm, perm_msg = cap_service.verify_permissions()
        
        if has_perm:
            st.success(f"Permissions Verified: {perm_msg}")
        else:
            st.warning(f"Live Sniffer Advisory: {perm_msg}. In unprivileged environments, use PCAP File Replay above or grant `setcap cap_net_raw,cap_net_admin+eip` to the python binary.")
        
        iface = st.text_input("Interface (e.g., eth0, lo, wlan0)", value="lo")
        bpf_filter = st.text_input("BPF Filter", value="ip")
        st.button("Start Live Capture Daemon", disabled=not has_perm)

with col_stats:
    st.subheader("📊 Ingestion & Canonical Flow Statistics")
    m1, m2, m3 = st.columns(3)
    m1.metric("Completed Flows", len(st.session_state.replayed_flows))
    m2.metric("Schema Standard", "R10 (10 Features)")
    m3.metric("Timeout Setting", "120 seconds")

    st.markdown("#### Flow Construction Invariants")
    st.markdown("""
    - **Canonical 5-Tuple Key:** Ordered lexicographically `(min(IP), max(IP), ...)` ensuring forward and reverse packets are assigned to the exact same bidirectional flow entity.
    - **Termination Criteria:** Immediate emission on TCP `FIN` or `RST` handshake teardown, or sliding inactivity timeout $\\ge 120$ seconds.
    - **Schema Enforcement:** Strict floating-point contract rejecting `NaN`, `+Inf`, and out-of-order feature columns.
    """)

st.divider()

st.subheader("📋 Assembled Flow Table & Extracted $R_{10}$ Features")
if st.session_state.replayed_flows:
    table_rows = []
    for f in st.session_state.replayed_flows:
        row = {
            "Flow ID": f.key.flow_id,
            "Source IP": f.key.src_ip,
            "Src Port": f.key.src_port,
            "Dest IP": f.key.dst_ip,
            "Dst Port": f.key.dst_port,
            "Proto": f.key.protocol,
            "Duration (ms)": round(f.features["flow_duration_ms"], 2),
            "Pkt Rate (/s)": round(f.features["flow_packets_per_s"], 2),
            "Byte Rate (/s)": round(f.features["flow_bytes_per_s"], 2),
            "Mean Pkt Len": round(f.features["packet_length_mean"], 2),
            "SYN": int(f.features["syn_count"]),
            "ACK": int(f.features["ack_count"]),
            "RST": int(f.features["rst_count"]),
            "FIN": int(f.features["fin_count"]),
        }
        table_rows.append(row)
    
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
else:
    st.info("No replayed flows in memory. Click 'Start PCAP Ingestion & Replay' above to stream packets and inspect assembled flows.")

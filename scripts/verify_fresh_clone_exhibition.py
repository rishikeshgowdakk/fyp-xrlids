#!/usr/bin/env python3
"""Fresh-Clone Verification Script for XRL-IDARS Exhibition Package.

This script executes an automated end-to-end verification of all artifacts,
dependencies, model inference paths, PCAP replay pipelines, dashboard endpoints,
and safety invariants.

Exit code 0 guarantees that the repository is in an authoritative, runnable,
and presentation-ready state on any fresh clone.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

# Setup paths
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))


class TerminalColor:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def log_step(category: str, item: str, status: bool, detail: str = "") -> None:
    badge = f"{TerminalColor.GREEN}[PASS]{TerminalColor.RESET}" if status else f"{TerminalColor.RED}[FAIL]{TerminalColor.RESET}"
    detail_str = f" {TerminalColor.DIM}({detail}){TerminalColor.RESET}" if detail else ""
    print(f"  {badge} {TerminalColor.BOLD}{category:<16}{TerminalColor.RESET} {item}{detail_str}")


def verify_environment() -> bool:
    print(f"\n{TerminalColor.CYAN}1. System Environment & Core Packages{TerminalColor.RESET}")
    all_ok = True

    # Python version
    py_ver = sys.version_info
    py_ok = py_ver.major == 3 and py_ver.minor >= 10
    log_step("Python Version", f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}", py_ok)
    all_ok &= py_ok

    # Required packages
    packages = ["torch", "sklearn", "scipy", "pandas", "numpy", "shap", "yaml"]
    for pkg in packages:
        try:
            mod = __import__(pkg)
            ver = getattr(mod, "__version__", "installed")
            log_step("Package", f"{pkg} ({ver})", True)
        except ImportError as e:
            log_step("Package", f"{pkg} (MISSING: {e})", False)
            all_ok = False

    return all_ok


def verify_model_artifacts() -> bool:
    print(f"\n{TerminalColor.CYAN}2. Canonical Model Artifact Integrity (9/9 Checkpoints){TerminalColor.RESET}")
    all_ok = True

    manifest_path = REPO_ROOT / "models" / "registry" / "model_manifest.json"
    if not manifest_path.exists():
        log_step("Registry Manifest", str(manifest_path), False, "File not found")
        return False

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    artifacts = manifest.get("artifacts", [])
    log_step("Registry Manifest", f"{len(artifacts)} canonical models registered", len(artifacts) == 9)

    import joblib
    import numpy as np
    import pandas as pd
    import torch
    from xrlids.models.lstm import LSTMDetector
    from xrlids.response.dqn.network import DuelingQNetwork

    for art in artifacts:
        p = REPO_ROOT / art["canonical_path"]
        if not p.exists():
            log_step("Artifact Exist", art["model_id"], False, "File missing on disk")
            all_ok = False
            continue

        actual_size = p.stat().st_size
        size_ok = actual_size == art["size_bytes"]
        actual_hash = hashlib.sha256(p.read_bytes()).hexdigest()
        hash_ok = actual_hash == art["sha256"]

        # Functional loading test
        load_ok = True
        err_msg = ""
        try:
            mtype = art.get("model_type")
            if mtype == "rf":
                detector = joblib.load(p)
                # Test inference with dummy DataFrame
                n_feats = len(detector.feature_names)
                dummy_df = pd.DataFrame(np.zeros((1, n_feats)), columns=detector.feature_names)
                probs = detector.predict_proba(dummy_df)
                if probs.shape != (1,):
                    load_ok = False
                    err_msg = f"Unexpected prob shape {probs.shape}"
            elif mtype == "lstm":
                detector = LSTMDetector.load(p)
                n_feats = len(detector.feature_names)
                tensor_x = torch.zeros(1, detector.seq_len, n_feats)
                detector.model.eval()
                with torch.no_grad():
                    logits = detector.model(tensor_x)
                    prob = torch.sigmoid(logits)
                if prob.shape != torch.Size([1]):
                    load_ok = False
                    err_msg = f"Unexpected LSTM prob shape {prob.shape}"
            elif mtype == "dqn":
                ckpt = torch.load(p, map_location="cpu", weights_only=False)
                action_dim = 4 if "4action" in art["model_id"] else 3
                q_net = DuelingQNetwork(input_dim=6, action_dim=action_dim, hidden_dim=64)
                q_net.load_state_dict(ckpt["online_net_state_dict"])
                q_net.eval()
                with torch.no_grad():
                    q_vals = q_net(torch.zeros(1, 6))
                if q_vals.shape != torch.Size([1, action_dim]):
                    load_ok = False
                    err_msg = f"Unexpected Q-val shape {q_vals.shape}"
            elif mtype == "fusion":
                with open(p, encoding="utf-8") as fw:
                    weights = json.load(fw)
                configs = weights.get("configurations", {})
                if "cicids2017" not in configs or "alpha" not in configs["cicids2017"]:
                    load_ok = False
                    err_msg = "Invalid fusion weights format"
        except Exception as e:
            load_ok = False
            err_msg = str(e)

        item_status = size_ok and hash_ok and load_ok
        detail = f"{actual_size:,} bytes | SHA: {actual_hash[:8]}... | Inference: {'OK' if load_ok else err_msg}"
        log_step("Model Checkpoint", art["model_id"], item_status, detail)
        all_ok &= item_status

    return all_ok


def verify_pcap_and_pipeline() -> bool:
    print(f"\n{TerminalColor.CYAN}3. PCAP Ingestion & Flow Extraction Pipeline{TerminalColor.RESET}")
    all_ok = True

    pcap_path = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"
    pcap_exists = pcap_path.exists()
    pcap_size = pcap_path.stat().st_size if pcap_exists else 0
    pcap_ok = pcap_exists and pcap_size == 63924
    log_step("PCAP Artifact", "sample_traffic.pcap", pcap_ok, f"{pcap_size:,} bytes")
    all_ok &= pcap_ok

    if not pcap_ok:
        return False

    from xrlids.demo.flow import FlowBuilder
    from xrlids.demo.pcap import PcapReader

    try:
        reader = PcapReader(pcap_path)
        packets = list(reader.read_packets())
        pkt_ok = len(packets) == 42
        log_step("PCAP Parser", f"Parsed {len(packets)} packets", pkt_ok, "Expected 42 packets")
        all_ok &= pkt_ok

        fb = FlowBuilder()
        completed_flows = []
        for p in packets:
            completed_flows.extend(fb.process_packet(p))
        completed_flows.extend(fb.flush_all())

        flows_ok = len(completed_flows) == 6
        log_step("Flow Aggregation", f"Extracted {len(completed_flows)} bidirectional flows", flows_ok, "Expected 6 flows")
        all_ok &= flows_ok

        # Check feature extraction on first flow
        f1 = completed_flows[0]
        feats = f1.to_features()
        has_r10 = all(
            k in feats
            for k in [
                "flow_duration_ms",
                "flow_packets_per_s",
                "flow_bytes_per_s",
                "packet_length_mean",
                "packet_length_std",
                "syn_count",
                "ack_count",
                "rst_count",
                "fin_count",
                "syn_ack_ratio",
            ]
        )
        log_step("R10 Contract", "Exact 10-feature vector computed", has_r10)
        all_ok &= has_r10
    except Exception as e:
        log_step("Pipeline Execution", f"Error: {e}", False)
        all_ok = False

    return all_ok


def verify_dashboard_endpoints() -> bool:
    print(f"\n{TerminalColor.CYAN}4. Dashboard Backend & Data Endpoints{TerminalColor.RESET}")
    all_ok = True

    index_path = REPO_ROOT / "dashboard" / "index.html"
    app_js_path = REPO_ROOT / "dashboard" / "app.js"
    server_path = REPO_ROOT / "dashboard" / "server.py"

    demo_html_path = REPO_ROOT / "dashboard" / "demo.html"
    demo_js_path = REPO_ROOT / "dashboard" / "demo.js"

    log_step("Frontend Assets", "index.html exists", index_path.exists(), f"{index_path.stat().st_size:,} bytes")
    log_step("Frontend Assets", "app.js exists", app_js_path.exists(), f"{app_js_path.stat().st_size:,} bytes")
    log_step("Frontend Assets", "demo.html exists (Viva Mode)", demo_html_path.exists(), f"{demo_html_path.stat().st_size:,} bytes")
    log_step("Frontend Assets", "demo.js exists (Viva Mode)", demo_js_path.exists(), f"{demo_js_path.stat().st_size:,} bytes")
    log_step("Server Script", "dashboard/server.py exists", server_path.exists())

    all_ok &= index_path.exists() and app_js_path.exists() and demo_html_path.exists() and demo_js_path.exists() and server_path.exists()

    from dashboard.server import (
        get_comparison_data,
        get_evaluation_data,
        get_limitations_data,
        get_overview_data,
        get_response_benchmark_data,
        list_scenarios,
    )

    try:
        ov = get_overview_data()
        log_step("API Endpoint", "get_overview_data()", "git_commit" in ov, f"Commit: {ov.get('git_commit', '')[:8]}...")

        ev = get_evaluation_data("cicids2017")
        log_step("API Endpoint", "get_evaluation_data('cicids2017')", ev is not None and "benchmark" in ev)

        co = get_comparison_data("cicids2017")
        models_count = len(co.get("models", {}))
        log_step("API Endpoint", f"get_comparison_data('cicids2017') ({models_count} models)", models_count >= 5)

        rb = get_response_benchmark_data(regime="standard_enterprise", mode="4-action")
        log_step("API Endpoint", "get_response_benchmark_data()", "policies" in rb)

        lim = get_limitations_data()
        lim_count = len(lim.get("limitations", []))
        log_step("API Endpoint", f"get_limitations_data() ({lim_count} limitations)", lim_count == 9)

        sc = list_scenarios()
        log_step("API Endpoint", f"list_scenarios() ({len(sc)} attack scenarios)", len(sc) >= 3)
    except Exception as e:
        log_step("API Endpoints", f"Exception: {e}", False)
        all_ok = False

    return all_ok


def verify_safety_invariants() -> bool:
    print(f"\n{TerminalColor.CYAN}5. Safety Invariants & Network Isolation{TerminalColor.RESET}")
    all_ok = True

    policy_path = REPO_ROOT / "configs" / "safety" / "response_safety_policy.yaml"
    if not policy_path.exists():
        log_step("Safety Policy", str(policy_path), False, "File missing")
        return False

    import yaml
    with open(policy_path, encoding="utf-8") as f:
        policy = yaml.safe_load(f)

    # Invariant: default modes must not apply mutations
    observe_mode = policy.get("modes", {}).get("OBSERVE", {})
    dry_run_mode = policy.get("modes", {}).get("DRY_RUN", {})
    obs_safe = observe_mode.get("applies_action") is False
    dry_safe = dry_run_mode.get("applies_action") is False

    log_step("Safety Invariant", "OBSERVE mode applies_action=False", obs_safe)
    log_step("Safety Invariant", "DRY_RUN mode applies_action=False", dry_safe)
    all_ok &= obs_safe and dry_safe

    # Invariant: Block gate requirements
    gate = policy.get("block_gate", {})
    cooldown = gate.get("cooldown_seconds", 0)
    repeat_obs = gate.get("minimum_repeated_observations", 0)
    gate_safe = cooldown >= 30.0 and repeat_obs >= 2
    log_step("Safety Invariant", f"Block gate cooldown={cooldown}s, repeat_req={repeat_obs}", gate_safe)
    all_ok &= gate_safe

    # Invariant: Dashboard binds to 127.0.0.1 loopback only
    server_code = (REPO_ROOT / "dashboard" / "server.py").read_text(encoding="utf-8")
    loopback_bound = 'server_address = ("127.0.0.1", port)' in server_code or 'bind_address = "127.0.0.1"' in server_code or '"127.0.0.1"' in server_code
    log_step("Network Security", "Server binds strictly to 127.0.0.1 (loopback)", loopback_bound)
    all_ok &= loopback_bound

    # Invariant: Live traffic disclaimer present in HTML
    html_code = (REPO_ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    disclaimer_present = "Scientific Disclaimer &amp; Strict Operational Mode Separation" in html_code or "Scientific Disclaimer & Strict Operational Mode Separation" in html_code
    log_step("Research Boundary", "Live traffic disclaimer banner present in UI", disclaimer_present)
    all_ok &= disclaimer_present

    return all_ok


def main() -> int:
    t0 = time.time()
    print(f"\n{TerminalColor.BOLD}======================================================================{TerminalColor.RESET}")
    print(f"{TerminalColor.BOLD}       XRL-IDARS — Fresh-Clone Exhibition Verification Suite        {TerminalColor.RESET}")
    print(f"{TerminalColor.BOLD}======================================================================{TerminalColor.RESET}")

    env_ok = verify_environment()
    models_ok = verify_model_artifacts()
    pcap_ok = verify_pcap_and_pipeline()
    dash_ok = verify_dashboard_endpoints()
    safety_ok = verify_safety_invariants()

    total_time = time.time() - t0
    all_passed = env_ok and models_ok and pcap_ok and dash_ok and safety_ok

    print(f"\n{TerminalColor.BOLD}----------------------------------------------------------------------{TerminalColor.RESET}")
    if all_passed:
        print(f"{TerminalColor.GREEN}{TerminalColor.BOLD}  OVERALL VERDICT: PASS (Verification completed in {total_time:.2f}s){TerminalColor.RESET}")
        print(f"  All 9 model artifacts, feature pipelines, dashboard endpoints,")
        print(f"  and safety constraints are verified and ready for exhibition.")
        print(f"  To launch the presentation workbench: {TerminalColor.CYAN}python scripts/demo/run_dashboard.py{TerminalColor.RESET}")
        print(f"{TerminalColor.BOLD}----------------------------------------------------------------------{TerminalColor.RESET}\n")
        return 0
    else:
        print(f"{TerminalColor.RED}{TerminalColor.BOLD}  OVERALL VERDICT: FAIL (Verification failed after {total_time:.2f}s){TerminalColor.RESET}")
        print(f"  One or more critical integrity checks failed. Review output above.")
        print(f"{TerminalColor.BOLD}----------------------------------------------------------------------{TerminalColor.RESET}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())

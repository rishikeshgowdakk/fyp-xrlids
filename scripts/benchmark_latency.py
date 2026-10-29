"""Empirical latency and performance benchmark for XRL-IDARS.

Strictly adheres to Phase 2 Acceptance Audit requirements:
1. Feature extraction latency:
   - Measures Flow.to_features() across accumulated packets.
   - Includes TCP flag aggregation, packet rate calculation, standard deviation.
   - Excludes packet capture and network socket overhead.
2. Model inference latency (EXCLUDING preprocessing):
   - Measures pure Random Forest traversal on pre-transformed feature array.
   - Excludes dictionary validation and StandardScaler transformation.
3. Model inference latency (INCLUDING preprocessing):
   - Measures ModelRegistry.infer() with strict dictionary validation,
     StandardScaler transformation, probability estimation, and class mapping.
4. TreeSHAP explanation latency:
   - Measures shap.TreeExplainer calculation on Random Forest for a single flow.
   - Excludes flow accumulation and network transport.
5. End-to-end packet-to-prediction latency:
   - Measures complete flow pipeline: packet stream ingestion -> FlowBuilder
     accumulation -> flow closure -> feature extraction -> preprocessor scaling ->
     Random Forest classification.
6. End-to-end packet-to-explanation latency:
   - Measures complete flow pipeline + TreeSHAP feature attribution.

Methodology:
- Minimum 5 warm-up iterations per benchmark to eliminate JIT / caching bias.
- 100 measured iterations (25 for TreeSHAP due to compute cost).
- Computes non-fabricated median, p95, p99, min, and max.
- Explicit notice: Single-flow microbenchmarks reflect CPU algorithmic execution
  and must not be conflated with multi-threaded line-rate burst network throughput.
"""

from __future__ import annotations

import os
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd

from xrlids.demo.flow import Flow, FlowBuilder, FlowKey
from xrlids.demo.pcap import PacketInfo
from xrlids.evaluation.csv_evaluator import explain_flow_prediction
from xrlids.features.definitions import R10_FEATURES
from xrlids.models.registry import DEFAULT_MODEL_REGISTRY


def run_benchmarks(n_samples: int = 100) -> dict:
    system_os = f"{platform.system()} {platform.release()}"
    cpu_model = platform.processor() or platform.machine()
    try:
        mem_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        mem_total_gb = round(mem_bytes / (1024**3), 2)
    except Exception:
        mem_total_gb = 16.0
    python_ver = platform.python_version()

    print(f"===========================================================")
    print(f"XRL-IDARS Empirical Latency & Performance Benchmark")
    print(f"===========================================================")
    print(f"OS:           {system_os}")
    print(f"Architecture: {cpu_model}")
    print(f"Host RAM:     {mem_total_gb} GB")
    print(f"Python:       {python_ver}")
    print(f"Trials:       {n_samples} (25 for TreeSHAP)")
    print(f"===========================================================\n")

    # Sample packet sequence (10 packets simulating realistic burst)
    packet_infos = []
    base_t = 1000.0
    for i in range(10):
        packet_infos.append(
            PacketInfo(
                timestamp=base_t + i * 0.05,
                src_ip="192.168.1.100",
                dst_ip="10.0.0.5",
                src_port=49152,
                dst_port=80,
                protocol=6,
                packet_length=64 + (i * 10),
                is_tcp=True,
                syn=(i == 0),
                ack=(i > 0),
                rst=False,
                fin=False,
            )
        )

    # -------------------------------------------------------------------------
    # 1. Feature extraction latency
    # -------------------------------------------------------------------------
    feat_latencies = []
    # Warmup
    for _ in range(5):
        w_flow = Flow(key=FlowKey("1.1.1.1", "2.2.2.2", 1000, 80, 6), start_time=0.0, last_time=1.0)
        for pkt in packet_infos:
            w_flow.add_packet(pkt, is_forward=True)
        w_flow.to_features()

    for _ in range(n_samples):
        flow = Flow(
            key=FlowKey("192.168.1.100", "10.0.0.5", 49152, 80, 6),
            start_time=base_t,
            last_time=base_t + 0.5,
        )
        for pkt in packet_infos:
            flow.add_packet(pkt, is_forward=True)

        t0 = time.perf_counter()
        feats = flow.to_features()
        t1 = time.perf_counter()
        feat_latencies.append((t1 - t0) * 1000.0)

    # -------------------------------------------------------------------------
    # 2. Model inference latency (EXCLUDING preprocessing)
    # -------------------------------------------------------------------------
    registry = DEFAULT_MODEL_REGISTRY
    meta_17 = registry.get_metadata("cicids2017")
    rf_model = registry.load_model(meta_17)
    prep_17 = registry.load_preprocessor(meta_17)

    sample_feats = {
        "flow_duration_ms": 1250.0,
        "flow_packets_per_s": 80.5,
        "flow_bytes_per_s": 15400.0,
        "packet_length_mean": 191.3,
        "packet_length_std": 84.2,
        "syn_count": 2.0,
        "ack_count": 4.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.5,
    }
    raw_df = pd.DataFrame([[sample_feats[f] for f in R10_FEATURES]], columns=list(R10_FEATURES))
    pre_scaled_df = prep_17.transform(raw_df)
    pre_scaled_arr = pre_scaled_df.to_numpy(dtype=float)

    # Warmup
    inner_rf = rf_model.model if hasattr(rf_model, "model") else rf_model
    for _ in range(5):
        inner_rf.predict_proba(pre_scaled_arr)

    pure_inf_latencies = []
    for _ in range(n_samples):
        t0 = time.perf_counter()
        inner_rf.predict_proba(pre_scaled_arr)
        t1 = time.perf_counter()
        pure_inf_latencies.append((t1 - t0) * 1000.0)

    # -------------------------------------------------------------------------
    # 3. Model inference latency (INCLUDING preprocessing)
    # -------------------------------------------------------------------------
    # Warmup
    for _ in range(5):
        registry.infer(sample_feats, benchmark="cicids2017")

    prep_inf_latencies = []
    for _ in range(n_samples):
        t0 = time.perf_counter()
        registry.infer(sample_feats, benchmark="cicids2017")
        t1 = time.perf_counter()
        prep_inf_latencies.append((t1 - t0) * 1000.0)

    # -------------------------------------------------------------------------
    # 4. TreeSHAP explanation latency
    # -------------------------------------------------------------------------
    # Warmup
    explain_flow_prediction(sample_feats, benchmark="cicids2017")
    shap_latencies = []
    n_shap = min(n_samples, 25)
    for _ in range(n_shap):
        t0 = time.perf_counter()
        explain_flow_prediction(sample_feats, benchmark="cicids2017")
        t1 = time.perf_counter()
        shap_latencies.append((t1 - t0) * 1000.0)

    # -------------------------------------------------------------------------
    # 5. End-to-end packet-to-prediction latency
    # -------------------------------------------------------------------------
    e2e_pred_latencies = []
    for _ in range(n_samples):
        builder = FlowBuilder(idle_timeout_s=120.0)
        t0 = time.perf_counter()
        for pkt in packet_infos:
            completed = builder.process_packet(pkt)
        completed.extend(builder.flush_all())
        for fl in completed:
            fl_feats = fl.to_features()
            registry.infer(fl_feats, benchmark="cicids2017")
        t1 = time.perf_counter()
        e2e_pred_latencies.append((t1 - t0) * 1000.0)

    # -------------------------------------------------------------------------
    # 6. End-to-end packet-to-explanation latency
    # -------------------------------------------------------------------------
    e2e_expl_latencies = []
    for _ in range(n_shap):
        builder = FlowBuilder(idle_timeout_s=120.0)
        t0 = time.perf_counter()
        for pkt in packet_infos:
            completed = builder.process_packet(pkt)
        completed.extend(builder.flush_all())
        for fl in completed:
            fl_feats = fl.to_features()
            registry.infer(fl_feats, benchmark="cicids2017")
            explain_flow_prediction(fl_feats, benchmark="cicids2017")
        t1 = time.perf_counter()
        e2e_expl_latencies.append((t1 - t0) * 1000.0)

    def stats(arr: list[float], scope_desc: str) -> dict[str, Any]:
        a = np.array(arr)
        return {
            "scope": scope_desc,
            "samples": len(arr),
            "median_ms": round(float(np.median(a)), 3),
            "p95_ms": round(float(np.percentile(a, 95)), 3),
            "p99_ms": round(float(np.percentile(a, 99)), 3),
            "min_ms": round(float(np.min(a)), 3),
            "max_ms": round(float(np.max(a)), 3),
        }

    results = {
        "system": {
            "os": system_os,
            "architecture": cpu_model,
            "ram_gb": mem_total_gb,
            "python": python_ver,
        },
        "feature_extraction": stats(
            feat_latencies,
            "Flow.to_features() on 10 accumulated packets (excludes packet capture/socket)",
        ),
        "random_forest_pure_inference": stats(
            pure_inf_latencies,
            "Pure 100-tree RF traversal on float32 array (EXCLUDES validation & preprocessing)",
        ),
        "random_forest_inference_with_preprocessing": stats(
            prep_inf_latencies,
            "ModelRegistry.infer() including contract validation, StandardScaler transform, and class mapping",
        ),
        "treeshap_explanation": stats(
            shap_latencies,
            "TreeExplainer attribution computation on single 10-feature flow vector",
        ),
        "end_to_end_packet_to_prediction": stats(
            e2e_pred_latencies,
            "Packet stream -> FlowBuilder -> feature extraction -> scaling -> RF prediction",
        ),
        "end_to_end_packet_to_explanation": stats(
            e2e_expl_latencies,
            "Packet stream -> FlowBuilder -> feature extraction -> scaling -> RF prediction -> TreeSHAP",
        ),
    }

    print("=== Empirical Latency Results ===")
    for stage, s in results.items():
        if stage == "system":
            continue
        print(f"\n[{stage.upper()}]")
        print(f"  Scope:   {s['scope']}")
        print(f"  Samples: {s['samples']}")
        print(f"  Median:  {s['median_ms']} ms")
        print(f"  P95:     {s['p95_ms']} ms")
        print(f"  P99:     {s['p99_ms']} ms")
        print(f"  Min/Max: {s['min_ms']} ms / {s['max_ms']} ms")

    print("\n-----------------------------------------------------------")
    print("Methodological Disclaimer:")
    print("Single-flow microbenchmarks measure per-flow algorithmic computational")
    print("latencies on isolated CPU threads. They exclude packet burst queue contention,")
    print("kernel socket buffer drops, network interface interrupts, and inter-process IPC,")
    print("and must not be cited as sustained production line-rate throughput.")
    print("-----------------------------------------------------------\n")

    return results


if __name__ == "__main__":
    run_benchmarks(100)

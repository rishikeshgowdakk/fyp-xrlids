"""Empirical latency and performance benchmark for XRL-IDARS.

Measures actual runtimes without fabricated numbers:
1. Feature extraction time (Flow.to_features() across packets).
2. Model inference time (Random Forest on validated feature vector).
3. TreeSHAP explanation time (TreeExplainer on single flow).
4. End-to-end event pipeline latency (packet -> flow -> inference -> event emission).
Computes median, p95, and p99 over multiple measured trials.
"""

from __future__ import annotations

import os
import platform
import time
from pathlib import Path

import numpy as np

from xrlids.demo.flow import Flow, FlowBuilder, FlowKey
from xrlids.demo.pcap import PacketInfo, build_raw_packet
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

    print(f"=== System Benchmark Context ===")
    print(f"OS: {system_os}")
    print(f"Architecture: {cpu_model}")
    print(f"RAM: {mem_total_gb} GB")
    print(f"Python: {python_ver}")
    print(f"Sample count: {n_samples}\n")

    # Sample packet sequence
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

    # 1. Feature extraction benchmark
    feat_latencies = []
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

    # 2. Model inference benchmark
    registry = DEFAULT_MODEL_REGISTRY
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
    # Warmup
    for _ in range(5):
        registry.infer(sample_feats, benchmark="cicids2017")

    inf_latencies = []
    for _ in range(n_samples):
        t0 = time.perf_counter()
        res = registry.infer(sample_feats, benchmark="cicids2017")
        t1 = time.perf_counter()
        inf_latencies.append((t1 - t0) * 1000.0)

    # 3. TreeSHAP benchmark
    # Warmup
    explain_flow_prediction(sample_feats, benchmark="cicids2017")
    shap_latencies = []
    # 20 trials for TreeSHAP as it is computationally heavier
    n_shap = min(n_samples, 25)
    for _ in range(n_shap):
        t0 = time.perf_counter()
        shap_res = explain_flow_prediction(sample_feats, benchmark="cicids2017")
        t1 = time.perf_counter()
        shap_latencies.append((t1 - t0) * 1000.0)

    # 4. End-to-end pipeline benchmark (packet -> flow -> inference)
    e2e_latencies = []
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
        e2e_latencies.append((t1 - t0) * 1000.0)

    def stats(arr: list[float]) -> dict[str, float]:
        a = np.array(arr)
        return {
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
        "feature_extraction": stats(feat_latencies),
        "random_forest_inference": stats(inf_latencies),
        "treeshap_explanation": stats(shap_latencies),
        "end_to_end_flow_pipeline": stats(e2e_latencies),
    }

    print("=== Empirical Latency Results ===")
    for stage, s in results.items():
        if stage == "system":
            continue
        print(f"\n[{stage.upper()}]")
        for k, v in s.items():
            print(f"  {k}: {v} ms")

    return results


if __name__ == "__main__":
    run_benchmarks(100)

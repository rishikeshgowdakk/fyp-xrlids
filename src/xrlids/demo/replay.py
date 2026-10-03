"""PCAP Replay Engine for reproducible demonstration and empirical validation.

Processes network traffic from PCAP files, aggregates packets into bidirectional
flows matching the 120s timeout / FIN-RST contract, extracts the frozen 10 R10
features, executes model inference, compares against known ground truth, and
records structured execution summaries and reports in results/demo/.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import joblib
import numpy as np
import pandas as pd

from xrlids.demo.extractor import flows_to_dataframe
from xrlids.demo.flow import Flow, FlowBuilder
from xrlids.demo.pcap import PacketInfo, PcapReader
from xrlids.features.definitions import R10_FEATURES


@dataclass
class FlowPredictionEvent:
    """Individual flow classification record."""

    flow_id: int
    timestamp_start: float
    protocol_name: str
    src_endpoint: str
    dst_endpoint: str
    packet_count: int
    duration_ms: float
    prediction_class: int  # 0 = Benign, 1 = Attack
    prediction_label: str  # "BENIGN" or "ATTACK"
    confidence: float
    ground_truth_class: int | None = None
    ground_truth_label: str = "UNKNOWN"
    verdict: str = "UNVERIFIED"  # "CORRECT", "INCORRECT", "UNVERIFIED"
    features: dict[str, float] = field(default_factory=dict)


@dataclass
class ReplaySummary:
    """Comprehensive replay execution summary."""

    run_timestamp: str
    pcap_file: str
    model_identifier: str
    threshold: float
    total_packets: int
    total_flows: int
    evaluated_flows: int
    confusion_matrix: dict[str, int]
    metrics: dict[str, float]
    flow_events: list[dict[str, Any]]


class ReplayEngine:
    """Streams PCAP packets, extracts R10 flow features, and performs inference."""

    def __init__(
        self,
        model: Any | None = None,
        preprocessor: Any | None = None,
        model_path: str | Path | None = None,
        threshold: float = 0.50,
        idle_timeout_s: float = 120.0,
    ) -> None:
        self.threshold = threshold
        self.idle_timeout_s = idle_timeout_s
        self.model_path_str = str(model_path) if model_path else "in-memory-model"

        # Load or assign model and preprocessor
        if model is not None:
            self.model = model
            self.preprocessor = preprocessor
        elif model_path is not None:
            p = Path(model_path)
            if p.is_dir():
                rf_path = p / "random_forest.joblib"
                prep_path = p / "preprocessor.joblib"
                if rf_path.exists():
                    self.model = joblib.load(rf_path)
                else:
                    raise FileNotFoundError(f"Model file not found in directory: {rf_path}")
                if prep_path.exists():
                    self.preprocessor = joblib.load(prep_path)
                else:
                    self.preprocessor = None
            elif p.is_file():
                self.model = joblib.load(p)
                self.preprocessor = None
            else:
                raise FileNotFoundError(f"Specified model path does not exist: {model_path}")
        else:
            self.model = None
            self.preprocessor = None

    def _predict_flow(self, flow: Flow) -> tuple[int, float]:
        """Extract features and return (predicted_class, probability)."""
        raw_df = flows_to_dataframe([flow])

        if self.preprocessor is not None:
            feature_df = self.preprocessor.transform(raw_df)
        else:
            feature_df = raw_df

        if self.model is None:
            # Fallback simple heuristic: high packet rate or SYN/ACK anomaly -> attack
            feats = flow.to_features()
            score = 0.95 if feats["flow_packets_per_s"] > 1000.0 or feats["syn_ack_ratio"] > 10.0 else 0.05
            pred = 1 if score >= self.threshold else 0
            return pred, float(score)

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(feature_df)
            if isinstance(probs, np.ndarray) and probs.ndim == 2:
                prob = float(probs[0, 1])
            elif isinstance(probs, np.ndarray) and probs.ndim == 1:
                prob = float(probs[0])
            elif isinstance(probs, (list, tuple)):
                prob = float(probs[0])
            else:
                prob = float(probs)
        elif hasattr(self.model, "predict"):
            pred_arr = self.model.predict(feature_df)
            pred = int(pred_arr[0])
            return pred, 1.0 if pred == 1 else 0.0
        else:
            raise ValueError("Configured model has neither predict_proba nor predict method.")

        pred = 1 if prob >= self.threshold else 0
        return pred, prob

    def replay_pcap(
        self,
        pcap_file: str | Path,
        ground_truth_resolver: Callable[[Flow], int | None] | None = None,
        on_flow_callback: Callable[[FlowPredictionEvent], None] | None = None,
    ) -> ReplaySummary:
        """Run PCAP replay through streaming flow builder and classifier."""
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        reader = PcapReader(pcap_path)
        builder = FlowBuilder(idle_timeout_s=self.idle_timeout_s)

        packet_count = 0
        completed_flows: list[Flow] = []
        events: list[FlowPredictionEvent] = []

        tp = fp = tn = fn = 0
        flow_idx = 0

        def process_completed(flow_list: Sequence[Flow]) -> None:
            nonlocal flow_idx, tp, fp, tn, fn
            for fl in flow_list:
                flow_idx += 1
                pred_cls, conf = self._predict_flow(fl)
                pred_label = "ATTACK" if pred_cls == 1 else "BENIGN"

                gt_cls = ground_truth_resolver(fl) if ground_truth_resolver else None
                if gt_cls is not None:
                    gt_label = "ATTACK" if gt_cls == 1 else "BENIGN"
                    if pred_cls == 1 and gt_cls == 1:
                        tp += 1
                        verdict = "CORRECT"
                    elif pred_cls == 1 and gt_cls == 0:
                        fp += 1
                        verdict = "INCORRECT"
                    elif pred_cls == 0 and gt_cls == 0:
                        tn += 1
                        verdict = "CORRECT"
                    else:
                        fn += 1
                        verdict = "INCORRECT"
                else:
                    gt_label = "UNKNOWN"
                    verdict = "UNVERIFIED"

                proto = "TCP" if fl.key.protocol == 6 else ("UDP" if fl.key.protocol == 17 else f"PROTO_{fl.key.protocol}")

                event = FlowPredictionEvent(
                    flow_id=flow_idx,
                    timestamp_start=fl.start_time,
                    protocol_name=proto,
                    src_endpoint=f"{fl.source_first_ip}:{fl.source_first_port}",
                    dst_endpoint=f"{fl.dest_first_ip}:{fl.dest_first_port}",
                    packet_count=fl.packet_count,
                    duration_ms=round(fl.duration_ms, 2),
                    prediction_class=pred_cls,
                    prediction_label=pred_label,
                    confidence=round(conf, 4),
                    ground_truth_class=gt_cls,
                    ground_truth_label=gt_label,
                    verdict=verdict,
                    features={k: round(v, 4) for k, v in fl.to_features().items()},
                )
                events.append(event)
                if on_flow_callback is not None:
                    on_flow_callback(event)

        for pkt in reader.read_packets():
            packet_count += 1
            closed = builder.process_packet(pkt)
            if closed:
                process_completed(closed)

        # Flush remaining active flows at EOF
        remaining = builder.flush_all()
        if remaining:
            process_completed(remaining)

        evaluated = tp + fp + tn + fn
        if evaluated > 0:
            acc = (tp + tn) / evaluated
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        else:
            acc = prec = rec = f1 = fpr = fnr = 0.0

        summary = ReplaySummary(
            run_timestamp=datetime.now(timezone.utc).isoformat(),
            pcap_file=str(pcap_path),
            model_identifier=self.model_path_str,
            threshold=self.threshold,
            total_packets=packet_count,
            total_flows=len(events),
            evaluated_flows=evaluated,
            confusion_matrix={"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            metrics={
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "fnr": round(fnr, 4),
            },
            flow_events=[asdict(e) for e in events],
        )

        return summary


def save_demo_artifacts(
    summary: ReplaySummary,
    output_dir: str | Path = "results/demo",
) -> tuple[Path, Path]:
    """Persist replay summary JSON and Markdown report to results/demo/."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    json_path = out_path / "replay_summary.json"
    md_path = out_path / "demo_report.md"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(asdict(summary), f, indent=2)

    cm = summary.confusion_matrix
    m = summary.metrics

    report_lines = [
        "# XRL-IDARS — Demonstration & Live Replay Verification Report",
        "",
        "## 1. Executive Summary",
        f"- **Run Timestamp (UTC):** `{summary.run_timestamp}`",
        f"- **Source Traffic (PCAP):** `{summary.pcap_file}`",
        f"- **Model Identifier:** `{summary.model_identifier}`",
        f"- **Decision Threshold (D-003):** `{summary.threshold}`",
        f"- **Total Ingested Packets:** `{summary.total_packets}`",
        f"- **Completed Network Flows:** `{summary.total_flows}`",
        f"- **Evaluated Labeled Flows:** `{summary.evaluated_flows}`",
        "",
        "## 2. Classification Performance",
        "",
        "### 2.1 Confusion Matrix",
        "| | Predicted Benign | Predicted Attack | Total |",
        "|---|---|---|---|",
        f"| **Actual Benign** | {cm['tn']} (TN) | {cm['fp']} (FP) | {cm['tn'] + cm['fp']} |",
        f"| **Actual Attack** | {cm['fn']} (FN) | {cm['tp']} (TP) | {cm['fn'] + cm['tp']} |",
        f"| **Total** | {cm['tn'] + cm['fn']} | {cm['fp'] + cm['tp']} | {summary.evaluated_flows} |",
        "",
        "### 2.2 Core Detection Metrics",
        f"- **Accuracy:** `{m['accuracy']:.4f}` ({m['accuracy']*100:.2f}%)",
        f"- **Precision:** `{m['precision']:.4f}` ({m['precision']*100:.2f}%)",
        f"- **Recall (TPR):** `{m['recall']:.4f}` ({m['recall']*100:.2f}%)",
        f"- **F1-Score:** `{m['f1']:.4f}`",
        f"- **False Positive Rate (FPR):** `{m['fpr']:.4f}` ({m['fpr']*100:.2f}%)",
        f"- **False Negative Rate (FNR):** `{m['fnr']:.4f}` ({m['fnr']*100:.2f}%)",
        "",
        "## 3. Flow-Level Inspection (First 15 Completed Flows)",
        "",
        "| Flow ID | Protocol | Source Endpoint | Destination Endpoint | Packets | Duration (ms) | Prediction | Conf | Truth | Verdict |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]

    for ev in summary.flow_events[:15]:
        report_lines.append(
            f"| {ev['flow_id']} | {ev['protocol_name']} | {ev['src_endpoint']} | {ev['dst_endpoint']} | "
            f"{ev['packet_count']} | {ev['duration_ms']} | **{ev['prediction_label']}** | {ev['confidence']:.2f} | "
            f"{ev['ground_truth_label']} | `{ev['verdict']}` |"
        )

    report_lines.extend([
        "",
        "## 4. Verification & Operational Contracts",
        "- **R10 Semantic Feature Parity:** Completed flows extract exact 10 R10 features.",
        "- **D-003 Decision Contract:** Tested at baseline research threshold 0.50.",
        "- **D-006 Flow Completion Policy:** Flow aggregation enforced at 120s idle timeout or TCP FIN/RST packet.",
        "- **Safety Guarantee:** Pure observational execution; no system packet interception or firewall mutation.",
    ])

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")

    return json_path, md_path

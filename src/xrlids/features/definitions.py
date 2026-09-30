"""Canonical feature definitions (build spec section 8).

This module is the single source of truth for *how* each canonical feature is computed.
Feature formulas operate on **semantic fields** (dataset-independent quantities such as
``duration_seconds`` or ``syn_flags``) rather than raw dataset columns. Per-dataset raw
columns are mapped to semantic fields in ``configs/features/features.yaml``.

That separation is what makes cross-dataset comparison honest: if a dataset cannot supply
a semantic field, the dependent feature is reported unavailable instead of being silently
approximated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

import numpy as np
import pandas as pd

SeriesMap = Mapping[str, pd.Series]
FeatureFn = Callable[[SeriesMap], pd.Series]


class FeatureComputationError(ValueError):
    """Raised when a feature cannot be computed from the available semantic fields."""


# Semantic fields a dataset may provide (directly or derived).
SEMANTIC_FIELDS: tuple[str, ...] = (
    "duration_seconds",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "pkt_len_mean",
    "pkt_len_std",
    "syn_flags",
    "ack_flags",
    "rst_flags",
    "fin_flags",
    "flow_iat_mean_s",
    "flow_iat_std_s",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "active_mean_s",
    "idle_mean_s",
    "subflow_fwd_bytes",
    "subflow_bwd_bytes",
)

# Fields always derived from others when their inputs exist.
DERIVED_SEMANTIC_FIELDS: tuple[str, ...] = ("total_packets", "total_bytes")


@dataclass(frozen=True)
class FeatureSpec:
    """A canonical feature: name, math, units and provenance of its inputs."""

    name: str
    description: str
    formula: str
    unit: str
    requires: tuple[str, ...]
    directionality: str
    live_available: bool
    edge_case_policy: str
    rationale: str
    limitations: str
    fn: FeatureFn


def _req(sem: SeriesMap, *names: str) -> list[pd.Series]:
    missing = [n for n in names if n not in sem]
    if missing:
        raise FeatureComputationError(
            f"missing semantic field(s) {missing}; available={sorted(sem)}"
        )
    return [sem[n].astype(float) for n in names]


def _safe_rate(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """numerator/denominator, with a documented zero-denominator policy.

    Policy: a zero or negative denominator yields NaN when the numerator is non-zero
    (the rate is genuinely undefined), and 0.0 when the numerator is also zero
    (nothing happened, so the rate is trivially zero). NaN is *not* silently replaced
    here; the cleaning policy decides how missing rates are handled.
    """
    out = pd.Series(np.nan, index=numerator.index, dtype=float)
    ok = denominator > 0
    out.loc[ok] = numerator.loc[ok] / denominator.loc[ok]
    both_zero = (~ok) & (numerator == 0)
    out.loc[both_zero] = 0.0
    return out


def _safe_ratio_floor_one(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """numerator / max(denominator, 1). Used where a count may legitimately be zero."""
    return numerator / denominator.clip(lower=1.0)


# ---------------------------------------------------------------------------
# Feature formulae
# ---------------------------------------------------------------------------
def _f_flow_duration_ms(sem: SeriesMap) -> pd.Series:
    (d,) = _req(sem, "duration_seconds")
    return d * 1000.0


def _f_flow_packets_per_s(sem: SeriesMap) -> pd.Series:
    (tp, d) = _req(sem, "total_packets", "duration_seconds")
    return _safe_rate(tp, d)


def _f_flow_bytes_per_s(sem: SeriesMap) -> pd.Series:
    (tb, d) = _req(sem, "total_bytes", "duration_seconds")
    return _safe_rate(tb, d)


def _f_packet_length_mean(sem: SeriesMap) -> pd.Series:
    (m,) = _req(sem, "pkt_len_mean")
    return m


def _f_packet_length_std(sem: SeriesMap) -> pd.Series:
    (s,) = _req(sem, "pkt_len_std")
    return s


def _f_syn_count(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "syn_flags")
    return v


def _f_ack_count(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "ack_flags")
    return v


def _f_rst_count(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "rst_flags")
    return v


def _f_fin_count(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "fin_flags")
    return v


def _f_syn_ack_ratio(sem: SeriesMap) -> pd.Series:
    (s, a) = _req(sem, "syn_flags", "ack_flags")
    return _safe_ratio_floor_one(s, a)


def _f_flow_iat_mean_ms(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "flow_iat_mean_s")
    return v * 1000.0


def _f_flow_iat_std_ms(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "flow_iat_std_s")
    return v * 1000.0


def _f_down_up_ratio(sem: SeriesMap) -> pd.Series:
    (b, f) = _req(sem, "total_bwd_packets", "total_fwd_packets")
    return _safe_ratio_floor_one(b, f)


def _f_fwd_packet_length_mean(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "fwd_pkt_len_mean")
    return v


def _f_bwd_packet_length_mean(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "bwd_pkt_len_mean")
    return v


def _f_flow_bytes_per_packet(sem: SeriesMap) -> pd.Series:
    (tb, tp) = _req(sem, "total_bytes", "total_packets")
    return _safe_ratio_floor_one(tb, tp)


def _f_active_mean_ms(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "active_mean_s")
    return v * 1000.0


def _f_idle_mean_ms(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "idle_mean_s")
    return v * 1000.0


def _f_subflow_fwd_bytes(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "subflow_fwd_bytes")
    return v


def _f_subflow_bwd_bytes(sem: SeriesMap) -> pd.Series:
    (v,) = _req(sem, "subflow_bwd_bytes")
    return v


# ---------------------------------------------------------------------------
# Registry of canonical features
# ---------------------------------------------------------------------------
FEATURES: dict[str, FeatureSpec] = {
    "flow_duration_ms": FeatureSpec(
        name="flow_duration_ms",
        description="Total flow duration in milliseconds.",
        formula="duration_seconds * 1000",
        unit="ms",
        requires=("duration_seconds",),
        directionality="longer flows are more likely benign bulk transfer",
        live_available=True,
        edge_case_policy="negative durations are invalid and are removed by the cleaning policy",
        rationale="fundamental flow-level time scale; available and identical in meaning everywhere",
        limitations="bidirectional flow semantics differ across capture tooling",
        fn=_f_flow_duration_ms,
    ),
    "flow_packets_per_s": FeatureSpec(
        name="flow_packets_per_s",
        description="Packet rate of the flow.",
        formula="total_packets / duration_seconds",
        unit="packets/s",
        requires=("total_packets", "duration_seconds"),
        directionality="high rate indicates flooding-like behaviour",
        live_available=True,
        edge_case_policy="duration<=0 yields NaN when packets>0, 0.0 when packets==0",
        rationale="rate (not raw count) is what separates legitimate bursts from floods",
        limitations="recomputed from source quantities rather than trusting vendor rate columns",
        fn=_f_flow_packets_per_s,
    ),
    "flow_bytes_per_s": FeatureSpec(
        name="flow_bytes_per_s",
        description="Byte throughput of the flow.",
        formula="total_bytes / duration_seconds",
        unit="bytes/s",
        requires=("total_bytes", "duration_seconds"),
        directionality="high throughput is more consistent with bulk transfer than with attack",
        live_available=True,
        edge_case_policy="same zero-duration policy as flow_packets_per_s",
        rationale="distinguishes many-tiny-packets floods from legitimate large transfers",
        limitations="vendor byte-rate columns sometimes contain Infinity; we recompute instead",
        fn=_f_flow_bytes_per_s,
    ),
    "packet_length_mean": FeatureSpec(
        name="packet_length_mean",
        description="Mean packet length across the flow.",
        formula="mean(packet_length)",
        unit="bytes",
        requires=("pkt_len_mean",),
        directionality="attack tools often emit uniform small packets",
        live_available=True,
        edge_case_policy="n/a (mean of observed packets)",
        rationale="packet-size structure is not captured by volume alone",
        limitations="for UNSW-NB15 this must be derived from byte/packet totals, not a native column",
        fn=_f_packet_length_mean,
    ),
    "packet_length_std": FeatureSpec(
        name="packet_length_std",
        description="Standard deviation of packet length.",
        formula="std(packet_length)",
        unit="bytes",
        requires=("pkt_len_std",),
        directionality="low variance suggests scripted traffic",
        live_available=True,
        edge_case_policy="n/a",
        rationale="dispersion of sizes separates scripted floods from human browsing",
        limitations="not available in UNSW-NB15",
        fn=_f_packet_length_std,
    ),
    "syn_count": FeatureSpec(
        name="syn_count",
        description="Count of packets with the TCP SYN flag set.",
        formula="count(TCP SYN)",
        unit="packets",
        requires=("syn_flags",),
        directionality="syn-heavy, ack-light traffic suggests scanning or SYN flood",
        live_available=True,
        edge_case_policy="n/a",
        rationale="TCP flag mix is a strong, cheap behavioural signal",
        limitations="not available as counts in UNSW-NB15",
        fn=_f_syn_count,
    ),
    "ack_count": FeatureSpec(
        name="ack_count",
        description="Count of packets with the TCP ACK flag set.",
        formula="count(TCP ACK)",
        unit="packets",
        requires=("ack_flags",),
        directionality="low ack relative to syn indicates half-open connections",
        live_available=True,
        edge_case_policy="n/a",
        rationale="complements SYN count to express connection-establishment behaviour",
        limitations="not available as counts in UNSW-NB15",
        fn=_f_ack_count,
    ),
    "rst_count": FeatureSpec(
        name="rst_count",
        description="Count of packets with the TCP RST flag set.",
        formula="count(TCP RST)",
        unit="packets",
        requires=("rst_flags",),
        directionality="many resets suggest scanning or connection refusal",
        live_available=True,
        edge_case_policy="n/a",
        rationale="captures failed/refused connections that volume features miss",
        limitations="not available as counts in UNSW-NB15",
        fn=_f_rst_count,
    ),
    "fin_count": FeatureSpec(
        name="fin_count",
        description="Count of packets with the TCP FIN flag set.",
        formula="count(TCP FIN)",
        unit="packets",
        requires=("fin_flags",),
        directionality="graceful termination indicator; near-absence on flood flows",
        live_available=True,
        edge_case_policy="n/a",
        rationale="flow lifecycle indicator available from packet headers",
        limitations="not available as counts in UNSW-NB15",
        fn=_f_fin_count,
    ),
    "syn_ack_ratio": FeatureSpec(
        name="syn_ack_ratio",
        description="Ratio of SYN to ACK packets.",
        formula="syn_count / max(ack_count, 1)",
        unit="ratio",
        requires=("syn_flags", "ack_flags"),
        directionality="high ratio indicates unanswered connection attempts",
        live_available=True,
        edge_case_policy="denominator floored at 1 so a zero ACK count is defined",
        rationale="a single interpretable expression of connection-completion behaviour",
        limitations="denominator flooring makes the value saturate for large SYN counts",
        fn=_f_syn_ack_ratio,
    ),
    "flow_iat_mean_ms": FeatureSpec(
        name="flow_iat_mean_ms",
        description="Mean inter-arrival time between flow packets.",
        formula="mean(inter_arrival_time) * 1000",
        unit="ms",
        requires=("flow_iat_mean_s",),
        directionality="very regular short IATs suggest automated traffic",
        live_available=True,
        edge_case_policy="n/a",
        rationale="temporal structure is precisely what RQ2 is about",
        limitations="not available in UNSW-NB15",
        fn=_f_flow_iat_mean_ms,
    ),
    "flow_iat_std_ms": FeatureSpec(
        name="flow_iat_std_ms",
        description="Standard deviation of inter-arrival time.",
        formula="std(inter_arrival_time) * 1000",
        unit="ms",
        requires=("flow_iat_std_s",),
        directionality="low dispersion suggests machine-generated pacing",
        live_available=True,
        edge_case_policy="n/a",
        rationale="dispersion of timing distinguishes scripted from human traffic",
        limitations="not available in UNSW-NB15",
        fn=_f_flow_iat_std_ms,
    ),
    "down_up_ratio": FeatureSpec(
        name="down_up_ratio",
        description="Ratio of backward to forward packet counts.",
        formula="total_bwd_packets / max(total_fwd_packets, 1)",
        unit="ratio",
        requires=("total_bwd_packets", "total_fwd_packets"),
        directionality="near-zero indicates one-way (spoofed/flooded) traffic",
        live_available=True,
        edge_case_policy="denominator floored at 1",
        rationale="directionality is cheap and separates floods from request/response traffic",
        limitations="depends on accurate bidirectional flow accounting",
        fn=_f_down_up_ratio,
    ),
    "fwd_packet_length_mean": FeatureSpec(
        name="fwd_packet_length_mean",
        description="Mean forward-direction packet length.",
        formula="mean(packet_length[forward])",
        unit="bytes",
        requires=("fwd_pkt_len_mean",),
        directionality="informational",
        live_available=True,
        edge_case_policy="n/a",
        rationale="directional size structure is lost in aggregate means",
        limitations="not available in UNSW-NB15 without re-derivation from raw packets",
        fn=_f_fwd_packet_length_mean,
    ),
    "bwd_packet_length_mean": FeatureSpec(
        name="bwd_packet_length_mean",
        description="Mean backward-direction packet length.",
        formula="mean(packet_length[backward])",
        unit="bytes",
        requires=("bwd_pkt_len_mean",),
        directionality="informational",
        live_available=True,
        edge_case_policy="n/a",
        rationale="complements forward mean; asymmetry is informative",
        limitations="not available in UNSW-NB15 without re-derivation from raw packets",
        fn=_f_bwd_packet_length_mean,
    ),
    "flow_bytes_per_packet": FeatureSpec(
        name="flow_bytes_per_packet",
        description="Mean bytes per packet over the flow.",
        formula="total_bytes / max(total_packets, 1)",
        unit="bytes/packet",
        requires=("total_bytes", "total_packets"),
        directionality="small values indicate many tiny packets",
        live_available=True,
        edge_case_policy="denominator floored at 1",
        rationale="derivable from volume and count; portable across datasets",
        limitations="closely related to packet_length_mean; may be redundant",
        fn=_f_flow_bytes_per_packet,
    ),
    "active_mean_ms": FeatureSpec(
        name="active_mean_ms",
        description="Mean duration of active periods in the flow.",
        formula="mean(active_period) * 1000",
        unit="ms",
        requires=("active_mean_s",),
        directionality="informational",
        live_available=False,
        edge_case_policy="n/a",
        rationale="activity structure is not captured by whole-flow aggregates",
        limitations="requires flow segmentation that live capture (Phase 3) may not reproduce",
        fn=_f_active_mean_ms,
    ),
    "idle_mean_ms": FeatureSpec(
        name="idle_mean_ms",
        description="Mean duration of idle periods in the flow.",
        formula="mean(idle_period) * 1000",
        unit="ms",
        requires=("idle_mean_s",),
        directionality="informational",
        live_available=False,
        edge_case_policy="n/a",
        rationale="complements active mean to describe temporal structure",
        limitations="same segmentation dependency as active_mean_ms",
        fn=_f_idle_mean_ms,
    ),
    "subflow_fwd_bytes": FeatureSpec(
        name="subflow_fwd_bytes",
        description="Forward bytes in the first subflow of the flow.",
        formula="subflow_fwd_bytes",
        unit="bytes",
        requires=("subflow_fwd_bytes",),
        directionality="informational",
        live_available=False,
        edge_case_policy="n/a",
        rationale="subflow volume isolates the opening phase of a flow",
        limitations="tool-specific definition; not live-reproducible, not available in UNSW-NB15",
        fn=_f_subflow_fwd_bytes,
    ),
    "subflow_bwd_bytes": FeatureSpec(
        name="subflow_bwd_bytes",
        description="Backward bytes in the first subflow of the flow.",
        formula="subflow_bwd_bytes",
        unit="bytes",
        requires=("subflow_bwd_bytes",),
        directionality="informational",
        live_available=False,
        edge_case_policy="n/a",
        rationale="complements subflow forward volume",
        limitations="tool-specific definition; not live-reproducible, not available in UNSW-NB15",
        fn=_f_subflow_bwd_bytes,
    ),
}


def feature_spec(name: str) -> FeatureSpec:
    if name not in FEATURES:
        raise KeyError(f"unknown canonical feature '{name}'")
    return FEATURES[name]

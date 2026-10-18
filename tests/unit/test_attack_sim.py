"""Tests for the calibrated attack simulator scenarios (``xrlids.demo.attack_sim``).

Structural tests only: the frozen-model score parity is verified end-to-end by
``scripts/demo/verify_attack_scenarios.py`` (requires the trained artefacts).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.demo.attack_sim import (  # noqa: E402
    BASE_TIMESTAMP,
    SCENARIOS,
    build_scenario_packets,
    get_scenario,
    list_scenarios,
)


def _bidirectional_key(pkt) -> tuple:
    """Canonical bidirectional flow key (direction-agnostic five-tuple)."""
    endpoint_a = (pkt.src_ip, pkt.src_port)
    endpoint_b = (pkt.dst_ip, pkt.dst_port)
    return (min(endpoint_a, endpoint_b), max(endpoint_a, endpoint_b), pkt.protocol)


def test_scenario_registry_is_consistent():
    assert SCENARIOS, "no scenarios registered"
    for scenario_id, spec in SCENARIOS.items():
        assert scenario_id == spec.id
        assert spec.name and spec.description
        assert spec.category in {"low_and_slow", "flood", "scan"}
        assert spec.expected_band in {"HIGH", "ALERT", "NONE"}
        assert spec.attacker_ip.startswith("203.0.113."), "attacker must use the RFC 5737 docs range"
        assert spec.packets, f"{scenario_id}: empty packet script"
        assert spec.packet_count >= 2
        assert spec.expected_flows >= 1
        assert 0.0 < spec.duration_s <= 10.0
        assert spec.calibration_note


def test_expected_bands_match_expected_scores():
    for spec in SCENARIOS.values():
        if spec.expected_band == "HIGH":
            assert spec.expected_score >= 0.85, f"{spec.id}: HIGH band needs score >= 0.85"
        elif spec.expected_band == "ALERT":
            assert 0.50 <= spec.expected_score < 0.85, f"{spec.id}: ALERT band needs 0.50 <= score < 0.85"
        else:
            assert spec.expected_score < 0.50, f"{spec.id}: NONE band needs score < 0.50"


def test_build_scenario_packets_preserves_script():
    for spec in SCENARIOS.values():
        packets = build_scenario_packets(spec)
        assert len(packets) == spec.packet_count
        timestamps = [p.timestamp for p in packets]
        assert timestamps == sorted(timestamps), f"{spec.id}: script not time-ordered"
        for packet in packets:
            assert packet.protocol == 6 and packet.is_tcp
            assert 54 <= packet.packet_length <= 1500
        assert packets[0].timestamp == pytest.approx(BASE_TIMESTAMP + spec.packets[0].offset_s)


def test_scenario_flows_match_expectations_and_close_cleanly():
    for spec in SCENARIOS.values():
        groups: dict[tuple, list] = {}
        for packet in build_scenario_packets(spec):
            groups.setdefault(_bidirectional_key(packet), []).append(packet)
        assert len(groups) == spec.expected_flows, (
            f"{spec.id}: expected {spec.expected_flows} flows, got {len(groups)}"
        )
        for key, packets in groups.items():
            assert packets[-1].rst or packets[-1].fin, f"{spec.id}: flow {key} never closes with RST/FIN"
        if spec.expected_flows == 1:
            assert len(next(iter(groups.values()))) == spec.packet_count


def test_detected_scenarios_are_low_and_slow_and_evasions_are_labelled():
    bands = {spec.expected_band for spec in SCENARIOS.values()}
    assert {"HIGH", "ALERT", "NONE"} <= bands, "expected at least one scenario in every calibration band"
    for spec in SCENARIOS.values():
        if spec.expected_band != "NONE":
            assert spec.category == "low_and_slow", (
                f"{spec.id}: detected scenarios are calibrated low-and-slow signatures"
            )
        else:
            assert "evasion demo" in spec.calibration_note, (
                f"{spec.id}: non-detected scenarios must be labelled evasion demos"
            )


def test_list_scenarios_metadata_is_json_serialisable():
    metadata = list_scenarios()
    assert len(metadata) == len(SCENARIOS)
    payload = json.dumps(metadata)  # must not raise
    assert "slow_http_dos" in payload
    for item in metadata:
        assert item["expected_band"] in {"HIGH", "ALERT", "NONE"}
        assert item["calibration_model"]
        assert item["victim_ip"] == "192.168.1.10"


def test_get_scenario_lookup():
    assert get_scenario("slow_http_dos") is not None
    assert get_scenario("does_not_exist") is None

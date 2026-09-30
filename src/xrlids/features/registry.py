"""Feature registry (build spec sections 8-10).

Loads ``configs/features/features.yaml`` and cross-validates it against the Python
formula definitions, so a rung can never reference a feature that has no implementation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from xrlids.features.definitions import FEATURES, SEMANTIC_FIELDS, feature_spec
from xrlids.utils.hashing import feature_schema_hash


class FeatureRegistryError(ValueError):
    """Raised when the feature registry is internally inconsistent or invalid."""


def _normalize_gate(gate: dict[str, dict[str, object]]) -> dict[str, dict[str, str]]:
    """Coerce YAML 1.1 ``yes``/``no`` booleans back to readable gate answers.

    YAML parses bare ``yes``/``no`` as booleans, which would silently turn a documentable
    decision-gate answer into ``True``/``False``.
    """
    normalized: dict[str, dict[str, str]] = {}
    for feature, answers in gate.items():
        row: dict[str, str] = {}
        for key, value in (answers or {}).items():
            if isinstance(value, bool):
                row[key] = "yes" if value else "no"
            else:
                row[key] = str(value)
        normalized[feature] = row
    return normalized


@dataclass
class FeatureRegistry:
    raw: dict[str, Any]
    rungs: dict[str, dict[str, Any]]
    gate: dict[str, dict[str, str]]
    column_maps: dict[str, dict[str, Any]]
    excluded_patterns: tuple[str, ...]
    version: str = "0.0.0"
    status: str = "unknown"
    column_maps_status: str = "unknown"
    frozen_by_decision: str | None = None
    _compiled_exclusions: list[re.Pattern] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_file(cls, path: str | Path = "configs/features/features.yaml") -> "FeatureRegistry":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        registry = cls(
            raw=data,
            rungs=data.get("rungs", {}) or {},
            gate=_normalize_gate(data.get("gate", {}) or {}),
            column_maps=data.get("column_maps", {}) or {},
            excluded_patterns=tuple(data.get("excluded_column_patterns", []) or ()),
            version=str(data.get("registry_version", "0.0.0")),
            status=str(data.get("contract_status", "unknown")),
            column_maps_status=str(data.get("column_maps_status", "unknown")),
            frozen_by_decision=data.get("frozen_by_decision"),
        )
        registry._compiled_exclusions = [re.compile(p, re.IGNORECASE) for p in registry.excluded_patterns]
        registry.validate()
        return registry

    # --------------------------------------------------------------- validation
    def validate(self) -> None:
        """Fail loudly on any inconsistency between config and code."""
        if not self.rungs:
            raise FeatureRegistryError("no rungs defined in feature registry")

        for rung_name, rung in self.rungs.items():
            feats = rung.get("features") or []
            if not feats:
                raise FeatureRegistryError(f"rung '{rung_name}' has an empty feature list")
            if len(feats) != len(set(feats)):
                dupes = sorted({f for f in feats if feats.count(f) > 1})
                raise FeatureRegistryError(f"rung '{rung_name}' has duplicate features: {dupes}")
            unknown = [f for f in feats if f not in FEATURES]
            if unknown:
                raise FeatureRegistryError(
                    f"rung '{rung_name}' references features with no implementation: {unknown}"
                )

        # Gate answers must cover every feature that appears in any rung.
        rung_features = {f for r in self.rungs.values() for f in (r.get("features") or [])}
        missing_gate = sorted(rung_features - set(self.gate))
        if missing_gate:
            raise FeatureRegistryError(
                f"decision-gate answers missing for features: {missing_gate}"
            )

        for dataset, mapping in self.column_maps.items():
            unknown_sem = [k for k in mapping if k not in SEMANTIC_FIELDS]
            if unknown_sem:
                raise FeatureRegistryError(
                    f"column map for '{dataset}' targets unknown semantic fields: {unknown_sem}"
                )

    # ------------------------------------------------------------------ queries
    def rung_features(self, rung: str) -> list[str]:
        if rung not in self.rungs:
            raise KeyError(f"unknown rung '{rung}' (known: {sorted(self.rungs)})")
        return list(self.rungs[rung]["features"])

    def schema_hash(self, rung: str) -> str:
        return feature_schema_hash(self.rung_features(rung))

    def available_semantics(self, dataset: str) -> set[str]:
        if dataset not in self.column_maps:
            raise KeyError(f"no column map for dataset '{dataset}'")
        return set(self.column_maps[dataset])

    def features_supported(self, dataset: str, rung: str) -> list[str]:
        available = self.available_semantics(dataset)
        out = []
        for name in self.rung_features(rung):
            spec = feature_spec(name)
            requires = set(spec.requires) - {"total_packets", "total_bytes"}
            if requires <= available:
                out.append(name)
        return out

    def unsupported_features(self, dataset: str, rung: str) -> list[str]:
        supported = set(self.features_supported(dataset, rung))
        return [f for f in self.rung_features(rung) if f not in supported]

    def rung_fully_supported(self, dataset: str, rung: str) -> bool:
        return not self.unsupported_features(dataset, rung)

    def gate_for(self, feature: str) -> dict[str, str]:
        if feature not in self.gate:
            raise KeyError(f"no gate answers for feature '{feature}'")
        return dict(self.gate[feature])

    def is_excluded_column(self, column: str) -> bool:
        """True if a raw column must never feed the model (identifiers, labels)."""
        return any(p.search(column) for p in self._compiled_exclusions)


def load_feature_registry(
    path: str | Path = "configs/features/features.yaml",
) -> FeatureRegistry:
    return FeatureRegistry.from_file(path)

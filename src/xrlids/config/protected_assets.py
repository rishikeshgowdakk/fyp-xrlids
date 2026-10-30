"""Authoritative protected infrastructure configuration for XRL-IDARS.

Provides a single authoritative source of truth for mission-critical network assets
(Default Gateways, Core DNS, Domain Controllers, Routers) that must NEVER be
isolated or blocked by autonomous response policies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import os
from typing import Sequence


@dataclass(frozen=True)
class ProtectedAsset:
    """Specification of an authoritative protected asset."""

    identifier: str
    role: str
    description: str

    def matches(self, host: str) -> bool:
        """Check if target host matches this protected asset safely."""
        clean_target = str(host).strip()
        if not clean_target:
            return False

        # Exact string match (for symbolic hostnames or exact IP representations)
        if clean_target.lower() == self.identifier.lower():
            return True

        # IP address equivalence check
        try:
            target_ip = ipaddress.ip_address(clean_target)
            asset_ip = ipaddress.ip_address(self.identifier)
            return target_ip == asset_ip
        except ValueError:
            # Identifier or target is a symbolic name or malformed IP string
            return False


# Authoritative baseline protected assets (conservative default deployment)
DEFAULT_PROTECTED_ASSETS: tuple[ProtectedAsset, ...] = (
    ProtectedAsset(
        identifier="192.168.10.1",
        role="Default Gateway",
        description="Core network default gateway routing internal subnet traffic.",
    ),
    ProtectedAsset(
        identifier="192.168.10.2",
        role="Core DNS / NTP",
        description="Internal primary DNS resolver and authoritative NTP time source.",
    ),
    ProtectedAsset(
        identifier="192.168.10.50",
        role="Domain Controller / Identity",
        description="Central domain controller and Kerberos/LDAP identity authority.",
    ),
    ProtectedAsset(
        identifier="gateway",
        role="Gateway Hostname",
        description="Symbolic internal DNS pointer for the default gateway.",
    ),
    ProtectedAsset(
        identifier="dns",
        role="DNS Resolver Hostname",
        description="Symbolic internal DNS pointer for the primary nameserver.",
    ),
    ProtectedAsset(
        identifier="core-router",
        role="Core Router",
        description="Core infrastructure routing control plane.",
    ),
)


class ProtectedInfrastructureRegistry:
    """Authoritative registry for mission-critical infrastructure protected from isolation."""

    def __init__(self, assets: Sequence[ProtectedAsset] | None = None) -> None:
        if assets is None:
            self._assets = list(DEFAULT_PROTECTED_ASSETS)
            # Support optional deployment-specific protected hosts via environment variable
            env_hosts = os.environ.get("XRLIDS_CRITICAL_HOSTS", "").strip()
            if env_hosts:
                for h in env_hosts.split(","):
                    h = h.strip()
                    if h:
                        self._assets.append(
                            ProtectedAsset(
                                identifier=h,
                                role="Deployment Custom Asset",
                                description="Asset specified via XRLIDS_CRITICAL_HOSTS.",
                            )
                        )
        else:
            self._assets = list(assets)

    def is_protected(self, host_identifier: str) -> bool:
        """Evaluate whether a host identifier is a protected infrastructure asset."""
        clean_host = str(host_identifier).strip()
        if not clean_host:
            return False
        for asset in self._assets:
            if asset.matches(clean_host):
                return True
        return False

    def get_protected_identifiers(self) -> frozenset[str]:
        """Return frozenset of all protected identifiers for fast lookups."""
        return frozenset(a.identifier for a in self._assets)

    def get_manifest(self) -> list[dict[str, str]]:
        """Return structured manifest for UI display and audit logging."""
        return [
            {
                "identifier": a.identifier,
                "role": a.role,
                "description": a.description,
            }
            for a in self._assets
        ]


# Singleton default registry instance
AUTHORITATIVE_PROTECTED_REGISTRY = ProtectedInfrastructureRegistry()


def is_critical_infrastructure(host_identifier: str) -> bool:
    """Convenience helper to check if host is protected infrastructure."""
    return AUTHORITATIVE_PROTECTED_REGISTRY.is_protected(host_identifier)

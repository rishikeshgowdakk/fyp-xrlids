"""Canonical bidirectional flow identity for XRL-IDARS (Phase 2).

Provides 5-tuple bidirectional canonicalization:
    (endpoint_a, endpoint_b, port_a, port_b, protocol)

Guarantees:
1. A forward packet and its reverse response packet map to the identical FlowKey.
2. Distinct port pairs, IP pairs, or transport protocols produce distinct FlowKeys.
3. Unsupported or non-transport protocols (e.g., ICMP) map ports safely to 0.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from xrlids.demo.pcap import PacketInfo


@dataclass(frozen=True)
class FlowKey:
    """Canonical bidirectional flow identity 5-tuple."""

    endpoint_a: str
    endpoint_b: str
    port_a: int
    port_b: int
    protocol: int

    @classmethod
    def from_packet(cls, pkt: PacketInfo) -> tuple[FlowKey, bool]:
        """Construct canonical FlowKey and return is_forward boolean.

        Sorts endpoints lexicographically so that (A -> B) and (B -> A) produce
        the exact same canonical key.

        Returns:
            (canonical_flow_key, is_forward)
        """
        # For protocols without transport ports (e.g. ICMP=1, IGMP=2, GRE=47), ensure port is 0
        src_port = pkt.src_port if pkt.protocol in (6, 17) else 0
        dst_port = pkt.dst_port if pkt.protocol in (6, 17) else 0

        ep1 = (pkt.src_ip, src_port)
        ep2 = (pkt.dst_ip, dst_port)

        if ep1 <= ep2:
            return cls(pkt.src_ip, pkt.dst_ip, src_port, dst_port, pkt.protocol), True
        return cls(pkt.dst_ip, pkt.src_ip, dst_port, src_port, pkt.protocol), False

    def __repr__(self) -> str:
        return (
            f"FlowKey({self.endpoint_a}:{self.port_a} <-> "
            f"{self.endpoint_b}:{self.port_b}, proto={self.protocol})"
        )

"""Passive local-device discovery for observational live capture.

The dashboard is a *client* on the WiFi network, not the access point.  A
client cannot read the AP's association table, so this module never claims to
list every device "connected to the router".  It reports devices that are
actually observable from this machine:

* Ethernet/IPv4 frames addressed to this host;
* ARP requests/replies (usually broadcast);
* DHCP hostname/vendor-class options (usually broadcast);
* mDNS names (multicast);
* SSDP service announcements (multicast); and
* the operating system's existing neighbour cache at session start.

Everything is passive.  No ARP scans, pings, probes, or other packets are sent.
Only headers and a few well-known text options are inspected; payloads are not
stored.  The device table lives in memory for the dashboard session only.
"""

from __future__ import annotations

import logging
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_DEVICES = 256
MAX_NAME_LEN = 80
MAX_EVIDENCE_LEN = 80

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_ARP = 0x0806
_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
_ZERO_MAC = "00:00:00:00:00:00"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# A few common OUIs used only when the system IEEE database is unavailable.
_BUILTIN_OUI = {
    "b827eb": "Raspberry Pi Foundation",
    "dc4f22": "Espressif Systems",
    "001a11": "Google LLC",
    "3c5a37": "Samsung Electronics",
    "f01898": "Apple, Inc.",
    "001b63": "Apple, Inc.",
    "f0a731": "TP-Link Corporation Limited",
    "001d7e": "Cisco-Linksys",
    "0024e4": "Withings",
    "b0be76": "TP-Link Corporation Limited",
}

_OUI_LOCK = threading.Lock()
_OUI_CACHE: dict[str, str] | None = None

_HOST_SOURCE_PRIORITY = {
    "DHCP": 3,
    "mDNS": 2,
    "hosts file": 1,
    "local interface": 1,
}


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw[:6])


def _is_unicast_mac(mac: str) -> bool:
    if not mac or mac in (_ZERO_MAC, _BROADCAST_MAC):
        return False
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return False
    return not (first & 0x01)


def _is_random_mac(mac: str) -> bool:
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _is_usable_ipv4(ip: str) -> bool:
    if not ip or ip == "0.0.0.0" or ip == "255.255.255.255":
        return False
    try:
        first = int(ip.split(".", 1)[0])
    except (ValueError, IndexError):
        return False
    return first not in (0, 127) and not (224 <= first <= 239)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _clean_name(value: str, *, strip_local: bool = True) -> str | None:
    """Return a bounded, printable device name (or None if it is a service label)."""
    if not value:
        return None
    name = "".join(ch for ch in str(value) if ch.isprintable()).strip().strip(".").strip()
    if not name:
        return None
    if strip_local and name.lower().endswith(".local"):
        name = name[:-6].strip().strip(".")
    if not name or len(name) > MAX_NAME_LEN:
        name = name[:MAX_NAME_LEN].strip()
    if not name:
        return None
    lowered = name.lower()
    if lowered in {"local", "localhost", "localdomain"}:
        return None
    # mDNS service names (e.g. _airplay._tcp.local) are not device hostnames.
    if name.startswith("_") or "._" in name:
        return None
    return name


def _load_oui(path: str | Path | None = None) -> dict[str, str]:
    """Load an IEEE OUI prefix -> vendor mapping without any network access."""
    global _OUI_CACHE
    with _OUI_LOCK:
        if _OUI_CACHE is not None and path is None:
            return _OUI_CACHE

        candidates: list[Path] = []
        if path is not None:
            candidates.append(Path(path))
        else:
            candidates.extend(
                [
                    Path("/usr/share/ieee-data/oui.txt"),
                    Path("/usr/share/misc/oui.txt"),
                    Path("/usr/share/nmap/nmap-mac-prefixes"),
                ]
            )

        mapping: dict[str, str] = dict(_BUILTIN_OUI)
        for candidate in candidates:
            try:
                if not candidate.is_file():
                    continue
                if candidate.name == "nmap-mac-prefixes":
                    with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
                        for line in handle:
                            match = re.match(r"^([0-9A-Fa-f]{6})\s+(.+?)\s*$", line)
                            if match:
                                mapping[match.group(1).lower()] = match.group(2)[:MAX_NAME_LEN]
                    break

                with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        match = re.match(
                            r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$",
                            line,
                        )
                        if match:
                            prefix = (match.group(1) + match.group(2) + match.group(3)).lower()
                            vendor = match.group(4).strip()
                            if vendor:
                                mapping[prefix] = vendor[:MAX_NAME_LEN]
                break
            except OSError:
                continue

        if path is None:
            _OUI_CACHE = mapping
        return mapping


def _read_command(args: list[str]) -> str:
    """Run a read-only system command and return stdout (empty on failure)."""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return completed.stdout if completed.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _read_arp_cache(interface: str) -> dict[str, str]:
    """Read /proc/net/arp (or `ip neigh`) for initial neighbour information."""
    entries: dict[str, str] = {}
    try:
        text = Path("/proc/net/arp").read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[5] == interface:
                ip, mac = parts[0], parts[3].lower()
                if _is_unicast_mac(mac):
                    entries[ip] = mac
        if entries:
            return entries
    except OSError:
        pass

    text = _read_command(["ip", "neigh", "show", "dev", interface])
    for line in text.splitlines():
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]{17})", line)
        if match and _is_unicast_mac(match.group(2).lower()):
            entries[match.group(1)] = match.group(2).lower()
    return entries


def _read_hosts_file() -> dict[str, str]:
    """Map IPv4 addresses to names in /etc/hosts (no DNS lookup)."""
    mapping: dict[str, str] = {}
    try:
        text = Path("/etc/hosts").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return mapping
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            continue
        name = _clean_name(parts[1], strip_local=False)
        if name:
            mapping[ip] = name
    return mapping


@dataclass
class _Device:
    mac: str
    first_seen: float
    last_seen: float
    ip: str | None = None
    hostname: str | None = None
    hostname_source: str | None = None
    hostname_priority: int = 0
    vendor: str | None = None
    vendor_class: str | None = None
    packets: int = 0
    bytes: int = 0
    evidence: set[str] = field(default_factory=set)
    is_local: bool = False
    is_gateway: bool = False
    is_random_mac: bool = False
    live_seen: bool = False


@dataclass
class _Network:
    interface: str
    ssid: str | None = None
    bssid: str | None = None
    signal_dbm: int | None = None
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    gateway_inferred: bool = False
    local_ip: str | None = None
    local_mac: str | None = None
    local_hostname: str | None = None


class DeviceTracker:
    """Thread-safe passive device tracker fed by raw Ethernet frames.

    ``observe_frame`` is intentionally cheap: it inspects link/IP headers and a
    few well-known UDP payloads, then updates an in-memory map keyed by MAC.
    It never writes to the network or to disk.
    """

    def __init__(
        self,
        interface: str,
        *,
        ssid: str | None = None,
        bssid: str | None = None,
        signal_dbm: int | None = None,
        gateway_ip: str | None = None,
        gateway_mac: str | None = None,
        gateway_inferred: bool = False,
        local_ip: str | None = None,
        local_mac: str | None = None,
        local_hostname: str | None = None,
        oui_path: str | Path | None = None,
    ) -> None:
        self.interface = interface
        self._lock = threading.RLock()
        self._devices: dict[str, _Device] = {}
        self._network = _Network(
            interface=interface,
            ssid=ssid,
            bssid=bssid.lower() if bssid else None,
            signal_dbm=signal_dbm,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac.lower() if gateway_mac else None,
            gateway_inferred=gateway_inferred,
            local_ip=local_ip,
            local_mac=local_mac.lower() if local_mac else None,
            local_hostname=local_hostname,
        )
        self._oui = _load_oui(oui_path)
        self._infra_macs = {
            mac for mac in (self._network.gateway_mac, self._network.bssid) if mac
        }
        # A BSSID is the AP radio, not a client.  Do not show it as a second
        # "router" when the gateway's LAN MAC is different.
        self._hidden_macs = {
            self._network.bssid
        } if self._network.bssid and self._network.bssid != self._network.gateway_mac else set()

        self._seed_known_devices()

    # ------------------------------------------------------------ construction
    @classmethod
    def from_system(cls, interface: str) -> "DeviceTracker":
        """Build a tracker seeded with read-only local system information."""
        if not re.match(r"^[A-Za-z0-9_.:-]+$", interface):
            return cls(interface=interface)

        local_mac = None
        try:
            local_mac = Path(f"/sys/class/net/{interface}/address").read_text(
                encoding="utf-8"
            ).strip().lower()
        except OSError:
            pass

        local_ip = None
        addr_text = _read_command(["ip", "-4", "-o", "addr", "show", "dev", interface])
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", addr_text)
        if match:
            local_ip = match.group(1)

        gateway_ip = None
        # Restrict the default-route lookup to this interface; a VPN or a second
        # NIC may own another default route.
        route_text = _read_command(["ip", "route", "show", "default", "dev", interface])
        match = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", route_text)
        if match:
            gateway_ip = match.group(1)

        ssid = bssid = None
        signal_dbm = None
        iw_text = _read_command(["iw", "dev", interface, "link"])
        match = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", iw_text)
        if match:
            bssid = match.group(1).lower()
        match = re.search(r"^\s*SSID:\s*(.+?)\s*$", iw_text, re.MULTILINE)
        if match:
            ssid = _clean_name(match.group(1), strip_local=False)
        match = re.search(r"^\s*signal:\s*(-?\d+)\s*dBm", iw_text, re.MULTILINE)
        if match:
            try:
                signal_dbm = int(match.group(1))
            except ValueError:
                signal_dbm = None

        arp = _read_arp_cache(interface)
        gateway_mac = arp.get(gateway_ip or "")
        gateway_inferred = False
        if gateway_mac is None and bssid:
            # Fall back to the AP radio MAC only when the LAN-side gateway MAC
            # is not in the neighbour cache (e.g. a freshly started session).
            gateway_mac = bssid
            gateway_inferred = True

        tracker = cls(
            interface=interface,
            ssid=ssid,
            bssid=bssid,
            signal_dbm=signal_dbm,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            gateway_inferred=gateway_inferred,
            local_ip=local_ip,
            local_mac=local_mac,
            local_hostname=_clean_name(socket.gethostname(), strip_local=False),
        )
        tracker._seed_neighbours(arp)
        return tracker

    # ------------------------------------------------------------ public feed
    def observe_frame(self, raw: bytes, timestamp: float | None = None) -> None:
        """Observe one raw Ethernet frame.  Never raises into the capture loop."""
        if len(raw) < 14:
            return
        ts = time.time() if timestamp is None else timestamp
        try:
            src_mac = _format_mac(raw[6:12])
            dst_mac = _format_mac(raw[0:6])
            with self._lock:
                self._touch(src_mac, ts, len(raw))
                self._touch(dst_mac, ts, 0)
                self._parse_frame(raw, src_mac, dst_mac, ts)
        except Exception:  # pragma: no cover - defensive: capture must not die
            logger.debug("Device tracker ignored a malformed frame", exc_info=True)

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable snapshot for the dashboard API."""
        with self._lock:
            now = time.time()
            devices = [self._device_dict(device, now) for device in self._devices.values()]
            devices.sort(
                key=lambda item: (
                    0 if item["is_gateway"] else 1 if item["is_local"] else 2,
                    -float(item["last_seen_epoch"]),
                )
            )
            seen = sum(1 for item in devices if item["live_seen"])
            return {
                "scope": "passive-observed",
                "network": self._network_dict(),
                "devices": devices,
                "counters": {
                    "total": len(devices),
                    "seen": seen,
                    "cached": len(devices) - seen,
                },
                "note": (
                    "Passive observation only. A WiFi client cannot read the access point's "
                    "association table; devices idle or isolated by the AP may be missing. "
                    "No probes or scans are sent."
                ),
            }

    # ------------------------------------------------------------ seeding
    def _seed_known_devices(self) -> None:
        now = time.time()
        network = self._network
        if network.local_mac:
            local = self._ensure(network.local_mac, now, evidence="local interface")
            local.is_local = True
            if network.local_ip:
                self._set_ip(local, network.local_ip, now, "local interface")
            if network.local_hostname:
                self._set_hostname(local, network.local_hostname, "local interface")
        if network.gateway_mac:
            gateway = self._ensure(network.gateway_mac, now, evidence="gateway")
            gateway.is_gateway = True
            if network.gateway_ip:
                self._set_ip(gateway, network.gateway_ip, now, "gateway")
        if network.bssid and network.bssid != network.gateway_mac:
            # Keep the BSSID in the network summary only; it is the AP radio,
            # not a separate client device.
            self._hidden_macs.add(network.bssid)

    def _seed_neighbours(self, arp: dict[str, str]) -> None:
        now = time.time()
        hosts = _read_hosts_file()
        with self._lock:
            for ip, mac in arp.items():
                if mac in self._hidden_macs:
                    continue
                device = self._ensure(mac, now, evidence="neighbor cache")
                self._set_ip(device, ip, now, "neighbor cache")
                if ip in hosts:
                    self._set_hostname(device, hosts[ip], "hosts file")
                if ip == self._network.gateway_ip:
                    device.is_gateway = True
                if ip == self._network.local_ip:
                    device.is_local = True

    # ------------------------------------------------------------ record helpers
    def _ensure(
        self,
        mac: str,
        ts: float,
        *,
        evidence: str | None = None,
        live: bool = False,
    ) -> _Device:
        device = self._devices.get(mac)
        if device is None:
            if len(self._devices) >= MAX_DEVICES:
                # Prefer evicting a cache-only entry; never let an unbounded
                # public network grow the dashboard process without limit.
                victim = min(
                    self._devices.values(),
                    key=lambda item: (item.live_seen, item.last_seen),
                )
                self._devices.pop(victim.mac, None)
            device = _Device(
                mac=mac,
                first_seen=ts,
                last_seen=ts,
                is_random_mac=_is_random_mac(mac),
            )
            if not device.is_random_mac:
                device.vendor = self._oui.get(mac.replace(":", "")[:6])
            self._devices[mac] = device
        else:
            device.last_seen = max(device.last_seen, ts)
        if live:
            device.live_seen = True
            device.evidence.add("live capture")
        if evidence:
            device.evidence.add(evidence)
        return device

    def _touch(self, mac: str, ts: float, packet_length: int) -> None:
        if not _is_unicast_mac(mac):
            return
        if mac in self._hidden_macs:
            # WiFi frames use the AP radio's BSSID rather than its LAN MAC.
            # Attribute that activity to the gateway row instead of showing a
            # confusing second \"router\" entry.
            if not self._network.gateway_mac:
                return
            mac = self._network.gateway_mac
        device = self._ensure(mac, ts, evidence="Ethernet", live=True)
        if packet_length > 0:
            # Count frames sourced by this MAC.  Destination-only frames update
            # last_seen but are not double-counted as device traffic.
            device.packets += 1
            device.bytes += packet_length

    def _set_ip(self, device: _Device, ip: str, ts: float, evidence: str) -> None:
        if not _is_usable_ipv4(ip):
            return
        if device.mac in self._infra_macs and ip != self._network.gateway_ip:
            # Frames from the AP can carry a remote source IP (NAT/routed
            # traffic); never label the router's MAC with a remote address.
            return
        device.ip = ip
        device.evidence.add(evidence)
        if ip == self._network.gateway_ip:
            device.is_gateway = True
        if ip == self._network.local_ip:
            device.is_local = True

    def _set_hostname(self, device: _Device, value: str, source: str) -> None:
        name = _clean_name(value)
        if not name:
            return
        priority = _HOST_SOURCE_PRIORITY.get(source, 1)
        if device.hostname and priority <= device.hostname_priority:
            return
        device.hostname = name
        device.hostname_source = source
        device.hostname_priority = priority

    # ------------------------------------------------------------ frame parsing
    def _parse_frame(self, raw: bytes, src_mac: str, dst_mac: str, ts: float) -> None:
        offset = 12
        ethertype = struct.unpack("!H", raw[offset : offset + 2])[0]
        offset += 2
        while ethertype in _VLAN_TYPES:
            if len(raw) < offset + 4:
                return
            ethertype = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
            offset += 4

        if ethertype == _ETHERTYPE_ARP:
            self._parse_arp(raw, offset, ts)
            return
        if ethertype != _ETHERTYPE_IPV4:
            return
        self._parse_ipv4(raw, offset, src_mac, dst_mac, ts)

    def _parse_arp(self, raw: bytes, offset: int, ts: float) -> None:
        if len(raw) < offset + 28:
            return
        htype, ptype, hlen, plen, _oper = struct.unpack("!HHBBH", raw[offset : offset + 8])
        if htype != 1 or ptype != _ETHERTYPE_IPV4 or hlen != 6 or plen != 4:
            return
        sender_mac = _format_mac(raw[offset + 8 : offset + 14])
        sender_ip = socket.inet_ntoa(raw[offset + 14 : offset + 18])
        target_mac = _format_mac(raw[offset + 18 : offset + 24])
        target_ip = socket.inet_ntoa(raw[offset + 24 : offset + 28])

        self._learn_mapping(sender_mac, sender_ip, ts, "ARP")
        if _is_unicast_mac(target_mac):
            self._learn_mapping(target_mac, target_ip, ts, "ARP")

    def _parse_ipv4(
        self, raw: bytes, offset: int, src_mac: str, dst_mac: str, ts: float
    ) -> None:
        if len(raw) < offset + 20:
            return
        version_ihl = raw[offset]
        if version_ihl >> 4 != 4:
            return
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(raw) < offset + ihl:
            return
        protocol = raw[offset + 9]
        src_ip = socket.inet_ntoa(raw[offset + 12 : offset + 16])
        dst_ip = socket.inet_ntoa(raw[offset + 16 : offset + 20])

        # Only source MAC <-> source IP is authoritative for a host.  A frame
        # from the AP can have a remote source IP, so skip infrastructure MACs
        # unless the address is the gateway itself.
        if src_mac not in self._infra_macs or src_ip == self._network.gateway_ip:
            self._learn_mapping(src_mac, src_ip, ts, "IPv4")
        if dst_mac not in self._infra_macs or dst_ip == self._network.gateway_ip:
            self._learn_mapping(dst_mac, dst_ip, ts, "IPv4")

        if protocol != 17 or len(raw) < offset + ihl + 8:
            return
        transport = offset + ihl
        src_port, dst_port, udp_len = struct.unpack("!HHH", raw[transport : transport + 6])
        payload_start = transport + 8
        payload_end = min(len(raw), transport + max(udp_len, 8))
        payload = raw[payload_start:payload_end]
        if not payload:
            return

        if 67 in (src_port, dst_port) or 68 in (src_port, dst_port):
            self._parse_dhcp(payload, src_mac, dst_mac, ts)
        elif 5353 in (src_port, dst_port):
            self._parse_mdns(payload, src_mac, src_ip, ts)
        elif 1900 in (src_port, dst_port):
            self._parse_ssdp(payload, src_mac, ts)

    def _learn_mapping(self, mac: str, ip: str, ts: float, evidence: str) -> None:
        if not _is_unicast_mac(mac) or mac in self._hidden_macs:
            return
        device = self._ensure(mac, ts, evidence=evidence, live=True)
        self._set_ip(device, ip, ts, evidence)

    # ------------------------------------------------------------ DHCP
    def _parse_dhcp(
        self, payload: bytes, src_mac: str, dst_mac: str, ts: float
    ) -> None:
        if len(payload) < 240 or payload[0] not in (1, 2):
            return
        if payload[236:240] != b"\x63\x82\x53\x63":
            return
        chaddr = _format_mac(payload[28:34])
        target_mac = chaddr if _is_unicast_mac(chaddr) else src_mac
        if target_mac in self._hidden_macs:
            return
        device = self._ensure(target_mac, ts, evidence="DHCP", live=True)

        ciaddr = socket.inet_ntoa(payload[12:16])
        yiaddr = socket.inet_ntoa(payload[16:20])
        if payload[0] == 1 and _is_usable_ipv4(ciaddr):
            self._set_ip(device, ciaddr, ts, "DHCP")
        elif payload[0] == 2 and _is_usable_ipv4(yiaddr):
            self._set_ip(device, yiaddr, ts, "DHCP")

        offset = 240
        while offset < len(payload):
            code = payload[offset]
            offset += 1
            if code == 0:
                continue
            if code == 255 or offset >= len(payload):
                break
            length = payload[offset]
            offset += 1
            if offset + length > len(payload):
                break
            data = payload[offset : offset + length]
            offset += length
            if code == 12:
                self._set_hostname(device, data.decode("utf-8", errors="replace"), "DHCP")
            elif code == 60:
                value = "".join(ch for ch in data.decode("utf-8", errors="replace") if ch.isprintable())
                if value:
                    device.vendor_class = value[:MAX_EVIDENCE_LEN]
            elif code == 50 and len(data) == 4 and device.ip is None:
                # A DHCP request's requested-address option is a useful hint,
                # but only ARP/DHCP ACK confirmation promotes it to the IP.
                pass

    # ------------------------------------------------------------ mDNS
    def _parse_mdns(self, payload: bytes, src_mac: str, src_ip: str, ts: float) -> None:
        if src_mac in self._infra_macs or src_mac in self._hidden_macs:
            return
        if len(payload) < 12:
            return
        try:
            qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", payload[4:12])
        except struct.error:
            return
        # Bound work on malformed/untrusted multicast packets.
        qdcount = min(qdcount, 64)
        record_count = min(ancount + nscount + arcount, 128)
        self._learn_mapping(src_mac, src_ip, ts, "mDNS")
        device = self._ensure(src_mac, ts, evidence="mDNS", live=True)

        offset = 12
        for _ in range(qdcount):
            parsed = _read_dns_name(payload, offset)
            if parsed is None:
                return
            name, offset = parsed
            if offset + 4 > len(payload):
                return
            offset += 4  # qtype, qclass
            self._set_hostname(device, name, "mDNS")

        for _ in range(record_count):
            parsed = _read_dns_name(payload, offset)
            if parsed is None:
                return
            name, offset = parsed
            if offset + 10 > len(payload):
                return
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
            offset += 10
            rdata_offset = offset
            if offset + rdlength > len(payload):
                return
            offset += rdlength
            if rtype in (1, 28):  # A / AAAA: the owner name is the hostname
                self._set_hostname(device, name, "mDNS")
            elif rtype == 33:  # SRV: target host begins after priority/weight/port
                parsed_target = _read_dns_name(payload, rdata_offset + 6)
                if parsed_target is not None:
                    self._set_hostname(device, parsed_target[0], "mDNS")

    # ------------------------------------------------------------ SSDP
    def _parse_ssdp(self, payload: bytes, src_mac: str, ts: float) -> None:
        if src_mac in self._infra_macs or src_mac in self._hidden_macs:
            return
        device = self._ensure(src_mac, ts, evidence="SSDP", live=True)
        text = payload[:4096].decode("utf-8", errors="replace")
        match = re.search(r"(?im)^SERVER:\s*(.+)$", text)
        if match and not device.vendor_class:
            server = "".join(ch for ch in match.group(1) if ch.isprintable()).strip()
            if server:
                device.vendor_class = server[:MAX_EVIDENCE_LEN]

    # ------------------------------------------------------------ serialization
    def _device_dict(self, device: _Device, now: float) -> dict[str, Any]:
        if device.is_local:
            role = "this_device"
            fallback = "This laptop"
        elif device.is_gateway:
            role = "gateway"
            fallback = "Gateway router"
        else:
            role = "observed"
            fallback = device.vendor or "Unknown device"
        label = device.hostname or fallback
        vendor = "Private/random MAC" if device.is_random_mac else (device.vendor or "Unknown")
        return {
            "mac": device.mac,
            "ip": device.ip,
            "hostname": device.hostname,
            "label": label,
            "role": role,
            "vendor": vendor,
            "vendor_class": device.vendor_class,
            "is_local": device.is_local,
            "is_gateway": device.is_gateway,
            "is_random_mac": device.is_random_mac,
            "live_seen": device.live_seen,
            "packets": device.packets,
            "bytes": device.bytes,
            "first_seen": _iso(device.first_seen),
            "last_seen": _iso(device.last_seen),
            "first_seen_epoch": round(device.first_seen, 3),
            "last_seen_epoch": round(device.last_seen, 3),
            "age_s": round(max(0.0, now - device.last_seen), 1),
            "evidence": sorted(device.evidence),
            "hostname_source": device.hostname_source,
        }

    def _network_dict(self) -> dict[str, Any]:
        network = self._network
        gateway_vendor = None
        if network.gateway_mac and not _is_random_mac(network.gateway_mac):
            gateway_vendor = self._oui.get(network.gateway_mac.replace(":", "")[:6])
        ap_vendor = None
        if network.bssid and not _is_random_mac(network.bssid):
            ap_vendor = self._oui.get(network.bssid.replace(":", "")[:6])
        return {
            "interface": network.interface,
            "ssid": network.ssid,
            "bssid": network.bssid,
            "signal_dbm": network.signal_dbm,
            "gateway_ip": network.gateway_ip,
            "gateway_mac": network.gateway_mac,
            "gateway_vendor": gateway_vendor,
            "gateway_inferred": network.gateway_inferred,
            "ap_vendor": ap_vendor,
            "local_ip": network.local_ip,
            "local_mac": network.local_mac,
            "local_hostname": network.local_hostname,
        }


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int] | None:
    """Read a (possibly compressed) DNS name; return name and next offset."""
    labels: list[str] = []
    cursor = offset
    next_offset = offset
    jumped = False
    seen = 0
    while True:
        if cursor >= len(data) or seen > 128:
            return None
        length = data[cursor]
        if length == 0:
            cursor += 1
            if not jumped:
                next_offset = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                return None
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer >= len(data):
                return None
            if not jumped:
                next_offset = cursor + 2
                jumped = True
            cursor = pointer
            seen += 1
            continue
        if length & 0xC0:
            return None
        cursor += 1
        if cursor + length > len(data):
            return None
        label = data[cursor : cursor + length].decode("utf-8", errors="replace")
        labels.append(label)
        cursor += length
        seen += 1
    name = ".".join(labels)
    return name, next_offset

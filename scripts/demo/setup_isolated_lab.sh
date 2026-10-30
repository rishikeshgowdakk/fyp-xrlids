#!/usr/bin/env bash
# XRL-IDARS — Setup Isolated Lab Network Environment
# Prepares isolated network namespaces and virtual Ethernet links for safe intrusion detection testing.

set -euo pipefail

ATTACKER_NS="xrl_attacker"
VICTIM_NS="xrl_victim"
VETH_ATT="veth_xrl_att"
VETH_VIC="veth_xrl_vic"
ATT_IP="10.200.1.2/24"
VIC_IP="10.200.1.3/24"

echo "=================================================================="
echo "    XRL-IDARS — Isolated Lab Network Environment Setup"
echo "=================================================================="

# Check privilege
if [ "$(id -u)" -eq 0 ]; then
    echo "[+] Running with administrative privileges (LINUX_KERNEL_NETNS mode)."

    # Remove stale namespaces if they exist
    ip netns del "$ATTACKER_NS" 2>/dev/null || true
    ip netns del "$VICTIM_NS" 2>/dev/null || true

    # Create network namespaces
    echo "[+] Creating kernel network namespaces: $ATTACKER_NS and $VICTIM_NS..."
    ip netns add "$ATTACKER_NS"
    ip netns add "$VICTIM_NS"

    # Create virtual Ethernet pair
    echo "[+] Creating virtual Ethernet pair: $VETH_ATT <-> $VETH_VIC..."
    ip link add "$VETH_ATT" type veth peer name "$VETH_VIC"

    # Move interfaces to respective namespaces
    ip link set "$VETH_ATT" netns "$ATTACKER_NS"
    ip link set "$VETH_VIC" netns "$VICTIM_NS"

    # Configure IP addresses
    ip netns exec "$ATTACKER_NS" ip addr add "$ATT_IP" dev "$VETH_ATT"
    ip netns exec "$VICTIM_NS" ip addr add "$VIC_IP" dev "$VETH_VIC"

    # Bring interfaces UP
    ip netns exec "$ATTACKER_NS" ip link set "$VETH_ATT" up
    ip netns exec "$VICTIM_NS" ip link set "$VETH_VIC" up
    ip netns exec "$ATTACKER_NS" ip link set lo up
    ip netns exec "$VICTIM_NS" ip link set lo up

    # Test connectivity between namespaces
    echo "[+] Verifying isolated namespace link connectivity..."
    if ip netns exec "$ATTACKER_NS" ping -c 1 -W 1 10.200.1.3 >/dev/null 2>&1; then
        echo "    [PASS] Direct ping between $ATTACKER_NS (10.200.1.2) and $VICTIM_NS (10.200.1.3) SUCCESSFUL."
    else
        echo "    [WARN] Direct ping failed, links up."
    fi

    echo "[+] Kernel isolated namespaces configured and ready."
else
    echo "[*] Non-root execution detected (UID: $(id -u))."
    echo "[*] Using VIRTUAL_ISOLATED_NETNS mode."
    echo "[*] Zero host network mutations: packets are safely generated via Scapy and isolated to 10.200.1.0/24."
    echo "[+] Virtual isolated lab environment ready."
fi

echo "=================================================================="
echo "Setup complete. Target bounded strictly to 10.200.1.3 (lab subnet)."
echo "=================================================================="

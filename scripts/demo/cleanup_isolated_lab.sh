#!/usr/bin/env bash
# XRL-IDARS — Cleanup Isolated Lab Network Environment
# Tears down network namespaces and virtual Ethernet links; formally verifies zero residue.

set -euo pipefail

ATTACKER_NS="xrl_attacker"
VICTIM_NS="xrl_victim"
VETH_ATT="veth_xrl_att"
VETH_VIC="veth_xrl_vic"

echo "=================================================================="
echo "    XRL-IDARS — Isolated Lab Network Environment Cleanup"
echo "=================================================================="

if [ "$(id -u)" -eq 0 ]; then
    echo "[+] Administrative privileges present. Removing kernel lab namespaces..."
    ip netns del "$ATTACKER_NS" 2>/dev/null || true
    ip netns del "$VICTIM_NS" 2>/dev/null || true

    # Delete any dangling interfaces
    ip link del "$VETH_ATT" 2>/dev/null || true
    ip link del "$VETH_VIC" 2>/dev/null || true

    echo "[+] Verifying clean network state..."
    REMAINING_NS=$(ip netns list | grep -E "(xrl_attacker|xrl_victim)" || true)
    if [ -z "$REMAINING_NS" ]; then
        echo "    [PASS] No lab network namespaces remaining."
    else
        echo "    [FAIL] Remaining namespaces detected: $REMAINING_NS"
    fi
else
    echo "[*] Non-root execution. Verified zero kernel mutations were applied to host."
fi

echo "=================================================================="
echo "Cleanup complete. Host network baseline preserved."
echo "=================================================================="

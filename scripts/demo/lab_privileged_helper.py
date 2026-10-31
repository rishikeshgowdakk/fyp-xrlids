#!/usr/bin/env python3
"""Narrowly Scoped Privileged Lab Helper for XRL-IDARS.

Safely creates, manages, and destroys isolated Linux network namespaces (xrlids_att_01, xrlids_vic_01)
and virtual Ethernet link (veth_xrl_att <-> veth_xrl_vic) with strict ownership validation.
Executes packet capture inside the victim namespace and forwards packets over Unix domain socket IPC.

Must be invoked with administrative privileges (e.g. via sudo or pkexec).
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ATTACKER_NS = "xrlids_att_01"
VICTIM_NS = "xrlids_vic_01"
VETH_ATTACKER = "veth_xrl_att"
VETH_VICTIM = "veth_xrl_vic"
ATTACKER_IP = "10.200.1.2"
VICTIM_IP = "10.200.1.3"
LAB_SUBNET = "10.200.1.0/24"

MARKER_FILE = Path("/tmp/xrlids_lab.json")
PID_FILE = Path("/tmp/xrlids_capture.pid")


def check_root() -> None:
    """Ensure process runs with root privileges."""
    if os.geteuid() != 0:
        res = {
            "success": False,
            "error": "Root privileges required (euid != 0). Run via pkexec or sudo.",
            "euid": os.geteuid(),
        }
        print(json.dumps(res))
        sys.exit(1)


def get_existing_namespaces() -> list[str]:
    """Return list of existing network namespaces."""
    try:
        proc = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True, check=True)
        ns_list = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                ns_name = line.split()[0]
                ns_list.append(ns_name)
        return ns_list
    except Exception:
        return []


def is_owned_lab() -> bool:
    """Verify whether existing namespaces were created by XRL-IDARS."""
    if MARKER_FILE.exists():
        try:
            with open(MARKER_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("owner") == "xrlids":
                return True
        except Exception:
            pass

    # Secondary check: inspect interfaces inside namespaces
    try:
        proc = subprocess.run(
            ["ip", "netns", "exec", ATTACKER_NS, "ip", "-br", "link"],
            capture_output=True,
            text=True,
            check=False,
        )
        if VETH_ATTACKER in proc.stdout:
            return True
    except Exception:
        pass
    return False


def setup_lab() -> dict[str, Any]:
    """Create isolated network namespaces and veth pair with safe collision handling."""
    check_root()

    existing_ns = get_existing_namespaces()
    has_att = ATTACKER_NS in existing_ns
    has_vic = VICTIM_NS in existing_ns

    # Safe collision handling:
    if has_att or has_vic:
        if is_owned_lab():
            # Clean up previous XRL-IDARS lab run
            teardown_lab()
        else:
            return {
                "success": False,
                "error": f"Collision: namespace '{ATTACKER_NS}' or '{VICTIM_NS}' already exists and is not verified as owned by XRL-IDARS.",
            }

    try:
        # 1. Create namespaces
        subprocess.run(["ip", "netns", "add", ATTACKER_NS], check=True, capture_output=True)
        subprocess.run(["ip", "netns", "add", VICTIM_NS], check=True, capture_output=True)

        # 2. Create isolated veth pair
        subprocess.run(
            ["ip", "link", "add", VETH_ATTACKER, "type", "veth", "peer", "name", VETH_VICTIM],
            check=True,
            capture_output=True,
        )

        # 3. Move interfaces into respective namespaces
        subprocess.run(["ip", "link", "set", VETH_ATTACKER, "netns", ATTACKER_NS], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", VETH_VICTIM, "netns", VICTIM_NS], check=True, capture_output=True)

        # 4. Configure IP addresses
        subprocess.run(
            ["ip", "netns", "exec", ATTACKER_NS, "ip", "addr", "add", f"{ATTACKER_IP}/24", "dev", VETH_ATTACKER],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["ip", "netns", "exec", VICTIM_NS, "ip", "addr", "add", f"{VICTIM_IP}/24", "dev", VETH_VICTIM],
            check=True,
            capture_output=True,
        )

        # 5. Bring interfaces and loopback UP
        subprocess.run(["ip", "netns", "exec", ATTACKER_NS, "ip", "link", "set", "dev", VETH_ATTACKER, "up"], check=True, capture_output=True)
        subprocess.run(["ip", "netns", "exec", VICTIM_NS, "ip", "link", "set", "dev", VETH_VICTIM, "up"], check=True, capture_output=True)
        subprocess.run(["ip", "netns", "exec", ATTACKER_NS, "ip", "link", "set", "dev", "lo", "up"], check=True, capture_output=True)
        subprocess.run(["ip", "netns", "exec", VICTIM_NS, "ip", "link", "set", "dev", "lo", "up"], check=True, capture_output=True)

        # 6. Verify link reachability
        ping_res = subprocess.run(
            ["ip", "netns", "exec", ATTACKER_NS, "ping", "-c", "1", "-W", "1", VICTIM_IP],
            capture_output=True,
            text=True,
            check=False,
        )
        conn_ok = (ping_res.returncode == 0)

        # 7. Write ownership marker file
        marker = {
            "owner": "xrlids",
            "created_at": time.time(),
            "namespaces": [ATTACKER_NS, VICTIM_NS],
            "interfaces": [VETH_ATTACKER, VETH_VICTIM],
            "attacker_ip": ATTACKER_IP,
            "victim_ip": VICTIM_IP,
        }
        with open(MARKER_FILE, "w", encoding="utf-8") as f:
            json.dump(marker, f)

        return {
            "success": True,
            "message": "Isolated lab topology created and verified.",
            "attacker_ns": ATTACKER_NS,
            "victim_ns": VICTIM_NS,
            "attacker_ip": ATTACKER_IP,
            "victim_ip": VICTIM_IP,
            "attacker_iface": VETH_ATTACKER,
            "victim_iface": VETH_VICTIM,
            "connectivity_verified": conn_ok,
        }
    except Exception as exc:
        teardown_lab()
        return {
            "success": False,
            "error": f"Failed to setup isolated lab topology: {exc}",
        }


def teardown_lab() -> dict[str, Any]:
    """Clean up only namespaces and interfaces created by XRL-IDARS."""
    check_root()

    # Stop capture worker if active
    stop_capture()

    # Verify ownership before deletion
    existing_ns = get_existing_namespaces()
    deleted = []

    for ns in (ATTACKER_NS, VICTIM_NS):
        if ns in existing_ns:
            try:
                subprocess.run(["ip", "netns", "del", ns], check=True, capture_output=True)
                deleted.append(ns)
            except Exception as exc:
                pass

    # Delete any dangling interfaces on host
    for iface in (VETH_ATTACKER, VETH_VICTIM):
        try:
            subprocess.run(["ip", "link", "del", iface], capture_output=True, check=False)
        except Exception:
            pass

    if MARKER_FILE.exists():
        try:
            MARKER_FILE.unlink()
        except Exception:
            pass

    # Verify clean state
    remaining = [ns for ns in (ATTACKER_NS, VICTIM_NS) if ns in get_existing_namespaces()]

    return {
        "success": len(remaining) == 0,
        "deleted_namespaces": deleted,
        "remaining_namespaces": remaining,
        "message": "Lab resources cleaned up successfully." if len(remaining) == 0 else f"Failed to clean: {remaining}",
    }


def lab_status() -> dict[str, Any]:
    """Query current status of namespaces, interfaces, connectivity, and capture."""
    existing_ns = get_existing_namespaces()
    has_att = ATTACKER_NS in existing_ns
    has_vic = VICTIM_NS in existing_ns

    conn_ok = False
    if has_att and has_vic:
        try:
            res = subprocess.run(
                ["ip", "netns", "exec", ATTACKER_NS, "ping", "-c", "1", "-W", "1", VICTIM_IP],
                capture_output=True,
                check=False,
            )
            conn_ok = (res.returncode == 0)
        except Exception:
            conn_ok = False

    capture_active = False
    capture_pid = None
    if PID_FILE.exists():
        try:
            with open(PID_FILE, "r") as f:
                pid_str = f.read().strip()
                if pid_str:
                    pid = int(pid_str)
                    os.kill(pid, 0)  # Check if PID exists
                    capture_active = True
                    capture_pid = pid
        except Exception:
            capture_active = False

    return {
        "lab_created": (has_att and has_vic),
        "attacker_ns": ATTACKER_NS if has_att else None,
        "victim_ns": VICTIM_NS if has_vic else None,
        "attacker_ip": ATTACKER_IP,
        "victim_ip": VICTIM_IP,
        "connectivity_ok": conn_ok,
        "capture_active": capture_active,
        "capture_pid": capture_pid,
    }


def start_capture(socket_path: str = "/tmp/xrlids_capture.sock") -> dict[str, Any]:
    """Launch capture worker inside the victim namespace."""
    check_root()

    status = lab_status()
    if not status["lab_created"]:
        return {
            "success": False,
            "error": "Cannot start capture: isolated lab namespaces not created yet.",
        }

    # Stop any existing worker
    stop_capture()

    repo_root = Path(__file__).resolve().parents[2]
    py_exec = str(repo_root / ".venv" / "bin" / "python")
    if not os.path.exists(py_exec):
        py_exec = sys.executable

    cmd = [
        "ip", "netns", "exec", VICTIM_NS,
        py_exec, "-m", "xrlids.capture.netns_capture_worker",
        "--iface", VETH_VICTIM,
        "--socket", socket_path,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(repo_root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pid = proc.pid
        with open(PID_FILE, "w") as f:
            f.write(str(pid))

        # Give worker 0.2s to bind socket
        time.sleep(0.2)
        if proc.poll() is not None:
            return {
                "success": False,
                "error": f"Capture worker exited immediately with code {proc.returncode}",
            }

        return {
            "success": True,
            "pid": pid,
            "netns": VICTIM_NS,
            "interface": VETH_VICTIM,
            "socket_path": socket_path,
            "message": f"Real packet capture active inside {VICTIM_NS} on {VETH_VICTIM}.",
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to spawn capture worker: {exc}",
        }


def stop_capture() -> dict[str, Any]:
    """Stop running capture worker inside victim namespace."""
    if not PID_FILE.exists():
        return {"success": True, "message": "No active capture worker found."}

    pid = None
    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
    except Exception:
        pass

    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait up to 1.5s
            for _ in range(15):
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)
                except OSError:
                    break
            else:
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception as exc:
            pass

    try:
        PID_FILE.unlink()
    except Exception:
        pass

    return {"success": True, "message": "Capture worker stopped cleanly."}


def run_netns_iptables(netns: str, iptables_args: list[str]) -> dict[str, Any]:
    """Execute iptables safely inside a lab namespace."""
    check_root()
    if netns not in (VICTIM_NS, ATTACKER_NS):
        return {
            "success": False,
            "returncode": 1,
            "stdout": "",
            "stderr": f"Refusing to execute iptables in non-lab namespace '{netns}'.",
        }
    cmd = ["ip", "netns", "exec", netns, "iptables"] + list(iptables_args)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0, check=False)
        return {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as exc:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="XRL-IDARS Privileged Lab Helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("setup", help="Create isolated network namespaces and veth topology")
    subparsers.add_parser("teardown", help="Clean up isolated namespaces and interfaces")
    subparsers.add_parser("status", help="Get current lab and capture status")

    cap_start = subparsers.add_parser("start-capture", help="Start packet capture inside victim namespace")
    cap_start.add_argument("--socket", default="/tmp/xrlids_capture.sock", help="Unix domain socket path")

    subparsers.add_parser("stop-capture", help="Stop packet capture worker")

    ipt_parser = subparsers.add_parser("netns-iptables", help="Execute iptables inside lab namespace")
    ipt_parser.add_argument("--netns", required=True, choices=[VICTIM_NS, ATTACKER_NS])
    ipt_parser.add_argument("iptables_args", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    if args.command == "setup":
        res = setup_lab()
    elif args.command == "teardown":
        res = teardown_lab()
    elif args.command == "status":
        res = lab_status()
    elif args.command == "start-capture":
        res = start_capture(socket_path=args.socket)
    elif args.command == "stop-capture":
        res = stop_capture()
    elif args.command == "netns-iptables":
        res = run_netns_iptables(netns=args.netns, iptables_args=args.iptables_args)
    else:
        res = {"success": False, "error": f"Unknown command {args.command}"}

    print(json.dumps(res))
    if not res.get("success", True) and args.command in ("setup", "teardown", "start-capture"):
        sys.exit(1)


if __name__ == "__main__":
    main()

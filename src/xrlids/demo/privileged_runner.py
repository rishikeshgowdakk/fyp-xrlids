"""Privileged Command Execution Runner for XRL-IDARS Lab Operations.

Coordinates execution of the narrowly scoped privileged helper (`lab_privileged_helper.py`).
Supports:
1. Direct execution when already root (`euid == 0`).
2. `sudo -n` passwordless execution (e.g. if `/etc/sudoers.d/xrlids` is configured).
3. `pkexec` PolicyKit elevation (standard Ubuntu graphical authentication dialog).
4. Informative fail-safe reporting with one-time terminal setup instructions.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

from xrlids.utils.logging_utils import get_logger

logger = get_logger("xrlids.demo.runner")

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER_PATH = REPO_ROOT / "scripts" / "demo" / "lab_privileged_helper.py"


def get_python_executable() -> str:
    """Return python executable inside active virtualenv if present."""
    venv_py = REPO_ROOT / ".venv" / "bin" / "python"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable


def run_helper(
    command: str,
    extra_args: list[str] | None = None,
    timeout_s: float = 15.0,
) -> tuple[bool, dict[str, Any], str]:
    """Execute privileged lab helper with automatic escalation strategy.

    Returns:
        (success, result_dict, diagnostic_message)
    """
    if not HELPER_PATH.exists():
        return False, {}, f"Privileged helper script not found at {HELPER_PATH}"

    py_bin = get_python_executable()
    cmd_args = [py_bin, str(HELPER_PATH), command] + (extra_args or [])

    # 1. Direct execution (read-only 'status' or when running as root)
    if command == "status" or os.geteuid() == 0:
        try:
            res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout_s, check=False)
            if res.returncode == 0:
                try:
                    data = json.loads(res.stdout.strip())
                    return True, data, data.get("message", "Success")
                except json.JSONDecodeError:
                    return True, {"raw": res.stdout}, "Command succeeded."
            else:
                err_text = res.stderr.strip() or res.stdout.strip() or f"Exited with code {res.returncode}"
                return False, {}, err_text
        except Exception as exc:
            return False, {}, f"Execution failed: {exc}"

    # 2. Try passwordless sudo (-n)
    if shutil.which("sudo"):
        try:
            sudo_cmd = ["sudo", "-n"] + cmd_args
            res = subprocess.run(sudo_cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
            if res.returncode == 0:
                try:
                    data = json.loads(res.stdout.strip())
                    return True, data, data.get("message", "Success via sudo")
                except json.JSONDecodeError:
                    return True, {"raw": res.stdout}, "Success via sudo."
        except Exception:
            pass

    # 3. Try pkexec (PolicyKit elevation with GUI prompt)
    if shutil.which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        try:
            pkexec_cmd = ["pkexec", "--user", "root"] + cmd_args
            res = subprocess.run(pkexec_cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
            if res.returncode == 0:
                try:
                    data = json.loads(res.stdout.strip())
                    return True, data, data.get("message", "Success via pkexec")
                except json.JSONDecodeError:
                    return True, {"raw": res.stdout}, "Success via pkexec."
            else:
                stderr_msg = res.stderr.strip()
                if "dismissed" in stderr_msg.lower() or "not authorized" in stderr_msg.lower():
                    return False, {}, "Authentication dialog was cancelled or dismissed."
        except subprocess.TimeoutExpired:
            return False, {}, "Authentication dialog timed out."
        except Exception as exc:
            logger.debug("pkexec invocation error: %s", exc)

    # 4. Privilege escalation required notice
    setup_help = (
        "Privilege escalation required for Linux network namespace creation.\n"
        "Option A: Authenticate using the system prompt if available.\n"
        "Option B: Run one-time terminal authorization command:\n"
        f"  sudo {py_bin} {HELPER_PATH} setup"
    )
    return False, {}, setup_help


def get_lab_status() -> dict[str, Any]:
    """Query real-time lab topology and capture state."""
    ok, data, _ = run_helper("status", timeout_s=3.0)
    if ok and data:
        return data
    return {
        "lab_created": False,
        "attacker_ns": None,
        "victim_ns": None,
        "attacker_ip": "10.200.1.2",
        "victim_ip": "10.200.1.3",
        "connectivity_ok": False,
        "capture_active": False,
        "capture_pid": None,
    }


def privileged_netns_cmd_runner(
    cmd: Sequence[str],
    capture_output: bool = True,
    text: bool = True,
    timeout: float = 3.0,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Execute iptables/netns commands with privilege escalation if needed."""
    if os.geteuid() == 0:
        return subprocess.run(cmd, capture_output=capture_output, text=text, timeout=timeout, check=check)

    cmd_list = [str(c) for c in cmd]
    if (
        len(cmd_list) >= 5
        and cmd_list[0] == "ip"
        and cmd_list[1] == "netns"
        and cmd_list[2] == "exec"
        and cmd_list[4] == "iptables"
    ):
        netns = cmd_list[3]
        ipt_args = cmd_list[5:]
        ok, data, msg = run_helper(
            "netns-iptables",
            ["--netns", netns] + ipt_args,
            timeout_s=timeout + 2.0,
        )
        retcode = data.get("returncode", 0 if ok else 1)
        stdout = data.get("stdout", "")
        stderr = data.get("stderr", msg if not ok else "")
        return subprocess.CompletedProcess(cmd, retcode, stdout, stderr)

    return subprocess.run(cmd, capture_output=capture_output, text=text, timeout=timeout, check=check)


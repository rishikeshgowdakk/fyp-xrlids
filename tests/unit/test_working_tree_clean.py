"""Unit regression tests for Git working-tree clean semantics in check_working_tree_clean.

Tests:
1. No staged, unstaged or untracked changes (CLEAN).
2. Untracked files only (DIRTY_UNTRACKED_ONLY -> clean=False).
3. Staged changes only (DIRTY_STAGED_ONLY -> clean=False).
4. Unstaged tracked changes only (DIRTY_UNSTAGED_ONLY -> clean=False).
5. Mixed changes (DIRTY_MIXED -> clean=False).
6. Git inspection failures (GIT_INSPECTION_FAILED -> clean=False).
7. Audit-directory scoped partitioning.
8. Live repository execution sanity check.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parents[2]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scripts.phase2.run_phase2b_readiness_audit import check_working_tree_clean


def test_clean_working_tree_semantics():
    """Verify clean=True only when 0 staged, 0 unstaged, and 0 untracked files exist."""
    mock_res = MagicMock()
    mock_res.stdout = ""

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is True
    assert res["state_category"] == "CLEAN"
    assert res["total_tracked_modified_count"] == 0
    assert res["staged_tracked_count"] == 0
    assert res["unstaged_tracked_count"] == 0
    assert res["total_untracked_count"] == 0
    assert "Verified Clean" in res["summary"]
    assert "0 uncommitted changes" in res["summary"]


def test_untracked_files_only_semantics():
    """Verify that presence of untracked files results in clean=False (regression fix)."""
    mock_res = MagicMock()
    mock_res.stdout = "?? new_script.py\n?? data/temp.csv\n"

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False, "Untracked files MUST prevent clean status"
    assert res["state_category"] == "DIRTY_UNTRACKED_ONLY"
    assert res["total_tracked_modified_count"] == 0
    assert res["total_untracked_count"] == 2
    assert "DIRTY / UNCOMMITTED" in res["summary"]
    assert "2 untracked files" in res["summary"]
    assert "0 tracked changes" in res["summary"]


def test_staged_changes_only_semantics():
    """Verify that staged changes in index result in clean=False and DIRTY_STAGED_ONLY."""
    mock_res = MagicMock()
    mock_res.stdout = "M  README.md\nA  src/module.py\nD  obsolete.txt\n"

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_STAGED_ONLY"
    assert res["staged_tracked_count"] == 3
    assert res["unstaged_tracked_count"] == 0
    assert res["total_untracked_count"] == 0
    assert "DIRTY / UNCOMMITTED" in res["summary"]
    assert "3 staged changes in index" in res["summary"]


def test_unstaged_tracked_changes_only_semantics():
    """Verify that unstaged modifications result in clean=False and DIRTY_UNSTAGED_ONLY."""
    mock_res = MagicMock()
    mock_res.stdout = " M README.md\n D src/module.py\n"

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_UNSTAGED_ONLY"
    assert res["staged_tracked_count"] == 0
    assert res["unstaged_tracked_count"] == 2
    assert res["total_untracked_count"] == 0
    assert "DIRTY / UNCOMMITTED" in res["summary"]
    assert "2 unstaged tracked changes" in res["summary"]


def test_mixed_changes_semantics():
    """Verify that concurrent staged, unstaged, and untracked changes result in DIRTY_MIXED."""
    mock_res = MagicMock()
    mock_res.stdout = "M  staged.py\n M unstaged.py\nMM both.py\n?? untracked.txt\n"

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_MIXED"
    assert res["total_tracked_modified_count"] == 3
    # staged.py (M ) and both.py (MM) are staged
    assert res["staged_tracked_count"] == 2
    # unstaged.py ( M) and both.py (MM) are unstaged
    assert res["unstaged_tracked_count"] == 2
    assert res["total_untracked_count"] == 1
    assert "DIRTY / UNCOMMITTED" in res["summary"]
    assert "3 tracked changes [2 staged, 2 unstaged]" in res["summary"]
    assert "1 untracked files" in res["summary"]


def test_git_inspection_failure_semantics():
    """Verify that git command failure results in clean=False and GIT_INSPECTION_FAILED."""
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, ["git", "status"])):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "GIT_INSPECTION_FAILED"
    assert res["total_tracked_modified_count"] == -1
    assert res["total_untracked_count"] == -1
    assert "UNKNOWN (git check failed:" in res["summary"]


def test_audit_directory_scoping_semantics(tmp_path: Path):
    """Verify that tracked and untracked changes within out_dir are accurately partitioned."""
    audit_dir = tmp_path / "results" / "audit_test_001"
    audit_dir.mkdir(parents=True)
    audit_file = audit_dir / "FINAL_REPORT.md"
    audit_file.write_text("report")

    external_file = tmp_path / "scripts" / "tool.py"
    external_file.parent.mkdir(parents=True)
    external_file.write_text("tool")

    mock_res = MagicMock()
    mock_res.stdout = (
        f" M {audit_file.relative_to(tmp_path)}\n"
        f" M {external_file.relative_to(tmp_path)}\n"
        f"?? {audit_dir.relative_to(tmp_path)}/temp.json\n"
        f"?? untracked_root.txt\n"
    )

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=tmp_path, out_dir=audit_dir)

    assert res["clean"] is False
    assert res["total_tracked_modified_count"] == 2
    assert res["external_tracked_modified_count"] == 1
    assert res["audit_dir_tracked_modified_count"] == 1
    assert res["total_untracked_count"] == 2
    assert res["external_untracked_count"] == 1
    assert res["audit_dir_untracked_count"] == 1


def test_live_repository_execution_sanity():
    """Sanity check executing check_working_tree_clean on the actual live repository."""
    res = check_working_tree_clean(repo_root=".")
    assert isinstance(res["clean"], bool)
    assert res["state_category"] in [
        "CLEAN",
        "DIRTY_UNTRACKED_ONLY",
        "DIRTY_STAGED_ONLY",
        "DIRTY_UNSTAGED_ONLY",
        "DIRTY_MIXED",
        "GIT_INSPECTION_FAILED",
    ]
    assert res["total_tracked_modified_count"] >= 0
    assert res["total_untracked_count"] >= 0
    assert isinstance(res["summary"], str)
    assert len(res["summary"]) > 0

"""Unit regression tests for Git working-tree clean semantics in check_working_tree_clean.

Comprehensive test suite covering 15 scenarios:
1. Clean repository (CLEAN -> clean=True).
2. Untracked-only changes (DIRTY_UNTRACKED_ONLY -> clean=False).
3. Staged-only changes (DIRTY_STAGED_ONLY -> clean=False).
4. Unstaged-only changes (DIRTY_UNSTAGED_ONLY -> clean=False).
5. Mixed changes across multiple categories (DIRTY_MIXED -> clean=False).
6. Single file with both staged and unstaged modifications (MM -> DIRTY_MIXED).
7. Git subprocess execution failure (CalledProcessError -> GIT_INSPECTION_FAILED).
8. Missing Git executable (FileNotFoundError -> GIT_INSPECTION_FAILED).
9. Non-Git directory (real directory without .git -> GIT_INSPECTION_FAILED).
10. Audit-directory scoping and sibling prefix avoidance (audit_dir vs audit_dir_sibling).
11. Rename and copy records (NUL-delimited -z and line-delimited rename/copy).
12. Unusual and quoted filenames (spaces, quotes, escaped chars).
13. File-type changes (T ,  T) and unmerged conflict statuses (UU, AA, DD).
14. Nested untracked paths in a real temporary Git repository.
15. Live repository execution sanity check without assuming developer tree state.
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


# 1. Clean repository
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


# 2. Untracked-only changes
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


# 3. Staged-only changes
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


# 4. Unstaged-only changes
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


# 5. Mixed changes
def test_mixed_changes_semantics():
    """Verify that concurrent staged, unstaged, and untracked changes result in DIRTY_MIXED."""
    mock_res = MagicMock()
    mock_res.stdout = "M  staged.py\n M unstaged.py\nMM both.py\n?? untracked.txt\n"

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_MIXED"
    assert res["total_tracked_modified_count"] == 3
    assert res["staged_tracked_count"] == 2
    assert res["unstaged_tracked_count"] == 2
    assert res["total_untracked_count"] == 1
    assert "DIRTY / UNCOMMITTED" in res["summary"]
    assert "3 tracked changes [2 staged, 2 unstaged]" in res["summary"]
    assert "1 untracked files" in res["summary"]


# 6. Single file with both staged and unstaged modifications
def test_both_staged_and_unstaged_single_file_semantics():
    """Verify that a single file with both index and worktree changes is tracked accurately."""
    mock_res = MagicMock()
    mock_res.stdout = "MM partially_staged.py\n"

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_MIXED"
    assert res["total_tracked_modified_count"] == 1
    assert res["staged_tracked_count"] == 1
    assert res["unstaged_tracked_count"] == 1
    assert res["total_untracked_count"] == 0
    assert "1 tracked changes [1 staged, 1 unstaged]" in res["summary"]


# 7. Git subprocess execution failure
def test_git_inspection_failure_semantics():
    """Verify that git command failure results in clean=False and GIT_INSPECTION_FAILED."""
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(128, ["git", "status"])):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "GIT_INSPECTION_FAILED"
    assert res["total_tracked_modified_count"] == -1
    assert res["staged_tracked_count"] == -1
    assert res["unstaged_tracked_count"] == -1
    assert res["total_untracked_count"] == -1
    assert "UNKNOWN (git check failed:" in res["summary"]


# 8. Missing Git executable
def test_missing_git_executable_semantics():
    """Verify that missing git executable safely fails closed with clean=False."""
    with patch("subprocess.run", side_effect=FileNotFoundError("No such file or directory: 'git'")):
        res = check_working_tree_clean(repo_root=".")

    assert res["clean"] is False
    assert res["state_category"] == "GIT_INSPECTION_FAILED"
    assert res["total_tracked_modified_count"] == -1
    assert res["total_untracked_count"] == -1
    assert "UNKNOWN (git check failed:" in res["summary"]


# 9. Non-Git directory (real execution)
def test_non_git_directory_semantics(tmp_path: Path):
    """Verify real git status invocation on a non-git directory returns GIT_INSPECTION_FAILED."""
    non_git_dir = tmp_path / "plain_dir"
    non_git_dir.mkdir(parents=True)

    res = check_working_tree_clean(repo_root=non_git_dir)

    assert res["clean"] is False
    assert res["state_category"] == "GIT_INSPECTION_FAILED"
    assert res["total_tracked_modified_count"] == -1
    assert res["total_untracked_count"] == -1
    assert "UNKNOWN (git check failed:" in res["summary"]


# 10. Audit-directory scoping and sibling prefix avoidance
def test_audit_directory_scoping_and_sibling_avoidance(tmp_path: Path):
    """Verify accurate audit scoping and that sibling directories (e.g. audit_dir_sibling) are not conflated."""
    audit_dir = tmp_path / "results" / "audit_001"
    audit_dir.mkdir(parents=True)
    audit_file = audit_dir / "FINAL_REPORT.md"
    audit_file.write_text("audit report")

    sibling_dir = tmp_path / "results" / "audit_001_sibling"
    sibling_dir.mkdir(parents=True)
    sibling_file = sibling_dir / "sibling_report.md"
    sibling_file.write_text("sibling report")

    external_file = tmp_path / "scripts" / "tool.py"
    external_file.parent.mkdir(parents=True)
    external_file.write_text("tool")

    mock_res = MagicMock()
    mock_res.stdout = (
        f" M {audit_file.relative_to(tmp_path)}\n"
        f" M {sibling_file.relative_to(tmp_path)}\n"
        f" M {external_file.relative_to(tmp_path)}\n"
        f"?? {audit_dir.relative_to(tmp_path)}/untracked_audit.json\n"
        f"?? {sibling_dir.relative_to(tmp_path)}/untracked_sibling.json\n"
    )

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=tmp_path, out_dir=audit_dir)

    assert res["clean"] is False
    assert res["total_tracked_modified_count"] == 3
    # Exactly 1 in audit_dir, 2 outside (including sibling)
    assert res["audit_dir_tracked_modified_count"] == 1
    assert res["external_tracked_modified_count"] == 2
    # Exactly 1 untracked in audit_dir, 1 outside (in sibling)
    assert res["total_untracked_count"] == 2
    assert res["audit_dir_untracked_count"] == 1
    assert res["external_untracked_count"] == 1


# 11. Rename and copy records
def test_rename_and_copy_semantics(tmp_path: Path):
    """Verify that renames (R) and copies (C) in both NUL (-z) and line formats are parsed correctly."""
    audit_dir = tmp_path / "audit_out"
    audit_dir.mkdir(parents=True)

    # NUL-delimited record:
    # 1. External rename: old_name.py -> new_name.py
    # 2. Rename into audit_dir: script.py -> audit_out/script.py
    # 3. Copy: orig.py -> audit_out/copied.py
    z_output = (
        "R  new_name.py\0old_name.py\0"
        "R  audit_out/script.py\0script.py\0"
        "C  audit_out/copied.py\0orig.py\0"
    )

    mock_res = MagicMock()
    mock_res.stdout = z_output

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=tmp_path, out_dir=audit_dir)

    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_STAGED_ONLY"
    assert res["total_tracked_modified_count"] == 3
    assert res["staged_tracked_count"] == 3
    assert res["unstaged_tracked_count"] == 0
    # 2 renames/copies involve audit_dir, 1 is external
    assert res["audit_dir_tracked_modified_count"] == 2
    assert res["external_tracked_modified_count"] == 1


# 12. Unusual and quoted filenames
def test_unusual_quoted_filenames_and_spaces(tmp_path: Path):
    """Verify paths containing spaces and enclosing quotes resolve accurately without quote artifacts."""
    audit_dir = tmp_path / "audit_out"
    audit_dir.mkdir(parents=True)

    # Line-mode output where git enclosed paths in quotes due to spaces
    mock_res = MagicMock()
    mock_res.stdout = (
        ' M "audit_out/report with spaces.md"\n'
        ' M "external dir/file with spaces.py"\n'
        '?? "audit_out/untracked space file.json"\n'
    )

    with patch("subprocess.run", return_value=mock_res):
        res = check_working_tree_clean(repo_root=tmp_path, out_dir=audit_dir)

    assert res["clean"] is False
    assert res["total_tracked_modified_count"] == 2
    assert res["audit_dir_tracked_modified_count"] == 1
    assert res["external_tracked_modified_count"] == 1
    assert res["total_untracked_count"] == 1
    assert res["audit_dir_untracked_count"] == 1
    # Check that paths do not retain raw enclosing quotes in parsed lists
    assert not any(f.startswith('"') for f in res["total_untracked_files"])


# 13. File-type changes and conflict statuses
def test_typechange_and_conflict_statuses():
    """Verify file typechanges (T) and conflict statuses (UU, AA, DD) are accurately categorized."""
    # Staged typechange only
    mock_t_staged = MagicMock()
    mock_t_staged.stdout = "T  symlink_target.txt\n"
    with patch("subprocess.run", return_value=mock_t_staged):
        res = check_working_tree_clean(repo_root=".")
    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_STAGED_ONLY"
    assert res["staged_tracked_count"] == 1
    assert res["unstaged_tracked_count"] == 0

    # Unstaged typechange only
    mock_t_unstaged = MagicMock()
    mock_t_unstaged.stdout = " T symlink_target.txt\n"
    with patch("subprocess.run", return_value=mock_t_unstaged):
        res = check_working_tree_clean(repo_root=".")
    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_UNSTAGED_ONLY"
    assert res["staged_tracked_count"] == 0
    assert res["unstaged_tracked_count"] == 1

    # Conflict statuses: UU (both modified), AA (both added), DD (both deleted)
    mock_conflicts = MagicMock()
    mock_conflicts.stdout = "UU conflict_mod.py\nAA conflict_add.py\nDD conflict_del.py\n"
    with patch("subprocess.run", return_value=mock_conflicts):
        res = check_working_tree_clean(repo_root=".")
    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_MIXED"
    assert res["total_tracked_modified_count"] == 3
    assert res["staged_tracked_count"] == 3
    assert res["unstaged_tracked_count"] == 3


# 14. Nested untracked paths in a real temporary Git repository
def test_nested_untracked_paths_real_git(tmp_path: Path):
    """Verify live git status execution in a temporary repository with nested untracked paths."""
    git_dir = tmp_path / "repo"
    git_dir.mkdir(parents=True)

    subprocess.run(["git", "init"], cwd=git_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=git_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=git_dir, check=True)

    # Initial commit
    (git_dir / "tracked.txt").write_text("base")
    subprocess.run(["git", "add", "tracked.txt"], cwd=git_dir, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=git_dir, check=True)

    # Create nested untracked file
    nested_dir = git_dir / "nested" / "deep"
    nested_dir.mkdir(parents=True)
    (nested_dir / "untracked.txt").write_text("new content")

    res = check_working_tree_clean(repo_root=git_dir)

    assert res["clean"] is False
    assert res["state_category"] == "DIRTY_UNTRACKED_ONLY"
    assert res["total_tracked_modified_count"] == 0
    assert res["total_untracked_count"] >= 1
    assert any("untracked.txt" in f for f in res["total_untracked_files"])


# 15. Live repository execution sanity check
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
    assert res["total_tracked_modified_count"] >= 0 or res["total_tracked_modified_count"] == -1
    assert res["total_untracked_count"] >= 0 or res["total_untracked_count"] == -1
    assert isinstance(res["summary"], str)
    assert len(res["summary"]) > 0

"""Multi-dimensional evaluation metrics for Phase 2 autonomous response (Task 8 & 11).

Follows SPEC-P2-AUTONOMOUS-RESPONSE-001 Section 10:
    1. Cumulative Operational Cost (C_total)
    2. Mean Cost per Flow (C_mean)
    3. Mitigation Delay (Δ_contain)
    4. False Quarantine Rate (FQR)
    5. Action Chattering Index (ACI)
    6. Business Availability Score (BAS)
    7. Relative Cost Reduction (ΔC_rel)
    8. Paired Bootstrap Hypothesis Testing on Operational Costs
"""

from __future__ import annotations

from typing import Any, Sequence
import numpy as np

from xrlids.response.types import Action


def compute_cumulative_cost(costs: Sequence[float]) -> float:
    """Compute total cumulative operational loss."""
    return float(np.sum(costs)) if len(costs) > 0 else 0.0


def compute_mean_cost(costs: Sequence[float]) -> float:
    """Compute mean operational loss per flow."""
    return float(np.mean(costs)) if len(costs) > 0 else 0.0


def compute_false_quarantine_rate(
    actions: Sequence[Action],
    y_true: Sequence[int],
) -> float:
    """Compute fraction of benign flows erroneously subjected to ISOLATE.

    FQR = sum(a_t == ISOLATE and y_t == 0) / sum(y_t == 0)
    """
    acts = np.asarray([int(a) for a in actions], dtype=int)
    yt = np.asarray(y_true, dtype=int)
    benign_mask = (yt == 0)
    n_benign = int(np.sum(benign_mask))
    if n_benign == 0:
        return 0.0
    isolated_benign = int(np.sum((acts == int(Action.ISOLATE)) & benign_mask))
    return float(isolated_benign / n_benign)


def compute_action_chattering_index(actions: Sequence[Action]) -> float:
    """Compute fraction of consecutive steps exhibiting violent action jumps (|a_t - a_(t-1)| >= 2).

    ACI = (1 / (T - 1)) * sum(I(|a_t - a_(t-1)| >= 2))
    """
    if len(actions) < 2:
        return 0.0
    acts = np.asarray([int(a) for a in actions], dtype=int)
    deltas = np.abs(acts[1:] - acts[:-1])
    chattering_jumps = np.sum(deltas >= 2)
    return float(chattering_jumps / len(deltas))


def compute_business_availability_score(
    actions: Sequence[Action],
    y_true: Sequence[int],
) -> float:
    """Compute percentage of benign flows that pass completely uninterrupted (ALLOW).

    BAS = (sum(a_t == ALLOW and y_t == 0) / sum(y_t == 0)) * 100%
    """
    acts = np.asarray([int(a) for a in actions], dtype=int)
    yt = np.asarray(y_true, dtype=int)
    benign_mask = (yt == 0)
    n_benign = int(np.sum(benign_mask))
    if n_benign == 0:
        return 100.0
    uninterrupted = int(np.sum((acts == int(Action.ALLOW)) & benign_mask))
    return float((uninterrupted / n_benign) * 100.0)


def compute_mitigation_delay(
    actions: Sequence[Action],
    y_true: Sequence[int],
    *,
    unmitigated_penalty_steps: int = 50,
) -> float:
    """Compute mean steps from the start of an attack sequence to the first mitigating action.

    Mitigating actions: RATE_LIMIT (2) or ISOLATE (3).
    If an attack sequence ends without mitigation, it receives unmitigated_penalty_steps.
    """
    acts = np.asarray([int(a) for a in actions], dtype=int)
    yt = np.asarray(y_true, dtype=int)

    delays: list[int] = []
    in_attack = False
    attack_start_idx = 0
    mitigated = False

    for t in range(len(yt)):
        if yt[t] == 1:
            if not in_attack:
                in_attack = True
                attack_start_idx = t
                mitigated = False

            if not mitigated and acts[t] in (int(Action.RATE_LIMIT), int(Action.ISOLATE)):
                delays.append(t - attack_start_idx)
                mitigated = True
        else:
            if in_attack:
                if not mitigated:
                    delays.append(unmitigated_penalty_steps)
                in_attack = False
                mitigated = False

    if in_attack and not mitigated:
        delays.append(unmitigated_penalty_steps)

    if not delays:
        return 0.0
    return float(np.mean(delays))


def compute_relative_cost_reduction(
    cost_baseline: float,
    cost_policy: float,
) -> float:
    """Compute percentage cost reduction of a policy relative to a baseline comparator.

    ΔC_rel = ((C_baseline - C_policy) / C_baseline) * 100%
    Positive value indicates cost savings over baseline.
    """
    if cost_baseline == 0.0:
        return 0.0
    return float(((cost_baseline - cost_policy) / cost_baseline) * 100.0)


def evaluate_response_run(
    actions: Sequence[Action],
    y_true: Sequence[int],
    costs: Sequence[float],
    *,
    cost_baseline: float | None = None,
) -> dict[str, Any]:
    """Compute complete multi-dimensional metric report for a simulation run."""
    c_tot = compute_cumulative_cost(costs)
    c_mean = compute_mean_cost(costs)
    fqr = compute_false_quarantine_rate(actions, y_true)
    aci = compute_action_chattering_index(actions)
    bas = compute_business_availability_score(actions, y_true)
    delay = compute_mitigation_delay(actions, y_true)

    # Action distribution
    acts = [int(a) for a in actions]
    counts = {
        Action.ALLOW.name: acts.count(int(Action.ALLOW)),
        Action.ALERT.name: acts.count(int(Action.ALERT)),
        Action.RATE_LIMIT.name: acts.count(int(Action.RATE_LIMIT)),
        Action.ISOLATE.name: acts.count(int(Action.ISOLATE)),
    }

    metrics: dict[str, Any] = {
        "total_flows": len(actions),
        "cumulative_cost": c_tot,
        "mean_cost_per_flow": c_mean,
        "false_quarantine_rate": fqr,
        "action_chattering_index": aci,
        "business_availability_score_pct": bas,
        "mitigation_delay_steps": delay,
        "action_counts": counts,
    }

    if cost_baseline is not None:
        metrics["relative_cost_reduction_pct"] = compute_relative_cost_reduction(cost_baseline, c_tot)

    return metrics


def paired_bootstrap_cost_comparison(
    costs_baseline: Sequence[float],
    costs_candidate: Sequence[float],
    *,
    baseline_name: str = "baseline",
    candidate_name: str = "candidate",
    n_bootstraps: int = 1000,
    ci_level: float = 0.95,
    seed: int = 42,
) -> dict[str, Any]:
    """Perform paired bootstrap hypothesis test comparing per-flow costs between two policies.

    H0: Mean cost difference E[cost_candidate - cost_baseline] == 0.
    A negative delta indicates the candidate achieves lower operational cost than baseline.
    """
    c_base = np.asarray(costs_baseline, dtype=float)
    c_cand = np.asarray(costs_candidate, dtype=float)

    if len(c_base) != len(c_cand):
        raise ValueError(f"Cost arrays must match in length: {len(c_base)} vs {len(c_cand)}")

    n = len(c_base)
    if n == 0:
        return {"status": "EMPTY_ARRAYS"}

    # Paired differences per flow
    paired_diffs = c_cand - c_base
    point_diff = float(np.mean(paired_diffs))
    point_cost_base = float(np.sum(c_base))
    point_cost_cand = float(np.sum(c_cand))

    rng = np.random.default_rng(seed)
    boot_diff_means = np.empty(n_bootstraps, dtype=float)

    for i in range(n_bootstraps):
        boot_idx = rng.integers(0, n, size=n)
        boot_diff_means[i] = float(np.mean(paired_diffs[boot_idx]))

    alpha = 1.0 - ci_level
    ci_lower = float(np.percentile(boot_diff_means, (alpha / 2.0) * 100))
    ci_upper = float(np.percentile(boot_diff_means, (1.0 - alpha / 2.0) * 100))

    # Two-sided p-value against zero difference
    p_le_zero = np.mean(boot_diff_means <= 0.0)
    p_ge_zero = np.mean(boot_diff_means >= 0.0)
    p_value = float(min(1.0, 2.0 * min(p_le_zero, p_ge_zero)))

    is_significant = bool((ci_lower > 0.0 and ci_upper > 0.0) or (ci_lower < 0.0 and ci_upper < 0.0))
    better_policy = "equal"
    if is_significant:
        better_policy = candidate_name if point_diff < 0.0 else baseline_name

    rel_reduction = compute_relative_cost_reduction(point_cost_base, point_cost_cand)

    return {
        "baseline_name": baseline_name,
        "candidate_name": candidate_name,
        "baseline_total_cost": point_cost_base,
        "candidate_total_cost": point_cost_cand,
        "mean_paired_difference": point_diff,
        "ci_lower": ci_lower,
        "ci_upper": ci_upper,
        "ci_level": ci_level,
        "p_value": p_value,
        "is_significant": is_significant,
        "superior_policy": better_policy,
        "relative_cost_reduction_pct": rel_reduction,
        "n_bootstraps": n_bootstraps,
    }

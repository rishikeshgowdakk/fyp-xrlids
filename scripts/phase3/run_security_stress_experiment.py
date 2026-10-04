#!/usr/bin/env python3
"""Phase 3K Experiment Execution Script: EXP-P3K-STRESS-SECURITY-001.

Formal Pre-Production Security & Stress Audit for XRL-IDARS v1.
Executes:
1. Pre-test host network baseline capture.
2. 4-tier socket ingestion stress test (Low, Nominal, High, Overload).
3. 24+ adversarial security attack surface tests (Namespaces, Interfaces, IPs, Authorization, Transactions, Safety Gate).
4. 8 cryptographic evidence tamper resistance tests.
5. 10,000-flow sustained soak workload across 10 segments with resource monitoring.
6. 12 concurrent failure injection scenarios during active soak.
7. 100 mixed-outcome transaction rollback stress tests.
8. Deterministic resource cleanup verification.
9. Post-test host network baseline capture and cryptographic verification (0 host mutations).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add project root to sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from xrlids.enforcement import SecurityStressHarness, StressWorkloadConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("exp_p3k_runner")


def main() -> int:
    logger.info("================================================================================")
    logger.info("STARTING PHASE 3K: EXP-P3K-STRESS-SECURITY-001")
    logger.info("Formal Pre-Production Security & Stress Audit")
    logger.info("================================================================================")

    config = StressWorkloadConfig(
        total_flows=10000,
        batch_size=1000,
        concurrency_level=8,
        random_seed=42,
        experiment_id="EXP-P3K-STRESS-SECURITY-001",
    )

    output_dir = repo_root / "results" / "phase3" / "EXP-P3K-STRESS-SECURITY-001"
    harness = SecurityStressHarness(config=config)

    try:
        summary = harness.execute_audit(output_dir=output_dir)
        logger.info("================================================================================")
        logger.info("PHASE 3K AUDIT COMPLETE: %s", summary["status"])
        logger.info("Total Flows Processed: %d", summary["total_flows_processed"])
        logger.info("Total Packets Processed: %d", summary["total_packets_processed"])
        logger.info("Zero Host Mutation Verified: %s", summary["zero_host_mutation"])
        logger.info("Attack Scenarios Passed: %d/%d", summary["attack_scenarios_passed"], summary["attack_scenarios_total"])
        logger.info("Provenance Tests Passed: %d/%d", summary["provenance_tests_passed"], summary["provenance_tests_total"])
        logger.info("Soak Failure Injections Passed: %d/%d", summary["soak_failure_injections_passed"], summary["soak_failure_injections_total"])
        logger.info("Rollback Success Rate: %.1f%%", summary["rollback_success_rate"] * 100.0)
        logger.info("Peak RSS: %.2f MiB (Growth: %.2f MiB)", summary["peak_rss_mib"], summary["rss_growth_mib"])
        logger.info("Artifacts saved to: %s", output_dir)
        logger.info("================================================================================")

        if summary["status"] == "PASS" and summary["zero_host_mutation"]:
            return 0
        return 1

    except Exception as err:
        logger.exception("FATAL ERROR in Phase 3K Security & Stress Audit: %s", err)
        return 2


if __name__ == "__main__":
    sys.exit(main())

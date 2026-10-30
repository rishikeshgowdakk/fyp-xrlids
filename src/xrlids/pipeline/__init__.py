"""Active End-to-End Inference Pipeline and Evaluation Orchestration for XRL-IDARS.

Unifies:
- ActiveInferencePipeline (real-time stream processing across all 4 tiers)
- run_single_dataset (Phase 1 offline dataset orchestration and benchmarking)
"""

from xrlids.pipeline.active_pipeline import (
    ActiveInferencePipeline,
    PipelineResult as ActivePipelineResult,
)
from xrlids.pipeline.single_dataset import (
    PipelineResult,
    run_single_dataset,
)

__all__ = [
    "ActiveInferencePipeline",
    "ActivePipelineResult",
    "PipelineResult",
    "run_single_dataset",
]

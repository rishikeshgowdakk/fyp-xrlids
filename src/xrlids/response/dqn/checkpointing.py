"""Checkpoint Management and Objective Selection (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements strict validation-based checkpoint evaluation and persistence.
Rules:
- Checkpoints are evaluated and selected strictly on validation data (D_pol_val).
- No checkpoint is ever selected using test data (D_pol_test).
- Tracks validation cumulative cost, mean cost/flow, FQR, ACI, BAS, and reward.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import torch


class CheckpointManager:
    """Manages serialization, restoration, and validation-based selection of DQN models."""

    def __init__(
        self,
        checkpoint_dir: str | Path,
        selection_metric: str = "mean_cost_per_flow",
        maximize: bool = False,
    ) -> None:
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.selection_metric = selection_metric
        self.maximize = maximize

        self.history: list[dict[str, Any]] = []
        self.best_checkpoint_path: Path | None = None
        self.best_metric_value: float = -float("inf") if maximize else float("inf")
        self.best_step: int = -1

    def save_checkpoint(
        self,
        filepath: str | Path,
        online_net: torch.nn.Module,
        target_net: torch.nn.Module,
        optimizer: torch.optim.Optimizer,
        step: int,
        metrics: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
    ) -> Path:
        """Save a complete agent state checkpoint."""
        save_path = Path(filepath)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "step": step,
            "online_net_state_dict": online_net.state_dict(),
            "target_net_state_dict": target_net.state_dict(),
            "optimizer_state_dict": optimizer.state_dict(),
            "metrics": metrics or {},
            "config": config or {},
        }
        torch.save(payload, save_path)
        return save_path

    def load_checkpoint(
        self,
        filepath: str | Path,
        online_net: torch.nn.Module,
        target_net: torch.nn.Module | None = None,
        optimizer: torch.optim.Optimizer | None = None,
    ) -> dict[str, Any]:
        """Restore model weights and training metadata from a checkpoint."""
        load_path = Path(filepath)
        if not load_path.exists():
            raise FileNotFoundError(f"Checkpoint file not found: {load_path}")

        payload = torch.load(load_path, map_location="cpu", weights_only=False)
        online_net.load_state_dict(payload["online_net_state_dict"])
        if target_net is not None and "target_net_state_dict" in payload:
            target_net.load_state_dict(payload["target_net_state_dict"])
        if optimizer is not None and "optimizer_state_dict" in payload:
            optimizer.load_state_dict(payload["optimizer_state_dict"])
        return payload

    def register_evaluation(
        self,
        step: int,
        metrics: dict[str, Any],
        online_net: torch.nn.Module,
        target_net: torch.nn.Module,
        optimizer: torch.optim.Optimizer,
        config: dict[str, Any] | None = None,
    ) -> tuple[bool, Path]:
        """Record validation evaluation and save checkpoint if it achieves a new best objective."""
        checkpoint_path = self.checkpoint_dir / f"checkpoint_step_{step:06d}.pt"
        self.save_checkpoint(
            checkpoint_path,
            online_net=online_net,
            target_net=target_net,
            optimizer=optimizer,
            step=step,
            metrics=metrics,
            config=config,
        )

        metric_val = float(metrics.get(self.selection_metric, 0.0))
        entry = {
            "step": step,
            "checkpoint_path": str(checkpoint_path),
            "metric_name": self.selection_metric,
            "metric_value": metric_val,
            "all_metrics": metrics,
        }
        self.history.append(entry)

        is_better = (metric_val > self.best_metric_value) if self.maximize else (metric_val < self.best_metric_value)
        if is_better:
            self.best_metric_value = metric_val
            self.best_step = step
            self.best_checkpoint_path = checkpoint_path

            # Also persist dedicated best model file
            best_link = self.checkpoint_dir / "best_model.pt"
            torch.save(
                {
                    "step": step,
                    "online_net_state_dict": online_net.state_dict(),
                    "metrics": metrics,
                    "selection_reason": f"Optimal {self.selection_metric}={metric_val:.6f} at step {step}",
                },
                best_link,
            )

        return is_better, checkpoint_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "selection_metric": self.selection_metric,
            "maximize": self.maximize,
            "best_step": self.best_step,
            "best_metric_value": self.best_metric_value,
            "best_checkpoint_path": str(self.best_checkpoint_path) if self.best_checkpoint_path else None,
            "evaluated_checkpoints_count": len(self.history),
            "history": self.history,
        }

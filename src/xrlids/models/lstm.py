"""Supervised LSTM temporal classifier (build spec sections 15, 25; scientific RULE 10).

The LSTM is a *supervised* temporal classifier over sequences of T consecutive flow
vectors. It is not generative, self-supervised or an anomaly generator.

Sequence safety
---------------
Sequences are constructed **independently within each split**, and each sequence records
the split it came from. A sequence therefore cannot span train/validation/test by
construction, and :func:`assert_no_boundary_crossing` re-checks that property.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd

from xrlids.utils.logging_utils import get_logger
from xrlids.utils.seeding import set_global_seeds

logger = get_logger(__name__)

DEFAULT_LSTM_PARAMS: dict[str, Any] = {
    "hidden_size": 64,
    "num_layers": 2,
    "dropout": 0.2,
    "learning_rate": 1e-3,
    "batch_size": 256,
    "epochs": 30,
    "patience": 5,
    "optimizer": "adam",
    "loss": "bce",
}


class SequenceError(ValueError):
    """Raised when sequence construction would violate split boundaries."""


@dataclass
class SequenceSet:
    """Sequences and labels for one split, with provenance for auditing."""

    X: np.ndarray            # (n, T, F)
    y: np.ndarray            # (n,)
    split: str
    origins: np.ndarray      # starting row index within the split
    label_rule: str
    stride: int

    def __len__(self) -> int:
        return int(self.X.shape[0])


def build_sequences(
    features: pd.DataFrame,
    labels: pd.Series,
    *,
    split: str,
    seq_len: int = 5,
    stride: int = 1,
    label_rule: str = "last",
) -> SequenceSet:
    """Build sequences inside a single split.

    ``label_rule``:
        ``last``   - label of the final element (default, matches "predict the current flow")
        ``any``    - 1 if any element in the window is an attack
        ``majority`` - majority vote over the window

    Because this function only ever sees one split's rows, no window can cross a split
    boundary. Callers must pass one split at a time.
    """
    if seq_len < 1:
        raise SequenceError("seq_len must be >= 1")
    if len(features) != len(labels):
        raise SequenceError("features and labels have different lengths")
    if len(features) < seq_len:
        return SequenceSet(
            X=np.empty((0, seq_len, features.shape[1])),
            y=np.empty((0,)),
            split=split,
            origins=np.empty((0,), dtype=int),
            label_rule=label_rule,
            stride=stride,
        )

    values = features.to_numpy(dtype=float)
    targets = labels.to_numpy(dtype=int)

    X, y, origins = [], [], []
    for start in range(0, len(features) - seq_len + 1, stride):
        window = values[start : start + seq_len]
        if label_rule == "last":
            label = targets[start + seq_len - 1]
        elif label_rule == "any":
            label = int(targets[start : start + seq_len].max())
        elif label_rule == "majority":
            label = int(round(targets[start : start + seq_len].mean()))
        else:
            raise SequenceError(f"unknown label_rule '{label_rule}'")
        X.append(window)
        y.append(label)
        origins.append(start)

    return SequenceSet(
        X=np.asarray(X, dtype=float),
        y=np.asarray(y, dtype=int),
        split=split,
        origins=np.asarray(origins, dtype=int),
        label_rule=label_rule,
        stride=stride,
    )


def assert_no_boundary_crossing(sets: Sequence[SequenceSet], split_sizes: dict[str, int]) -> None:
    """Verify no sequence extends past the end of its own split."""
    for s in sets:
        if len(s) == 0:
            continue
        size = split_sizes[s.split]
        end = s.origins + s.X.shape[1]
        if int(end.max()) > size:
            raise SequenceError(
                f"sequence from split '{s.split}' extends beyond the split "
                f"(max end {int(end.max())} > size {size})"
            )


def _torch():
    import torch  # imported lazily so non-LSTM work does not pay the import cost

    return torch


@dataclass
class LSTMDetector:
    """Configurable supervised LSTM with early stopping and checkpointing."""

    params: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_LSTM_PARAMS))
    feature_names: list[str] = field(default_factory=list)
    seq_len: int = 5
    label_rule: str = "last"
    seed: int = 42
    model: Any = field(default=None, repr=False)
    history: list[dict[str, float]] = field(default_factory=list)
    best_val_loss: float = float("inf")
    best_epoch: int = -1

    def __post_init__(self) -> None:
        merged = dict(DEFAULT_LSTM_PARAMS)
        merged.update(self.params or {})
        self.params = merged

    def _build(self, n_features: int) -> Any:
        torch = _torch()

        class _Net(torch.nn.Module):
            def __init__(self, n_features: int, hidden: int, layers: int, dropout: float):
                super().__init__()
                self.lstm = torch.nn.LSTM(
                    input_size=n_features,
                    hidden_size=hidden,
                    num_layers=layers,
                    batch_first=True,
                    dropout=dropout if layers > 1 else 0.0,
                )
                self.head = torch.nn.Linear(hidden, 1)

            def forward(self, x):  # (B, T, F) -> (B,)
                out, _ = self.lstm(x)
                return self.head(out[:, -1, :]).squeeze(-1)

        return _Net(n_features, self.params["hidden_size"], self.params["num_layers"], self.params["dropout"])

    def fit(self, train: SequenceSet, validation: SequenceSet) -> "LSTMDetector":
        torch = _torch()
        set_global_seeds(self.seed)
        if len(train) == 0:
            raise SequenceError("no training sequences were built")

        self.feature_names = self.feature_names or [f"f{i}" for i in range(train.X.shape[2])]
        net = self._build(train.X.shape[2])
        self.model = net

        device = torch.device("cpu")
        net.to(device)
        optim = torch.optim.Adam(net.parameters(), lr=float(self.params["learning_rate"]))
        lossf = torch.nn.BCEWithLogitsLoss()

        Xtr = torch.tensor(train.X, dtype=torch.float32)
        ytr = torch.tensor(train.y, dtype=torch.float32)
        Xva = torch.tensor(validation.X, dtype=torch.float32) if len(validation) else None
        yva = torch.tensor(validation.y, dtype=torch.float32) if len(validation) else None

        batch = int(self.params["batch_size"])
        patience = int(self.params["patience"])
        best_state = {k: v.clone() for k, v in net.state_dict().items()}
        epochs_without_improvement = 0

        for epoch in range(int(self.params["epochs"])):
            net.train()
            perm = torch.randperm(len(Xtr))
            epoch_loss = 0.0
            for i in range(0, len(perm), batch):
                idx = perm[i : i + batch]
                optim.zero_grad()
                logits = net(Xtr[idx])
                loss = lossf(logits, ytr[idx])
                loss.backward()
                torch.nn.utils.clip_grad_norm_(net.parameters(), 5.0)
                optim.step()
                epoch_loss += float(loss.item()) * len(idx)
            epoch_loss /= max(1, len(Xtr))

            val_loss = float("nan")
            if Xva is not None and yva is not None:
                net.eval()
                with torch.no_grad():
                    val_loss = float(lossf(net(Xva), yva).item())
                if val_loss < self.best_val_loss - 1e-6:
                    self.best_val_loss = val_loss
                    self.best_epoch = epoch
                    best_state = {k: v.clone() for k, v in net.state_dict().items()}
                    epochs_without_improvement = 0
                else:
                    epochs_without_improvement += 1

            self.history.append({"epoch": epoch, "train_loss": epoch_loss, "val_loss": val_loss})
            if epochs_without_improvement >= patience:
                logger.info("LSTM early stopping at epoch %d (best epoch %d)", epoch, self.best_epoch)
                break

        net.load_state_dict(best_state)
        net.eval()
        logger.info("LSTM trained: seq_len=%d features=%d best_val_loss=%.6f", self.seq_len, train.X.shape[2], self.best_val_loss)
        return self

    def predict_proba(self, seqs: SequenceSet) -> np.ndarray:
        """Continuous scores = sigmoid(logit), i.e. P(class = 1)."""
        torch = _torch()
        if self.model is None:
            raise SequenceError("LSTM is not fitted")
        if len(seqs) == 0:
            return np.empty((0,))
        self.model.eval()
        with torch.no_grad():
            logits = self.model(torch.tensor(seqs.X, dtype=torch.float32))
            return torch.sigmoid(logits).numpy()

    def config(self) -> dict[str, Any]:
        return {
            "model_type": "SupervisedLSTM",
            "params": dict(self.params),
            "seq_len": self.seq_len,
            "label_rule": self.label_rule,
            "seed": self.seed,
            "best_epoch": self.best_epoch,
            "best_val_loss": self.best_val_loss,
            "history": self.history,
        }

    def save(self, directory: str | Path) -> Path:
        torch = _torch()
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "lstm.pt"
        torch.save(
            {
                "state_dict": self.model.state_dict() if self.model else None,
                "params": self.params,
                "feature_names": self.feature_names,
                "seq_len": self.seq_len,
                "label_rule": self.label_rule,
                "seed": self.seed,
            },
            path,
        )
        return path

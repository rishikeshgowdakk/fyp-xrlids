"""Supervised LSTM temporal classifier (build spec sections 15, 25; scientific RULE 10; Task 13).

The LSTM is a *supervised* temporal classifier over sequences of T consecutive flow
vectors. It is not generative, self-supervised or an anomaly generator.

Memory safety & Sequence safety
-------------------------------
Features are kept in 2D array representation (N, F); (N, T, F) is NEVER materialized
in RAM. Mini-batch generation extracts (batch_size, seq_len, F) on the fly during training
and inference.
Sequences are constructed **independently within each split**, and each sequence records
the split it came from. A sequence therefore cannot span train/validation/test by
construction, and :func:`assert_no_boundary_crossing` re-checks that property.
Session/group boundaries are respected when grouping is configured.
"""

from __future__ import annotations

import os
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
    """Raised when sequence construction would violate split or group boundaries."""


class SequenceArray:
    """Memory-bounded 3D sequence view over a 2D feature matrix and origins.

    Never materializes the full (N, T, F) array in RAM unless explicitly converted via np.asarray().
    """

    def __init__(self, features: np.ndarray, origins: np.ndarray, seq_len: int) -> None:
        self.features = features
        self.origins = origins
        self.seq_len = int(seq_len)
        n_features = features.shape[1] if features.ndim > 1 else 0
        self.shape = (len(origins), self.seq_len, n_features)

    def __len__(self) -> int:
        return self.shape[0]

    def __getitem__(self, idx: Any) -> Any:
        if isinstance(idx, (int, np.integer)):
            idx_int = int(idx)
            if idx_int < 0:
                idx_int += len(self)
            if idx_int < 0 or idx_int >= len(self):
                raise IndexError(f"index {idx} out of range for SequenceArray of length {len(self)}")
            start = int(self.origins[idx_int])
            return self.features[start : start + self.seq_len]
        elif isinstance(idx, slice):
            sub_origins = self.origins[idx]
            return SequenceArray(self.features, sub_origins, self.seq_len)
        elif isinstance(idx, (list, np.ndarray)):
            sub_origins = self.origins[idx]
            return SequenceArray(self.features, sub_origins, self.seq_len)
        elif isinstance(idx, tuple) and len(idx) == 3:
            return np.asarray(self)[idx]
        raise NotImplementedError(f"indexing with {type(idx)} not implemented for SequenceArray")

    def __array__(self) -> np.ndarray:
        if len(self.origins) == 0:
            return np.empty(self.shape, dtype=self.features.dtype)
        return np.stack([self.features[s : s + self.seq_len] for s in self.origins])


class SequenceSet:
    """Sequences and labels for one split, stored memory-efficiently with 2D features + origins."""

    def __init__(
        self,
        *,
        features_2d: np.ndarray | None = None,
        y: np.ndarray,
        split: str,
        origins: np.ndarray,
        seq_len: int = 5,
        label_rule: str = "last",
        stride: int = 1,
        X: np.ndarray | SequenceArray | None = None,
    ) -> None:
        self.y = np.asarray(y, dtype=int)
        self.split = split
        self.origins = np.asarray(origins, dtype=int)
        self.seq_len = int(seq_len)
        self.label_rule = label_rule
        self.stride = int(stride)

        if X is not None:
            self._X = X
            if features_2d is None and hasattr(X, "ndim") and X.ndim == 3 and len(X) > 0:
                self.seq_len = X.shape[1]
                self.features_2d = X.reshape(-1, X.shape[2])
            elif features_2d is not None:
                self.features_2d = np.asarray(features_2d, dtype=np.float32)
            else:
                self.features_2d = np.empty((0, 0), dtype=np.float32)
        else:
            self.features_2d = np.asarray(features_2d, dtype=np.float32) if features_2d is not None else np.empty((0, 0), dtype=np.float32)
            self._X = SequenceArray(self.features_2d, self.origins, self.seq_len)

    @property
    def X(self) -> Any:
        return self._X

    @property
    def n_features(self) -> int:
        if hasattr(self, "features_2d") and self.features_2d.ndim > 1:
            return self.features_2d.shape[1]
        if hasattr(self._X, "shape") and len(self._X.shape) > 2:
            return self._X.shape[2]
        return 0

    def __len__(self) -> int:
        return len(self.origins)


def build_sequences(
    features: pd.DataFrame | np.ndarray,
    labels: pd.Series | np.ndarray,
    *,
    split: str,
    seq_len: int = 5,
    stride: int = 1,
    label_rule: str = "last",
    groups: pd.Series | np.ndarray | None = None,
    session_column: pd.Series | np.ndarray | None = None,
) -> SequenceSet:
    """Build sequences inside a single split without materializing (N, T, F) in memory.

    ``label_rule``:
        ``last``     - label of the final element (default, matches "predict the current flow")
        ``any``      - 1 if any element in the window is an attack
        ``majority`` - majority vote over the window

    Because this function only ever sees one split's rows, no window can cross a split
    boundary. If ``groups`` (or ``session_column``) is supplied (e.g. session / IP IDs / file provenance),
    sequences that cross group boundaries are discarded.
    """
    if groups is None and session_column is not None:
        groups = session_column
    if seq_len < 1:
        raise SequenceError("seq_len must be >= 1")
    if len(features) != len(labels):
        raise SequenceError("features and labels have different lengths")

    n_rows = len(features)
    n_features = features.shape[1] if hasattr(features, "shape") and len(features.shape) > 1 else 0
    if n_rows < seq_len:
        return SequenceSet(
            features_2d=np.empty((0, n_features), dtype=np.float32),
            y=np.empty((0,), dtype=int),
            split=split,
            origins=np.empty((0,), dtype=int),
            seq_len=seq_len,
            label_rule=label_rule,
            stride=stride,
        )

    # 2D float32 representation (halves memory vs float64)
    if isinstance(features, pd.DataFrame):
        features_2d = features.to_numpy(dtype=np.float32)
    else:
        features_2d = np.asarray(features, dtype=np.float32)

    if isinstance(labels, pd.Series):
        targets = labels.to_numpy(dtype=int)
    else:
        targets = np.asarray(labels, dtype=int)

    grp_arr = None
    if groups is not None:
        if isinstance(groups, pd.Series):
            grp_arr = groups.to_numpy()
        else:
            grp_arr = np.asarray(groups)
        if len(grp_arr) != n_rows:
            raise SequenceError("groups and features have different lengths")

    # Fast prefix-sum label computation: O(1) per sequence
    csum = np.pad(np.cumsum(targets), (1, 0))

    origins_list: list[int] = []
    y_list: list[int] = []

    for start in range(0, n_rows - seq_len + 1, stride):
        # Prevent boundary crossing across sessions/groups if configured
        if grp_arr is not None:
            first_grp = grp_arr[start]
            if grp_arr[start + seq_len - 1] != first_grp or np.any(grp_arr[start : start + seq_len] != first_grp):
                continue

        origins_list.append(start)
        if label_rule == "last":
            label = int(targets[start + seq_len - 1])
        elif label_rule == "any":
            wsum = csum[start + seq_len] - csum[start]
            label = int(wsum > 0)
        elif label_rule == "majority":
            wsum = csum[start + seq_len] - csum[start]
            label = int(round(wsum / seq_len))
        else:
            raise SequenceError(f"unknown label_rule '{label_rule}'")
        y_list.append(label)

    return SequenceSet(
        features_2d=features_2d,
        y=np.asarray(y_list, dtype=int),
        split=split,
        origins=np.asarray(origins_list, dtype=int),
        seq_len=seq_len,
        label_rule=label_rule,
        stride=stride,
    )


def assert_no_boundary_crossing(sets: Sequence[SequenceSet], split_sizes: dict[str, int]) -> None:
    """Verify no sequence extends past the end of its own split."""
    for s in sets:
        if len(s) == 0:
            continue
        size = split_sizes[s.split]
        seq_len = s.seq_len if hasattr(s, "seq_len") else s.X.shape[1]
        end = s.origins + seq_len
        if int(end.max()) > size:
            raise SequenceError(
                f"sequence from split '{s.split}' extends beyond the split "
                f"(max end {int(end.max())} > size {size})"
            )


def _torch():
    import torch  # imported lazily so non-LSTM work does not pay the import cost

    return torch


def _make_sequence_dataset(seq_set: SequenceSet):
    """Create a PyTorch Dataset that yields (seq_len, F) sequences on the fly from the 2D array."""
    torch = _torch()

    class _Dataset(torch.utils.data.Dataset):
        def __init__(self, s: SequenceSet):
            self.s = s
            self.is_2d = hasattr(s, "features_2d") and s.features_2d is not None and len(s.features_2d) > 0
            if self.is_2d:
                feat_arr = s.features_2d
                if not feat_arr.flags.writeable:
                    feat_arr = feat_arr.copy()
                self.features = torch.from_numpy(feat_arr).float()
            else:
                self.features = None
            tgt_arr = s.y
            if not tgt_arr.flags.writeable:
                tgt_arr = tgt_arr.copy()
            self.targets = torch.from_numpy(tgt_arr).float()
            self.origins = s.origins
            self.seq_len = s.seq_len

        def __len__(self) -> int:
            return len(self.origins)

        def __getitem__(self, idx: int) -> tuple[torch.Tensor, torch.Tensor]:
            if self.is_2d and self.features is not None:
                start = int(self.origins[idx])
                x = self.features[start : start + self.seq_len]
            else:
                x = torch.as_tensor(self.s.X[idx], dtype=torch.float32)
            y = self.targets[idx]
            return x, y

    return _Dataset(seq_set)


@dataclass
class LSTMDetector:
    """Configurable supervised LSTM with mini-batch training, early stopping and checkpointing."""

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

    def fit(self, train: SequenceSet, validation: SequenceSet | None = None) -> "LSTMDetector":
        """Train LSTM with bounded mini-batches on-the-fly."""
        torch = _torch()
        set_global_seeds(self.seed)
        if len(train) == 0:
            raise SequenceError("no training sequences were built")

        n_features = train.n_features or (train.X.shape[2] if hasattr(train.X, "shape") else 0)
        self.feature_names = self.feature_names or [f"f{i}" for i in range(n_features)]
        net = self._build(n_features)
        self.model = net

        device = torch.device("cpu")
        net.to(device)
        optim = torch.optim.Adam(net.parameters(), lr=float(self.params["learning_rate"]))
        lossf = torch.nn.BCEWithLogitsLoss()

        batch_size = int(self.params["batch_size"])
        train_ds = _make_sequence_dataset(train)
        train_loader = torch.utils.data.DataLoader(
            train_ds,
            batch_size=batch_size,
            shuffle=True,
            drop_last=False,
        )

        val_loader = None
        if validation is not None and len(validation) > 0:
            val_ds = _make_sequence_dataset(validation)
            val_loader = torch.utils.data.DataLoader(
                val_ds,
                batch_size=batch_size * 2,
                shuffle=False,
                drop_last=False,
            )

        patience = int(self.params["patience"])
        best_state = {k: v.clone() for k, v in net.state_dict().items()}
        epochs_without_improvement = 0

        for epoch in range(int(self.params["epochs"])):
            net.train()
            epoch_loss = 0.0
            total_samples = 0
            for bx, by in train_loader:
                optim.zero_grad()
                logits = net(bx)
                loss = lossf(logits, by)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(net.parameters(), 5.0)
                optim.step()
                n_b = len(by)
                epoch_loss += float(loss.item()) * n_b
                total_samples += n_b
            epoch_loss /= max(1, total_samples)

            val_loss = float("nan")
            if val_loader is not None:
                net.eval()
                val_loss_sum = 0.0
                val_samples = 0
                with torch.no_grad():
                    for bx, by in val_loader:
                        logits = net(bx)
                        loss = lossf(logits, by)
                        n_b = len(by)
                        val_loss_sum += float(loss.item()) * n_b
                        val_samples += n_b
                val_loss = val_loss_sum / max(1, val_samples)
                if val_loss < self.best_val_loss - 1e-6:
                    self.best_val_loss = val_loss
                    self.best_epoch = epoch
                    best_state = {k: v.clone() for k, v in net.state_dict().items()}
                    epochs_without_improvement = 0
                else:
                    epochs_without_improvement += 1

            self.history.append({"epoch": epoch, "train_loss": epoch_loss, "val_loss": val_loss})
            logger.info("Epoch %d/%d: train_loss=%.5f, val_loss=%.5f", epoch + 1, self.params["epochs"], epoch_loss, val_loss)
            print(f"       Epoch {epoch + 1}/{self.params['epochs']}: train_loss={epoch_loss:.5f}, val_loss={val_loss:.5f} (best: {self.best_val_loss:.5f} at ep {self.best_epoch + 1})")
            if epochs_without_improvement >= patience:
                logger.info("LSTM early stopping at epoch %d (best epoch %d)", epoch, self.best_epoch)
                print(f"       LSTM early stopping triggered at epoch {epoch + 1} (best epoch {self.best_epoch + 1})")
                break

        net.load_state_dict(best_state)
        net.eval()
        logger.info("LSTM trained: seq_len=%d features=%d best_val_loss=%.6f", self.seq_len, n_features, self.best_val_loss)
        return self

    def predict_proba(
        self,
        seqs: SequenceSet,
        batch_size: int = 1024,
        two_class: bool = False,
    ) -> np.ndarray:
        """Continuous scores = sigmoid(logit), i.e. P(class = 1).

        Evaluates predictions in mini-batches so the test set is never materialized into
        a full tensor in memory.
        If two_class=True, returns shape (N, 2) where column 0 is P(0) and column 1 is P(1).
        """
        torch = _torch()
        if self.model is None:
            raise SequenceError("LSTM is not fitted")
        if len(seqs) == 0:
            return np.empty((0, 2) if two_class else (0,))

        self.model.eval()
        ds = _make_sequence_dataset(seqs)
        loader = torch.utils.data.DataLoader(
            ds,
            batch_size=batch_size,
            shuffle=False,
            drop_last=False,
        )

        scores_list: list[np.ndarray] = []
        with torch.no_grad():
            for bx, _ in loader:
                logits = self.model(bx)
                prob = torch.sigmoid(logits).cpu().numpy()
                scores_list.append(prob)

        scores = np.concatenate(scores_list) if scores_list else np.empty((0,))
        if two_class:
            return np.column_stack([1.0 - scores, scores])
        return scores

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
                "best_epoch": self.best_epoch,
                "best_val_loss": self.best_val_loss,
                "history": self.history,
            },
            path,
        )
        return path

    @classmethod
    def load(cls, path_or_dir: str | Path) -> "LSTMDetector":
        torch = _torch()
        path = Path(path_or_dir)
        if path.is_dir():
            path = path / "lstm.pt"
        if not path.is_file():
            raise FileNotFoundError(f"LSTM model checkpoint not found at {path}")
        data = torch.load(path, map_location="cpu", weights_only=False)
        detector = cls(
            params=data.get("params", {}),
            feature_names=data.get("feature_names", []),
            seq_len=data.get("seq_len", 5),
            label_rule=data.get("label_rule", "last"),
            seed=data.get("seed", 42),
        )
        detector.best_epoch = data.get("best_epoch", 0)
        detector.best_val_loss = data.get("best_val_loss", float("inf"))
        detector.history = data.get("history", [])
        if data.get("state_dict") is not None:
            n_features = len(detector.feature_names)
            detector.model = detector._build(n_features)
            detector.model.load_state_dict(data["state_dict"])
            detector.model.eval()
        return detector

"""Label contract: normalization, binary mapping, families and unknown-label rejection."""

from xrlids.labels.contract import (
    LabelContract,
    UnknownLabelError,
    apply_label_contract,
    load_label_contract,
)

__all__ = [
    "LabelContract",
    "UnknownLabelError",
    "apply_label_contract",
    "load_label_contract",
]

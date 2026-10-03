"""Target Network Parameter Update Strategies (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements Section 9.2:
- Polyak soft parameter updates: theta_target <- tau * theta_online + (1 - tau) * theta_target
  with tau_target = 0.005
- Hard parameter copy
"""

from __future__ import annotations

import torch
import torch.nn as nn


def soft_update(target_net: nn.Module, online_net: nn.Module, tau: float = 0.005) -> None:
    """Polyak soft update: theta_target <- tau * theta_online + (1 - tau) * theta_target."""
    with torch.no_grad():
        for target_p, online_p in zip(target_net.parameters(), online_net.parameters()):
            target_p.data.mul_(1.0 - tau).add_(online_p.data, alpha=tau)


def hard_update(target_net: nn.Module, online_net: nn.Module) -> None:
    """Hard update: copy online network weights directly into target network."""
    target_net.load_state_dict(online_net.state_dict())

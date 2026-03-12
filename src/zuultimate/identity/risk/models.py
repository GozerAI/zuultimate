"""Risk signal evaluation -- real-time auth risk scoring."""

import enum
from dataclasses import dataclass, field


class RiskAction(str, enum.Enum):
    allow = "allow"
    step_up = "step_up"
    block = "block"


@dataclass
class RiskSignal:
    signal_type: str
    score: float  # 0.0-1.0
    evidence: dict = field(default_factory=dict)


@dataclass
class RiskDecision:
    action: RiskAction
    score: float
    signals: list[RiskSignal] = field(default_factory=list)

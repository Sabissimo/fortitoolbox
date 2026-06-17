"""Verdict model. Every check yields one Status plus a headline and metrics --
the 'amplitud con criterio' principle: breadth of checks, each with a crisp
PASS/WARN/FAIL and the single number that matters.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    SKIPPED = "skipped"
    ERROR = "error"


SEVERITY = {Status.FAIL: 4, Status.WARN: 3, Status.ERROR: 2,
            Status.INFO: 1, Status.PASS: 0, Status.SKIPPED: 0}


@dataclass
class CheckResult:
    id: str
    module: str
    title: str
    status: Status = Status.INFO
    headline: str = ""
    metrics: List[Tuple[str, str]] = field(default_factory=list)
    raw: str = ""

    def m(self, k: str, v) -> None:
        self.metrics.append((k, str(v)))


def roll_up(results: List[CheckResult]) -> Dict[str, int]:
    tally = {s.value: 0 for s in Status}
    for r in results:
        tally[r.status.value] += 1
    return tally

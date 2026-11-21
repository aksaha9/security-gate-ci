"""Abstract reporter interface for rendering or publishing gate verdicts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from sec_gate.models import GateVerdict


class BaseReporter(ABC):
    """Contract for sec-gate output and CI comment reporters."""

    name: ClassVar[str]

    @abstractmethod
    def report(self, verdict: GateVerdict) -> Any:
        """Emit or publish ``verdict``."""

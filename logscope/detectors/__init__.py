"""Domain-specific detectors registry and base class for LogScope."""

from __future__ import annotations

from abc import ABC, abstractmethod
from logscope.canonical import CanonicalEvent, DetectionFinding


class BaseDetector(ABC):
    """Abstract base detector interface."""
    detector_name: str = "base"

    @abstractmethod
    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        """Analyze a single CanonicalEvent and return zero or more findings."""
        pass


class DetectorRegistry:
    """Central registry of modular security detectors."""

    def __init__(self):
        self._detectors: list[BaseDetector] = []

    def register(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)

    def run_all(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for det in self._detectors:
            try:
                res = det.analyze_event(event)
                if res:
                    findings.extend(res)
            except Exception:
                # Detectors must be resilient and never crash the stream
                pass
        return findings

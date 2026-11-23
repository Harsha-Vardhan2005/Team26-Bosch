"""Base class for all Guardian agents."""

from __future__ import annotations

from abc import ABC, abstractmethod

from guardian.models import AgentResult, ScanContext


class BaseAgent(ABC):
    """
    Every agent receives:
      - context:      scan metadata (repo path, commit, scan id).
      - shared_state: mutable dict for passing data between agents in
                      the pipeline (SBOM data, components, graph, etc.).

    Every agent returns an AgentResult.
    """

    name: str = "base"

    @abstractmethod
    def run(self, context: ScanContext, shared_state: dict) -> AgentResult:
        """Execute the agent's analysis and return structured results."""
        ...


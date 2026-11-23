"""
Analyst Agent — Stage 5 of the Guardian pipeline.

Responsibilities (to be implemented later):
  - Correlate findings from all previous agents.
  - Set risk_level on each Finding (distinct from tool severity).
  - Write evidence-backed explanations using ONLY the tool data —
    never invent advisory IDs, severity scores, or fixes.
  - Produce the consolidated assessment for the report.
"""

from __future__ import annotations

from guardian.agents.base import BaseAgent
from guardian.models import AgentResult, ScanContext


class AnalystAgent(BaseAgent):
    name = "analyst"

    def run(self, context: ScanContext, shared_state: dict) -> AgentResult:
        # TODO: implement later
        return AgentResult(agent_name=self.name)


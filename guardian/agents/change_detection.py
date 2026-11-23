"""
Change-Detection Agent — Stage 4 of the Guardian pipeline.

Responsibilities (to be implemented later):
  - Typosquat check: compare discovered package names against known
    popular packages for suspicious similarity.
  - Install-script check: detect pre/postinstall scripts in manifests.
  - Lockfile diff: compare the current lockfile against a baseline
    commit to find unexpected additions/changes.
  - Unpinned versions: flag deps using "latest" or wildcard ranges.
  - Dockerfile checks: untrusted base images, running as root, etc.
  - CI workflow checks: unsafe patterns in GitHub Actions / pipelines.
"""

from __future__ import annotations

from guardian.agents.base import BaseAgent
from guardian.models import AgentResult, ScanContext


class ChangeDetectionAgent(BaseAgent):
    name = "change_detection"

    def run(self, context: ScanContext, shared_state: dict) -> AgentResult:
        # TODO: implement later
        return AgentResult(agent_name=self.name)


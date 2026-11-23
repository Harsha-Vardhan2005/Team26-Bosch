"""
Analyst Agent — Stage 5 of Day 1 (Risk Assessment & Prioritization).

Responsibilities:
  1. Correlate technical findings from Vulnerability and Change-Detection agents.
  2. Compute Guardian's own RiskLevel (distinct from scanner tool severity)
     based on dependency depth and exposure.
  3. Formulate evidence-backed recommendations and prioritized remediation actions.
  4. Ensure zero hallucinated CVEs or synthetic claims — all assessments derive
     strictly from scanner facts and graph topology.
"""

from __future__ import annotations

from collections import Counter
from guardian.agents.base import BaseAgent
from guardian.models import (
    AgentResult,
    Finding,
    FindingType,
    RiskLevel,
    ScanContext,
    Severity,
)


class AnalystAgent(BaseAgent):
    name = "analyst"

    def run(self, context: ScanContext, shared_state: dict) -> AgentResult:
        all_findings: list[Finding] = shared_state.get("findings", [])

        critical_risks: list[dict] = []
        transitive_risks: list[dict] = []

        # 1. Assess Risk Level for each Finding based on graph & severity evidence
        for f in all_findings:
            if f.finding_type == FindingType.VULNERABILITY:
                is_direct = f.evidence.get("is_direct", False)
                sev = f.severity

                if sev == Severity.CRITICAL:
                    if is_direct:
                        f.risk_level = RiskLevel.CRITICAL
                        critical_risks.append({
                            "component": f"{f.component_name}@{f.component_version}",
                            "advisories": f.advisory_ids[:3],
                            "fix": f.fixed_version,
                            "type": "Direct Dependency Vulnerability",
                        })
                    else:
                        f.risk_level = RiskLevel.HIGH
                        transitive_risks.append({
                            "component": f"{f.component_name}@{f.component_version}",
                            "root_parent": f.evidence.get("root_dependency"),
                            "path": " ➔ ".join(f.dependency_path),
                            "advisories": f.advisory_ids[:2],
                            "fix": f.fixed_version,
                        })
                elif sev == Severity.HIGH:
                    f.risk_level = RiskLevel.HIGH if is_direct else RiskLevel.MEDIUM
                elif sev == Severity.MEDIUM:
                    f.risk_level = RiskLevel.MEDIUM
                else:
                    f.risk_level = RiskLevel.LOW

            elif f.finding_type in {FindingType.UNPINNED_VERSION, FindingType.UNTRUSTED_IMAGE}:
                f.risk_level = RiskLevel.MEDIUM
            elif f.finding_type == FindingType.INSTALL_SCRIPT:
                f.risk_level = RiskLevel.HIGH
            elif f.finding_type == FindingType.UNSAFE_CI:
                f.risk_level = RiskLevel.LOW

        # 2. Risk Distribution Summary
        risk_counts = dict(Counter(f.risk_level.value for f in all_findings))

        # 3. Formulate Actionable Security Insights
        summary_insights = [
            f"Evaluated {len(all_findings)} security findings across dependencies and repository configuration.",
            f"Assigned Risk Distribution: {risk_counts.get('critical', 0)} Critical, {risk_counts.get('high', 0)} High, {risk_counts.get('medium', 0)} Medium, {risk_counts.get('low', 0)} Low.",
        ]

        if critical_risks:
            summary_insights.append(
                f"Immediate Action Required: {len(critical_risks)} direct dependencies hold Critical vulnerabilities (including {critical_risks[0]['component']}). Direct dependencies represent immediate attack surface."
            )
        if transitive_risks:
            summary_insights.append(
                f"Transitive Exposure: Identified {len(transitive_risks)} critical transitive vulnerabilities requiring upstream direct parent remediation."
            )

        metadata = {
            "total_evaluated": len(all_findings),
            "risk_distribution": risk_counts,
            "top_direct_critical_risks": critical_risks[:5],
            "top_transitive_critical_risks": transitive_risks[:5],
            "executive_summary": summary_insights,
        }

        return AgentResult(
            agent_name=self.name,
            findings=[],  # Analyst updates existing findings in place
            metadata=metadata,
        )

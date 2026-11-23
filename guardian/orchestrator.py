"""
Guardian Orchestrator — coordinates the agent pipeline.

Runs each specialist agent in order, feeds shared state forward,
and merges results into a single ScanResult.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from guardian.agents import (
    AnalystAgent,
    ChangeDetectionAgent,
    DiscoveryAgent,
    GraphAgent,
    VulnerabilityAgent,
)
from guardian.models import AgentResult, ScanContext, ScanResult
from guardian.report_generator import write_markdown_report
from guardian.dashboard_template import render_dashboard


class Orchestrator:
    """Run the full Day-1 analysis pipeline on a repository."""

    def __init__(self, groq_key: Optional[str] = None) -> None:
        self.agents = [
            DiscoveryAgent(),
            GraphAgent(),
            VulnerabilityAgent(),
            ChangeDetectionAgent(),
            AnalystAgent(api_key=groq_key),
        ]

    def run(
        self,
        repo_path: str,
        *,
        sbom_path: Optional[str] = None,
        grype_path: Optional[str] = None,
        output_path: Optional[str] = None,
        groq_key: Optional[str] = None,
        callback: Optional[Callable[[str, str, Any], None]] = None,
    ) -> ScanResult:
        if groq_key:
            self.agents[-1] = AnalystAgent(api_key=groq_key)

        repo_path = str(Path(repo_path).resolve())

        context = ScanContext(
            repo_path=repo_path,
            repo_name=Path(repo_path).name,
            commit_hash=_detect_commit(repo_path),
        )

        shared_state: dict = {
            "sbom_path": sbom_path,
            "grype_path": grype_path,
            "sbom_data": None,
            "grype_data": None,
            "components": [],
            "findings": [],
            "elements": [],
            "dependency_graph": None,
        }

        scan_result = ScanResult(context=context)

        for agent in self.agents:
            print(f"[guardian] Running {agent.name} agent …")
            if callback:
                try:
                    callback(agent.name, "running", {"message": f"Running {agent.name} agent..."})
                except Exception:
                    pass

            agent_result: AgentResult = agent.run(context, shared_state)

            scan_result.agent_results[agent_result.agent_name] = agent_result
            scan_result.components.extend(agent_result.components)
            scan_result.findings.extend(agent_result.findings)
            scan_result.elements.extend(agent_result.elements)

            shared_state["components"].extend(agent_result.components)
            shared_state["findings"].extend(agent_result.findings)
            shared_state["elements"].extend(agent_result.elements)

            if callback:
                try:
                    callback(
                        agent.name,
                        "completed",
                        {
                            "components_count": len(agent_result.components),
                            "findings_count": len(agent_result.findings),
                            "elements_count": len(agent_result.elements),
                            "metadata": agent_result.metadata,
                        },
                    )
                except Exception:
                    pass

            if agent_result.errors:
                for err in agent_result.errors:
                    print(f"  ⚠ {agent.name}: {err}")

        if output_path:
            _write_report(scan_result, output_path)

        graph = shared_state.get("dependency_graph")
        dashboard_path = Path(output_path).parent / "dashboard.html" if output_path else Path("reports/dashboard.html")
        _write_dashboard(scan_result, graph, str(dashboard_path))

        if callback:
            try:
                callback(
                    "orchestrator",
                    "finished",
                    {
                        "total_findings": len(scan_result.findings),
                        "total_components": len(scan_result.components),
                        "total_elements": len(scan_result.elements),
                    },
                )
            except Exception:
                pass

        return scan_result


def _detect_commit(repo_path: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _write_report(scan_result: ScanResult, path: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(scan_result.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )
    print(f"[guardian] Report written to {out}")

    # Generate Markdown Executive Report
    md_path = out.parent / "SECURITY-REPORT.md"
    write_markdown_report(scan_result, str(md_path))


def _graph_to_json(graph: Optional[nx.DiGraph]) -> dict:
    if graph is None:
        return {"nodes": [], "edges": []}

    nodes = []
    for node_id, attrs in graph.nodes(data=True):
        nodes.append({
            "id": node_id,
            "name": attrs.get("name", node_id),
            "version": attrs.get("version", ""),
            "is_direct": attrs.get("is_direct", False),
        })

    edges = []
    for src, tgt in graph.edges():
        edges.append({"source": src, "target": tgt})

    return {"nodes": nodes, "edges": edges}


def _write_dashboard(
    scan_result: ScanResult,
    graph: Optional[nx.DiGraph],
    path: str,
) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    html = render_dashboard(scan_result, graph)
    out.write_text(html, encoding="utf-8")
    print(f"[guardian] Dashboard written to {out}")

"""
Command-line interface for the Software Supply Chain Guardian.

Usage:
    python -m guardian scan <path> [--sbom FILE] [--grype FILE] [-o FILE]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from guardian.orchestrator import Orchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardian",
        description="Software Supply Chain Guardian — scan a repository for "
                    "supply-chain risks and present evidence-backed findings.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Scan a local repository.",
    )
    scan.add_argument(
        "path",
        type=str,
        help="Path to the local repository to analyse.",
    )
    scan.add_argument(
        "--sbom",
        type=str,
        default=None,
        help="Pre-generated CycloneDX SBOM file (skips running Syft).",
    )
    scan.add_argument(
        "--grype",
        type=str,
        default=None,
        help="Pre-generated Grype results file (skips running Grype).",
    )
    scan.add_argument(
        "--groq-key",
        type=str,
        default=None,
        help="Groq API key for the AI Intelligence Layer (defaults to GROQ_API_KEY env or .env).",
    )
    scan.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Path to write the JSON report.",
    )

    serve = sub.add_parser(
        "serve",
        help="Start the interactive Guardian Live Demo Server and UI Command Center.",
    )
    serve.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the web server (default: 8000).",
    )
    serve.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind (default: 127.0.0.1).",
    )
    serve.add_argument(
        "--open",
        action="store_true",
        help="Automatically open the web dashboard in your default browser.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "serve":
        import uvicorn
        import webbrowser
        url = f"http://{args.host}:{args.port}"
        print(f"[guardian] 🚀 Starting Guardian Live Command Center at {url}")
        print(f"[guardian] Interactive Live UI, Real-time Scan SSE, and AI Copilot active.")
        if args.open:
            webbrowser.open(url)
        uvicorn.run("guardian.server:app", host=args.host, port=args.port, reload=False)
        return 0

    if args.command == "scan":
        repo = Path(args.path)
        if not repo.is_dir():
            print(f"Error: '{args.path}' is not a directory.", file=sys.stderr)
            return 1

        orchestrator = Orchestrator(groq_key=args.groq_key)
        result = orchestrator.run(
            repo_path=str(repo),
            sbom_path=args.sbom,
            grype_path=args.grype,
            output_path=args.output,
            groq_key=args.groq_key,
        )

        # Detailed summary
        disc_meta = result.agent_results.get("discovery", None)
        supply_chain_count = disc_meta.metadata.get("supply_chain_files_count", 0) if disc_meta else len(result.elements)
        graph_meta = result.agent_results.get("graph", None)
        nodes = graph_meta.metadata.get("total_nodes", 0) if graph_meta else 0
        edges = graph_meta.metadata.get("total_edges", 0) if graph_meta else 0
        direct_deps = graph_meta.metadata.get("direct_dependencies", 0) if graph_meta else 0

        vuln_meta = result.agent_results.get("vulnerability", None)
        vuln_counts = vuln_meta.metadata.get("severity_breakdown", {}) if vuln_meta else {}
        analyst_meta = result.agent_results.get("analyst", None)
        risk_dist = analyst_meta.metadata.get("risk_distribution", {}) if analyst_meta else {}
        top_critical = analyst_meta.metadata.get("top_critical_risks", []) if analyst_meta else []

        ai_reach = analyst_meta.metadata.get("reachability_agent_assessment") if analyst_meta else ""
        ai_context = analyst_meta.metadata.get("context_analysis_assessment") if analyst_meta else ""
        ai_risk = analyst_meta.metadata.get("risk_analysis_assessment") if analyst_meta else ""
        ai_recs = analyst_meta.metadata.get("recommendation_agent_actions") if analyst_meta else ""

        print()
        print("=" * 76)
        print("         🛡️   SOFTWARE SUPPLY CHAIN GUARDIAN — DAY 1 ASSESSMENT")
        print("=" * 76)
        print(f"  Target Repository   : {result.context.repo_name}")
        print(f"  Verified Commit     : {result.context.commit_hash or 'unknown'}")
        print("-" * 76)
        print("  INVENTORY & TOPOLOGY:")
        print(f"    • Total Repository Files  : {len(result.elements)}")
        print(f"    • Supply-Chain Manifests  : {supply_chain_count}")
        print(f"    • Software Components     : {len(result.components)}")
        print(f"    • Dependency Graph Nodes  : {nodes:,}")
        print(f"    • Dependency Graph Edges  : {edges:,}")
        print(f"    • Direct Dependencies     : {direct_deps}")
        print("-" * 76)
        print("  VULNERABILITY DETECTION (Grype Engine):")
        print(f"    • Total Deduplicated Risks : {len(result.findings)}")
        print(f"    • Critical Severity        : {vuln_counts.get('Critical', 0)}")
        print(f"    • High Severity            : {vuln_counts.get('High', 0)}")
        print(f"    • Medium Severity          : {vuln_counts.get('Medium', 0)}")
        print(f"    • Low Severity             : {vuln_counts.get('Low', 0)}")
        print("-" * 76)
        print("  GUARDIAN RISK LEVEL EVALUATION:")
        print(f"    • Critical Risk (Direct)   : {risk_dist.get('critical', 0)}")
        print(f"    • High Risk (Transitive)   : {risk_dist.get('high', 0)}")
        print(f"    • Medium Risk              : {risk_dist.get('medium', 0)}")
        print(f"    • Low Risk / Anomaly       : {risk_dist.get('low', 0)}")

        if top_critical:
            print("-" * 76)
            print("  ⚠️   PRIORITY ACTION ITEMS (Direct Critical Vulnerabilities):")
            for item in top_critical[:4]:
                advisories = ", ".join(item.get("advisories", []))
                fix = f"➜ Fix available in v{item['fix']}" if item.get("fix") else "➜ No direct patch upstream"
                print(f"    [!] {item['package']:<22} | {advisories} ({fix})")

        if ai_reach or ai_risk:
            print("-" * 76)
            print("  🤖  AGENTIC AI INTELLIGENCE LAYER (Groq 120B Multi-Agent Team):")
            print()
            print("  [Agent 1: Reachability Agent]")
            print(f"    {ai_reach.strip()}")
            print()
            print("  [Agent 2: Context Analysis Agent]")
            print(f"    {ai_context.strip()}")
            print()
            print("  [Agent 3: Risk Analysis Agent (Lead)]")
            print(f"    {ai_risk.strip()}")
            print()
            print("  [Agent 4: Recommendation Agent]")
            print(f"    {ai_recs.strip()}")

        print("=" * 76)

        if args.output:
            print(f"  Full Audit Report Written To : {args.output}")
            print("=" * 76)
        return 0

    return 0


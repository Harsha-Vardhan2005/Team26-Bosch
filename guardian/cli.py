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
        "-o", "--output",
        type=str,
        default=None,
        help="Path to write the JSON report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        repo = Path(args.path)
        if not repo.is_dir():
            print(f"Error: '{args.path}' is not a directory.", file=sys.stderr)
            return 1

        orchestrator = Orchestrator()
        result = orchestrator.run(
            repo_path=str(repo),
            sbom_path=args.sbom,
            grype_path=args.grype,
            output_path=args.output,
        )

        # Quick summary
        disc_meta = result.agent_results.get("discovery", None)
        supply_chain_count = disc_meta.metadata.get("supply_chain_files_count", 0) if disc_meta else len(result.elements)
        graph_meta = result.agent_results.get("graph", None)
        nodes = graph_meta.metadata.get("total_nodes", 0) if graph_meta else 0
        edges = graph_meta.metadata.get("total_edges", 0) if graph_meta else 0
        direct_deps = graph_meta.metadata.get("direct_dependencies", 0) if graph_meta else 0

        print()
        print("=" * 65)
        print("     Software Supply Chain Guardian — Day 1 Scan Summary")
        print("=" * 65)
        print(f"  Repository                 : {result.context.repo_name}")
        print(f"  Tested Commit              : {result.context.commit_hash or 'unknown'}")
        print("-" * 65)
        print(f"  Total Repo Files Discovered: {len(result.elements)}")
        print(f"  Supply-Chain Files         : {supply_chain_count}")
        print(f"  Components (SBOM)          : {len(result.components)}")
        print(f"  Dependency Graph Nodes     : {nodes}")
        print(f"  Dependency Graph Edges     : {edges}")
        print(f"  Direct Dependencies        : {direct_deps}")
        print(f"  Findings (Risks)           : {len(result.findings)}")
        print("=" * 65)

        if args.output:
            print(f"  Full report: {args.output}")
        return 0

    return 0


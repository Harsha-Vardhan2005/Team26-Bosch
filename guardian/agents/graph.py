"""
Graph Agent — Checkpoint 3 (Dependency Graph).

Responsibilities:
  1. Parse package-lock.json (v2 "packages" format AND v1 "dependencies"
     format) to build a directed dependency graph.
  2. Mark each component as direct or transitive.
  3. Provide path-tracing from any component back to its direct-
     dependency root.
  4. Store the graph in shared_state for downstream agents.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import networkx as nx

from guardian.agents.base import BaseAgent
from guardian.models import AgentResult, Component, ScanContext


# Root node name used in the graph
_ROOT = "<root>"


class GraphAgent(BaseAgent):
    name = "graph"

    def run(self, context: ScanContext, shared_state: dict) -> AgentResult:
        repo_path = Path(context.repo_path)
        errors: list[str] = []
        graph = nx.DiGraph()
        direct_deps: set[str] = set()
        metadata: dict = {}

        # ---- Find lockfiles to parse ----
        lockfile = repo_path / "package-lock.json"
        if lockfile.exists():
            try:
                data = json.loads(lockfile.read_text(encoding="utf-8"))
                lockfile_version = data.get("lockfileVersion", 1)
                metadata["lockfile_version"] = lockfile_version

                # Parse using the best format available
                if lockfile_version >= 2 and "packages" in data:
                    graph, direct_deps = self._parse_v2_packages(data)
                elif "dependencies" in data:
                    graph, direct_deps = self._parse_v1_dependencies(data)
                else:
                    errors.append("package-lock.json has no parseable format")
            except Exception as exc:
                errors.append(f"Failed to parse package-lock.json: {exc}")
        else:
            errors.append("No package-lock.json found in repo")

        # ---- Update components with direct/transitive info ----
        existing_components: list[Component] = shared_state.get("components", [])
        for comp in existing_components:
            if comp.ecosystem == "npm":
                node_key = f"{comp.name}@{comp.version}"
                comp.is_direct = comp.name in direct_deps

        # ---- Store graph in shared state ----
        shared_state["dependency_graph"] = graph
        shared_state["direct_deps"] = direct_deps

        metadata.update({
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
            "direct_dependencies": len(direct_deps),
            "direct_dep_names": sorted(direct_deps),
        })

        # ---- Generate sample paths for verification ----
        sample_paths = {}
        # Verify handlebars path (commonly asked)
        for target in ["handlebars", "minimist", "lodash"]:
            paths = self.find_dependency_paths(graph, target)
            if paths:
                sample_paths[target] = [
                    " → ".join(p) for p in paths[:3]  # top 3 shortest
                ]
        metadata["sample_paths"] = sample_paths

        return AgentResult(
            agent_name=self.name,
            metadata=metadata,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Lockfile v2 parser ("packages" key with node_modules/ paths)
    # ------------------------------------------------------------------

    def _parse_v2_packages(
        self, data: dict
    ) -> tuple[nx.DiGraph, set[str]]:
        """Parse lockfileVersion 2/3 'packages' format."""
        graph = nx.DiGraph()
        packages = data.get("packages", {})
        direct_deps: set[str] = set()

        # Root entry "" holds the project itself
        root_entry = packages.get("", {})
        root_deps = {
            **root_entry.get("dependencies", {}),
            **root_entry.get("devDependencies", {}),
        }
        direct_deps = set(root_deps.keys())

        graph.add_node(_ROOT, version="project", is_direct=True)

        # Build a map: package name -> (version, their dependencies)
        # In v2, keys are like "node_modules/express" or
        # "node_modules/hbs/node_modules/handlebars" (nested)
        pkg_map: dict[str, dict] = {}
        for path_key, pkg_info in packages.items():
            if not path_key or path_key == "":
                continue
            # Extract the package name from the path
            parts = path_key.split("node_modules/")
            pkg_name = parts[-1] if parts else path_key
            version = pkg_info.get("version", "unknown")
            node_id = f"{pkg_name}@{version}"

            graph.add_node(node_id, name=pkg_name, version=version,
                           is_direct=pkg_name in direct_deps)
            pkg_map[path_key] = {
                "node_id": node_id,
                "name": pkg_name,
                "version": version,
                "deps": {
                    **pkg_info.get("dependencies", {}),
                    **pkg_info.get("optionalDependencies", {}),
                },
            }

        # Add root -> direct dep edges
        for dep_name in direct_deps:
            # Find the matching node
            dep_key = f"node_modules/{dep_name}"
            if dep_key in pkg_map:
                graph.add_edge(_ROOT, pkg_map[dep_key]["node_id"])

        # Add all dependency edges
        for path_key, info in pkg_map.items():
            parent_id = info["node_id"]
            for dep_name in info["deps"]:
                # Resolve: check nested first, then hoist
                child_key = f"{path_key}/node_modules/{dep_name}"
                if child_key not in pkg_map:
                    child_key = f"node_modules/{dep_name}"
                if child_key in pkg_map:
                    child_id = pkg_map[child_key]["node_id"]
                    graph.add_edge(parent_id, child_id)

        return graph, direct_deps

    # ------------------------------------------------------------------
    # Lockfile v1 parser ("dependencies" key with nested structure)
    # ------------------------------------------------------------------

    def _parse_v1_dependencies(
        self, data: dict
    ) -> tuple[nx.DiGraph, set[str]]:
        """Parse lockfileVersion 1 nested 'dependencies' format."""
        graph = nx.DiGraph()
        graph.add_node(_ROOT, version="project", is_direct=True)
        direct_deps: set[str] = set()

        top_deps = data.get("dependencies", {})
        # Also read package.json-level deps from the root
        root_pkg_deps = set()
        root_entry = data.get("packages", {}).get("", {})
        if root_entry:
            root_pkg_deps = set(root_entry.get("dependencies", {}).keys())
            root_pkg_deps |= set(root_entry.get("devDependencies", {}).keys())

        for name in top_deps:
            direct_deps.add(name)

        self._walk_v1_deps(graph, _ROOT, top_deps, direct_deps)
        return graph, direct_deps

    def _walk_v1_deps(
        self,
        graph: nx.DiGraph,
        parent_id: str,
        deps: dict,
        direct_deps: set[str],
    ) -> None:
        """Recursively walk v1 nested dependencies."""
        for name, info in deps.items():
            version = info.get("version", "unknown")
            node_id = f"{name}@{version}"

            if not graph.has_node(node_id):
                graph.add_node(
                    node_id, name=name, version=version,
                    is_direct=name in direct_deps,
                )
            graph.add_edge(parent_id, node_id)

            # Recurse into nested dependencies
            nested = info.get("dependencies", {})
            if nested:
                self._walk_v1_deps(graph, node_id, nested, direct_deps)

            # Also handle "requires" (which reference hoisted siblings)
            requires = info.get("requires", {})
            for req_name, req_version_range in requires.items():
                # Try to find the actual resolved package
                # (it might be at the top level or nested)
                # For now, we'll check if there's already a node for it
                matching_nodes = [
                    n for n in graph.nodes
                    if graph.nodes[n].get("name") == req_name
                ]
                if matching_nodes:
                    graph.add_edge(node_id, matching_nodes[0])

    # ------------------------------------------------------------------
    # Public utility: find dependency paths
    # ------------------------------------------------------------------

    @staticmethod
    def find_dependency_paths(
        graph: nx.DiGraph,
        target_name: str,
        max_paths: int = 5,
    ) -> list[list[str]]:
        """
        Find all shortest paths from <root> to any node matching
        *target_name* (by name, ignoring version).
        """
        target_nodes = [
            n for n in graph.nodes
            if graph.nodes[n].get("name") == target_name
            or n.startswith(f"{target_name}@")
        ]

        all_paths: list[list[str]] = []
        for target in target_nodes:
            try:
                for path in nx.all_shortest_paths(graph, _ROOT, target):
                    all_paths.append(path)
                    if len(all_paths) >= max_paths:
                        return all_paths
            except nx.NetworkXNoPath:
                continue
            except nx.NodeNotFound:
                continue

        return all_paths

    @staticmethod
    def get_dependency_path(
        graph: nx.DiGraph,
        component_name: str,
        component_version: str,
    ) -> list[str]:
        """Get the shortest path from root to a specific component."""
        target = f"{component_name}@{component_version}"
        if target not in graph:
            return []
        try:
            path = nx.shortest_path(graph, _ROOT, target)
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

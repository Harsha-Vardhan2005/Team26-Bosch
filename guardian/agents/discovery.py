"""
Discovery Agent — Checkpoint 1 (Repo Exploration) + Checkpoint 2 (SBOM).

Responsibilities:
  1. Walk the entire repo to discover and categorize ALL files (Stage 1).
  2. Identify the specific Supply-Chain Control Files (manifests, lockfiles,
     container configs, CI/CD workflows).
  3. Run Syft via Docker to produce a CycloneDX SBOM — OR load a
     pre-generated SBOM when ``--sbom`` is passed.
  4. Verify the exact Syft catalogers that inspected the files.
  5. Parse the SBOM into Component inventory items.
  6. Detect which ecosystems are present.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Optional

from guardian.agents.base import BaseAgent
from guardian.models import (
    AgentResult,
    Component,
    ElementType,
    RepositoryElement,
    ScanContext,
)
from guardian.tools import ToolRunner


# ---------------------------------------------------------------------------
# Supply-chain file patterns (manifests, lockfiles, docker, etc.)
# ---------------------------------------------------------------------------

_SUPPLY_CHAIN_PATTERNS: dict[str, tuple[ElementType, Optional[str]]] = {
    # Node / JavaScript
    "package.json": (ElementType.MANIFEST, "npm"),
    "package-lock.json": (ElementType.LOCKFILE, "npm"),
    "yarn.lock": (ElementType.LOCKFILE, "npm"),
    "pnpm-lock.yaml": (ElementType.LOCKFILE, "npm"),
    "bun.lockb": (ElementType.LOCKFILE, "npm"),
    "bun.lock": (ElementType.LOCKFILE, "npm"),
    # Python
    "requirements.txt": (ElementType.MANIFEST, "pypi"),
    "requirements-dev.txt": (ElementType.MANIFEST, "pypi"),
    "Pipfile": (ElementType.MANIFEST, "pypi"),
    "Pipfile.lock": (ElementType.LOCKFILE, "pypi"),
    "pyproject.toml": (ElementType.MANIFEST, "pypi"),
    "poetry.lock": (ElementType.LOCKFILE, "pypi"),
    "uv.lock": (ElementType.LOCKFILE, "pypi"),
    "setup.py": (ElementType.MANIFEST, "pypi"),
    "setup.cfg": (ElementType.MANIFEST, "pypi"),
    # Java / JVM
    "pom.xml": (ElementType.MANIFEST, "maven"),
    "build.gradle": (ElementType.MANIFEST, "gradle"),
    "build.gradle.kts": (ElementType.MANIFEST, "gradle"),
    # Others
    "Gemfile": (ElementType.MANIFEST, "rubygems"),
    "Gemfile.lock": (ElementType.LOCKFILE, "rubygems"),
    "go.mod": (ElementType.MANIFEST, "go"),
    "go.sum": (ElementType.LOCKFILE, "go"),
    "Cargo.toml": (ElementType.MANIFEST, "cargo"),
    "Cargo.lock": (ElementType.LOCKFILE, "cargo"),
    "composer.json": (ElementType.MANIFEST, "composer"),
    "composer.lock": (ElementType.LOCKFILE, "composer"),
    "*.csproj": (ElementType.MANIFEST, "nuget"),
    # Containers
    "Dockerfile": (ElementType.DOCKERFILE, None),
    "docker-compose.yml": (ElementType.DOCKER_COMPOSE, None),
    "docker-compose.yaml": (ElementType.DOCKER_COMPOSE, None),
}

_CI_DIRS = {".github/workflows", ".gitlab-ci", ".circleci"}


class DiscoveryAgent(BaseAgent):
    name = "discovery"

    def run(self, context: ScanContext, shared_state: dict) -> AgentResult:
        repo_path = Path(context.repo_path)
        elements: list[RepositoryElement] = []
        components: list[Component] = []
        ecosystems: set[str] = set()
        errors: list[str] = []

        # ---- 1. Walk the ENTIRE repo and catalog all files ----
        elements, ecosystems = self._discover_all_elements(repo_path)

        # ---- 2. Run / load SBOM ----
        sbom_data = None
        sbom_path = shared_state.get("sbom_path")
        try:
            sbom_data = ToolRunner.run_syft(
                repo_path=str(repo_path),
                pregenerated=sbom_path,
            )
            shared_state["sbom_data"] = sbom_data
        except Exception as exc:
            errors.append(f"SBOM generation failed: {exc}")

        # ---- 3. Parse SBOM into Components & check Syft catalogers ----
        syft_catalogers: set[str] = set()
        if sbom_data:
            components, syft_catalogers = self._parse_sbom_components(sbom_data)
            for comp in components:
                ecosystems.add(comp.ecosystem)

        # Calculate exact metrics dynamically
        supply_chain_count = sum(1 for e in elements if e.is_supply_chain)
        category_counts = dict(Counter(e.category for e in elements))

        metadata = {
            "total_files_discovered": len(elements),
            "supply_chain_files_count": supply_chain_count,
            "category_breakdown": category_counts,
            "syft_catalogers_verified": sorted(syft_catalogers),
            "ecosystems_detected": sorted(ecosystems),
            "total_components": len(components),
            "sbom_format": sbom_data.get("bomFormat", "unknown") if sbom_data else None,
            "sbom_spec_version": sbom_data.get("specVersion", "unknown") if sbom_data else None,
        }

        # Store SBOM tool version
        if sbom_data and "metadata" in sbom_data:
            tools = sbom_data["metadata"].get("tools", {})
            tool_comps = tools.get("components", [])
            if tool_comps:
                t = tool_comps[0]
                context.tool_versions["syft"] = t.get("version", "unknown")

        return AgentResult(
            agent_name=self.name,
            components=components,
            elements=elements,
            metadata=metadata,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Dynamic Repo Walker & Classifier
    # ------------------------------------------------------------------

    def _discover_all_elements(
        self, repo_path: Path
    ) -> tuple[list[RepositoryElement], set[str]]:
        """Walk the entire repo and categorize every single file."""
        elements: list[RepositoryElement] = []
        ecosystems: set[str] = set()

        for root, dirs, files in os.walk(repo_path):
            # Exclude vendor and VCS directories
            dirs[:] = [
                d for d in dirs
                if d not in {"node_modules", ".git", "__pycache__", "venv", ".venv", ".idea", ".vscode"}
            ]

            rel_root = Path(root).relative_to(repo_path)
            rel_root_str = str(rel_root).replace("\\", "/")

            for fname in files:
                rel_path = (str(rel_root / fname) if rel_root_str != "." else fname).replace("\\", "/")

                # 1. Check CI/CD workflows
                is_ci = any(rel_path.startswith(ci) for ci in _CI_DIRS)
                if is_ci:
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.CI_WORKFLOW,
                        category="CI/CD Workflows",
                        is_supply_chain=True,
                        metadata={"ci_system": "github-actions" if ".github" in rel_path else "ci"},
                    ))
                    ecosystems.add("github-action")
                    continue

                # 2. Check Supply-Chain files (manifests, lockfiles, docker)
                if fname in _SUPPLY_CHAIN_PATTERNS or fname.startswith("Dockerfile"):
                    if fname.startswith("Dockerfile"):
                        etype, eco = ElementType.DOCKERFILE, None
                    else:
                        etype, eco = _SUPPLY_CHAIN_PATTERNS[fname]

                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=etype,
                        category="Supply-Chain Manifests",
                        is_supply_chain=True,
                        ecosystem=eco,
                    ))
                    if eco:
                        ecosystems.add(eco)
                    continue

                # 3. Check Exploit Demos / PoCs
                if rel_path.startswith("exploits/"):
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.EXPLOIT_DEMO,
                        category="Exploit Demonstrations",
                        is_supply_chain=False,
                        metadata={"note": "Demonstration vulnerability script/payload"},
                    ))
                    continue

                # 4. Check Tests
                if rel_path.startswith("tests/") or "spec." in fname or "test." in fname:
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.TEST,
                        category="Tests & Specs",
                        is_supply_chain=False,
                    ))
                    continue

                # 5. Check Views & Templates
                if rel_path.startswith("views/") or fname.endswith((".ejs", ".hbs", ".dust", ".html")):
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.VIEW,
                        category="Templates & Views",
                        is_supply_chain=False,
                    ))
                    continue

                # 6. Check Static Assets
                if rel_path.startswith("public/"):
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.STATIC_ASSET,
                        category="Static Assets",
                        is_supply_chain=False,
                    ))
                    continue

                # 7. Check App Source Code
                if fname.endswith((".js", ".ts", ".py", ".go", ".java", ".rb", ".cs")):
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.SOURCE,
                        category="Application Source Code",
                        is_supply_chain=False,
                    ))
                    continue

                # 8. Check Documentation
                if fname.endswith((".md", ".txt")) or fname in {"LICENSE", "README"}:
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.DOCUMENTATION,
                        category="Documentation",
                        is_supply_chain=False,
                    ))
                    continue

                # 9. Config / Other
                if fname.endswith((".json", ".yml", ".yaml", ".env")) or fname.startswith("."):
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.CONFIG,
                        category="Configuration",
                        is_supply_chain=False,
                    ))
                else:
                    elements.append(RepositoryElement(
                        path=rel_path,
                        element_type=ElementType.OTHER,
                        category="Other Files",
                        is_supply_chain=False,
                    ))

        return elements, ecosystems

    # ------------------------------------------------------------------
    # SBOM Component Parser
    # ------------------------------------------------------------------

    def _parse_sbom_components(
        self, sbom: dict
    ) -> tuple[list[Component], set[str]]:
        """Parse CycloneDX SBOM components and record catalogers used."""
        raw_components = sbom.get("components", [])
        seen: set[tuple[str, str, str]] = set()
        components: list[Component] = []
        catalogers: set[str] = set()

        for raw in raw_components:
            name = raw.get("name", "")
            version = raw.get("version", "")
            purl = raw.get("purl", "")
            comp_type = raw.get("type", "library")

            # Record Syft catalogers
            for prop in raw.get("properties", []):
                if prop.get("name") == "syft:package:foundBy":
                    catalogers.add(prop.get("value"))

            ecosystem = self._detect_ecosystem(raw)

            licenses: list[str] = []
            for lic_entry in raw.get("licenses", []):
                if "license" in lic_entry:
                    licenses.append(
                        lic_entry["license"].get("id", "")
                        or lic_entry["license"].get("name", "")
                    )
                elif "expression" in lic_entry:
                    licenses.append(lic_entry["expression"])

            key = (ecosystem, name, version)
            if key in seen:
                continue
            seen.add(key)

            components.append(Component(
                name=name,
                version=version,
                ecosystem=ecosystem,
                purl=purl or None,
                component_type=comp_type,
                licenses=[l for l in licenses if l],
                source_file=self._get_source_file(raw),
            ))

        return components, catalogers

    @staticmethod
    def _detect_ecosystem(raw: dict) -> str:
        """Infer ecosystem from purl or syft properties."""
        purl = raw.get("purl", "")
        if purl.startswith("pkg:npm/"):
            return "npm"
        if purl.startswith("pkg:pypi/"):
            return "pypi"
        if purl.startswith("pkg:maven/"):
            return "maven"
        if purl.startswith("pkg:github/"):
            return "github-action"
        if purl.startswith("pkg:cargo/"):
            return "cargo"
        if purl.startswith("pkg:golang/"):
            return "go"
        if purl.startswith("pkg:nuget/"):
            return "nuget"
        if purl.startswith("pkg:gem/"):
            return "rubygems"

        for prop in raw.get("properties", []):
            if prop.get("name") == "syft:package:language":
                lang = prop.get("value", "")
                return {"javascript": "npm", "python": "pypi", "java": "maven",
                        "go": "go", "rust": "cargo"}.get(lang, lang)
            if prop.get("name") == "syft:package:type":
                return prop.get("value", "unknown")

        return "unknown"

    @staticmethod
    def _get_source_file(raw: dict) -> Optional[str]:
        """Extract the source file path from syft properties."""
        for prop in raw.get("properties", []):
            if prop.get("name", "").startswith("syft:location:") and prop["name"].endswith(":path"):
                return prop.get("value", "")
        return None

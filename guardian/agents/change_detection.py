"""
Change-Detection Agent — Stage 4 of Day 1 (Supply-Chain Risk Signals).

Responsibilities:
  1. Inspect manifests (e.g. package.json) for unpinned dependencies (e.g. "latest", "*").
  2. Inspect manifests for risky install scripts (preinstall, postinstall, build).
  3. Inspect container definitions (Dockerfile) for base image risks.
  4. Inspect CI workflows (.github/workflows) for third-party action usage.
  5. Produce normalized Finding objects with evidence and confidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from guardian.agents.base import BaseAgent
from guardian.models import (
    AgentResult,
    Finding,
    FindingType,
    RiskLevel,
    ScanContext,
    Severity,
)


class ChangeDetectionAgent(BaseAgent):
    name = "change_detection"

    def run(self, context: ScanContext, shared_state: dict) -> AgentResult:
        repo_path = Path(context.repo_path)
        findings: list[Finding] = []
        errors: list[str] = []

        # 1. Inspect package.json for unpinned versions & install scripts
        pkg_json = repo_path / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                all_deps = {**deps, **dev_deps}

                # Check unpinned versions
                for dep_name, dep_ver in all_deps.items():
                    if dep_ver in {"latest", "*"} or dep_ver.startswith((">=", ">")):
                        findings.append(Finding(
                            finding_type=FindingType.UNPINNED_VERSION,
                            component_name=dep_name,
                            component_version=dep_ver,
                            ecosystem="npm",
                            dependency_path=["<root>", f"{dep_name}@{dep_ver}"],
                            severity=Severity.MEDIUM,
                            risk_level=RiskLevel.UNASSESSED,
                            source_tool="guardian-change-detector",
                            description=f"Package '{dep_name}' uses unpinned version '{dep_ver}'. Non-reproducible builds increase risk of automated dependency compromise.",
                            confidence="high",
                            evidence={
                                "manifest": "package.json",
                                "declared_version": dep_ver,
                                "risk_factor": "unpinned_dynamic_version",
                            },
                        ))

                # Check suspicious / install scripts
                scripts = data.get("scripts", {})
                for script_name, script_cmd in scripts.items():
                    if script_name in {"preinstall", "postinstall", "install"}:
                        findings.append(Finding(
                            finding_type=FindingType.INSTALL_SCRIPT,
                            component_name=context.repo_name or "root",
                            component_version="1.0.0",
                            ecosystem="npm",
                            severity=Severity.HIGH,
                            risk_level=RiskLevel.UNASSESSED,
                            source_tool="guardian-change-detector",
                            description=f"Automated execution hook '{script_name}' detected: '{script_cmd}'. Lifecycle scripts execute automatically during installation.",
                            confidence="high",
                            evidence={
                                "script_name": script_name,
                                "command": script_cmd,
                                "file": "package.json",
                            },
                        ))

            except Exception as exc:
                errors.append(f"Failed parsing package.json: {exc}")

        # 2. Inspect Dockerfile for base image risks
        dockerfile = repo_path / "Dockerfile"
        if dockerfile.exists():
            try:
                lines = dockerfile.read_text(encoding="utf-8").splitlines()
                for idx, line in enumerate(lines, 1):
                    line_clean = line.strip()
                    if line_clean.startswith("FROM ") and not line_clean.startswith("#"):
                        image = line_clean.split("FROM ")[1].strip()
                        findings.append(Finding(
                            finding_type=FindingType.UNTRUSTED_IMAGE,
                            component_name=image.split(":")[0],
                            component_version=image.split(":")[1] if ":" in image else "latest",
                            ecosystem="docker",
                            severity=Severity.MEDIUM,
                            risk_level=RiskLevel.UNASSESSED,
                            source_tool="guardian-change-detector",
                            description=f"Container base image declared: '{image}'. Base images inherit OS package vulnerabilities and must be pinned with digest.",
                            confidence="medium",
                            evidence={
                                "dockerfile": "Dockerfile",
                                "line_number": idx,
                                "instruction": line_clean,
                                "base_image": image,
                            },
                        ))
            except Exception as exc:
                errors.append(f"Failed parsing Dockerfile: {exc}")

        # 3. Inspect GitHub Workflows for untrusted actions
        ci_dir = repo_path / ".github" / "workflows"
        if ci_dir.is_dir():
            for wf in ci_dir.glob("*.yml"):
                try:
                    content = wf.read_text(encoding="utf-8")
                    for line in content.splitlines():
                        if "uses:" in line and not line.strip().startswith("#"):
                            action = line.split("uses:")[1].strip()
                            # Check if action uses commit SHA or mutable tag
                            if "@" in action and len(action.split("@")[1]) != 40:
                                findings.append(Finding(
                                    finding_type=FindingType.UNSAFE_CI,
                                    component_name=action.split("@")[0],
                                    component_version=action.split("@")[1],
                                    ecosystem="github-action",
                                    severity=Severity.LOW,
                                    risk_level=RiskLevel.UNASSESSED,
                                    source_tool="guardian-change-detector",
                                    description=f"CI workflow '{wf.name}' uses mutable action tag '{action}'. Actions should be pinned to immutable commit SHAs.",
                                    confidence="medium",
                                    evidence={
                                        "workflow_file": wf.name,
                                        "action_reference": action,
                                    },
                                ))
                                break  # Flag once per workflow
                except Exception:
                    pass

        metadata = {
            "signals_detected": len(findings),
            "signal_types": list({f.finding_type.value for f in findings}),
        }

        return AgentResult(
            agent_name=self.name,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

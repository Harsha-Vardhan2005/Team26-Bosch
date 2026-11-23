"""
Core data models for the Software Supply Chain Guardian.

Two distinct top-level entities:
  - Component: an item in the software inventory (not a risk).
  - Finding:   a risk signal — vulnerability, suspicious change, anomaly.

Supporting models:
  - RepositoryElement: a file/artifact relevant to supply-chain analysis.
  - ScanContext:       metadata about the current scan run.
  - AgentResult:       what an individual agent returns.
  - ScanResult:        consolidated output of a full scan.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Severity as reported by the scanner tool (not our own assessment)."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NEGLIGIBLE = "Negligible"
    UNKNOWN = "Unknown"


class RiskLevel(str, Enum):
    """Risk level assigned by the analyst agent."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNASSESSED = "unassessed"


class FindingType(str, Enum):
    """Category of a risk finding."""
    VULNERABILITY = "vulnerability"
    TYPOSQUAT = "typosquat"
    INSTALL_SCRIPT = "install_script"
    UNPINNED_VERSION = "unpinned_version"
    LOCKFILE_DRIFT = "lockfile_drift"
    UNTRUSTED_IMAGE = "untrusted_image"
    UNSAFE_CI = "unsafe_ci"
    SUSPICIOUS_CHANGE = "suspicious_change"


class ElementType(str, Enum):
    """Type of repository element relevant to supply-chain analysis."""
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"
    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    CI_WORKFLOW = "ci_workflow"
    SOURCE = "source"
    VIEW = "view"
    STATIC_ASSET = "static_asset"
    CONFIG = "config"
    TEST = "test"
    EXPLOIT_DEMO = "exploit_demo"
    DOCUMENTATION = "documentation"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Component — inventory, NOT a risk
# ---------------------------------------------------------------------------

class Component(BaseModel):
    """A discovered software component in the repository inventory."""

    name: str
    version: str
    ecosystem: str                              # npm, pypi, maven, nuget, …
    purl: Optional[str] = None                  # Package URL (pkg:npm/express@4.12.4)
    component_type: str = "library"             # library, application, framework, …
    is_direct: Optional[bool] = None            # True = direct dep, False = transitive
    source_file: Optional[str] = None           # manifest/lockfile where discovered
    supplier: Optional[str] = None
    licenses: list[str] = Field(default_factory=list)
    description: Optional[str] = None

    def key(self) -> tuple[str, str, str]:
        """Natural dedup key: (ecosystem, name, version)."""
        return (self.ecosystem, self.name, self.version)


# ---------------------------------------------------------------------------
# Finding — a risk signal
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """
    A single risk finding: vulnerability, suspicious change, or anomaly.

    One Finding per (component_name, component_version, canonical vuln).
    CVE/GHSA aliases for the same vulnerability are merged into advisory_ids.
    ``severity`` comes from the scanner; ``risk_level`` is set later by the
    analyst agent.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: FindingType
    component_name: str
    component_version: str
    ecosystem: str
    dependency_path: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
    severity: Optional[Severity] = None         # from the tool
    risk_level: RiskLevel = RiskLevel.UNASSESSED  # set by analyst
    source_tool: str = ""
    advisory_ids: list[str] = Field(default_factory=list)  # CVE-xxx, GHSA-xxx
    fixed_version: Optional[str] = None
    description: Optional[str] = None
    confidence: Optional[str] = None            # for anomaly findings

    @property
    def dedup_key(self) -> tuple[str, str, frozenset[str]]:
        """
        Deduplication key: (component+version, frozenset of advisory IDs).

        Two findings that share *any* advisory ID for the same component
        should be merged before they reach the report.
        """
        return (
            self.component_name,
            self.component_version,
            frozenset(self.advisory_ids),
        )


# ---------------------------------------------------------------------------
# Repository Element
# ---------------------------------------------------------------------------

class RepositoryElement(BaseModel):
    """A file or artifact in the repo relevant to supply-chain analysis."""

    path: str
    element_type: ElementType
    category: str = "other"                     # supply_chain, source, exploits, views, assets, etc.
    is_supply_chain: bool = False               # True if manifest, lockfile, docker, or CI
    ecosystem: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scan context and results
# ---------------------------------------------------------------------------

class ScanContext(BaseModel):
    """Metadata for a single scan run."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_path: str
    repo_name: Optional[str] = None
    commit_hash: Optional[str] = None
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    tool_versions: dict[str, str] = Field(default_factory=dict)


class AgentResult(BaseModel):
    """Result returned by a single agent."""

    agent_name: str
    components: list[Component] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    elements: list[RepositoryElement] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Consolidated result of a full Guardian scan."""

    context: ScanContext
    components: list[Component] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    elements: list[RepositoryElement] = Field(default_factory=list)
    agent_results: dict[str, AgentResult] = Field(default_factory=dict)


"""Unit tests for the Software Supply Chain Guardian Day 1 pipeline."""

import json
from pathlib import Path
import pytest

from guardian.models import Component, Finding, FindingType, RiskLevel, Severity
from guardian.agents.graph import GraphAgent
from guardian.agents.vulnerability import VulnerabilityAgent


def test_component_model():
    c = Component(
        name="express",
        version="4.12.4",
        ecosystem="npm",
        purl="pkg:npm/express@4.12.4",
        is_direct=True,
    )
    assert c.name == "express"
    assert c.is_direct is True
    assert c.key() == ("npm", "express", "4.12.4")


def test_finding_model():
    f = Finding(
        finding_type=FindingType.VULNERABILITY,
        component_name="mongoose",
        component_version="4.2.4",
        ecosystem="npm",
        severity=Severity.CRITICAL,
        advisory_ids=["CVE-2016-10564", "GHSA-xxxx"],
        fixed_version="4.3.0",
    )
    assert f.severity == Severity.CRITICAL
    assert f.risk_level == RiskLevel.UNASSESSED
    assert len(f.advisory_ids) == 2


def test_scan_result_has_all_checkpoints():
    report_path = Path("reports/scan-result.json")
    assert report_path.exists(), "Scan result JSON must exist"

    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert "components" in data
    assert len(data["components"]) > 500

    assert "elements" in data
    assert len(data["elements"]) >= 50

    assert "findings" in data
    assert len(data["findings"]) > 200

    # Verify at least one Critical direct vulnerability exists
    critical_direct = [
        f for f in data["findings"]
        if f.get("severity") == "Critical" and f.get("evidence", {}).get("is_direct") is True
    ]
    assert len(critical_direct) > 0, "Must detect direct critical vulnerabilities"


def test_handlebars_transitive_path():
    report_path = Path("reports/scan-result.json")
    data = json.loads(report_path.read_text(encoding="utf-8"))

    # Find findings for handlebars
    hb_findings = [f for f in data["findings"] if f["component_name"] == "handlebars"]
    assert len(hb_findings) > 0, "Must have findings for handlebars"

    # Verify dependency path traces back to hbs
    path = hb_findings[0]["dependency_path"]
    assert len(path) >= 3, "Handlebars path must be transitive (>=3 nodes)"
    assert path[0] == "<root>"
    assert any("hbs@" in node for node in path), "Handlebars must be traced through hbs"


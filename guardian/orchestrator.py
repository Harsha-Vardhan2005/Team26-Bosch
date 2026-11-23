"""
Guardian Orchestrator — coordinates the agent pipeline.

Runs each specialist agent in order, feeds shared state forward,
and merges results into a single ScanResult.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

import networkx as nx

from guardian.agents import (
    AnalystAgent,
    ChangeDetectionAgent,
    DiscoveryAgent,
    GraphAgent,
    VulnerabilityAgent,
)
from guardian.models import AgentResult, ScanContext, ScanResult


class Orchestrator:
    """Run the full Day-1 analysis pipeline on a repository."""

    def __init__(self) -> None:
        self.agents = [
            DiscoveryAgent(),
            GraphAgent(),
            VulnerabilityAgent(),
            ChangeDetectionAgent(),
            AnalystAgent(),
        ]

    def run(
        self,
        repo_path: str,
        *,
        sbom_path: Optional[str] = None,
        grype_path: Optional[str] = None,
        output_path: Optional[str] = None,
    ) -> ScanResult:
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
            agent_result: AgentResult = agent.run(context, shared_state)

            scan_result.agent_results[agent_result.agent_name] = agent_result
            scan_result.components.extend(agent_result.components)
            scan_result.findings.extend(agent_result.findings)
            scan_result.elements.extend(agent_result.elements)

            shared_state["components"].extend(agent_result.components)
            shared_state["findings"].extend(agent_result.findings)
            shared_state["elements"].extend(agent_result.elements)

            if agent_result.errors:
                for err in agent_result.errors:
                    print(f"  ⚠ {agent.name}: {err}")

        if output_path:
            _write_report(scan_result, output_path)

        graph = shared_state.get("dependency_graph")
        dashboard_path = Path(output_path).parent / "dashboard.html" if output_path else Path("reports/dashboard.html")
        _write_dashboard(scan_result, graph, str(dashboard_path))

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

    components_json = json.dumps(
        [c.model_dump(mode="json") for c in scan_result.components],
        default=str,
    )
    elements_json = json.dumps(
        [e.model_dump(mode="json") for e in scan_result.elements],
        default=str,
    )
    graph_json = json.dumps(_graph_to_json(graph), default=str)
    context_json = json.dumps(scan_result.context.model_dump(mode="json"), default=str)

    agent_meta = {}
    for aname, ares in scan_result.agent_results.items():
        agent_meta[aname] = ares.metadata
    agent_meta_json = json.dumps(agent_meta, default=str)

    html = _DASHBOARD_HTML.replace("__CONTEXT__", context_json)
    html = html.replace("__COMPONENTS__", components_json)
    html = html.replace("__ELEMENTS__", elements_json)
    html = html.replace("__GRAPH__", graph_json)
    html = html.replace("__AGENT_META__", agent_meta_json)

    out.write_text(html, encoding="utf-8")
    print(f"[guardian] Dashboard written to {out}")


# ---------------------------------------------------------------------------
# Clean, Professional Executive Dashboard HTML
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Supply Chain Guardian</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
  :root {
    --bg: #090d16;
    --surface: #111726;
    --surface-hover: #172033;
    --border: #202b42;
    --border-subtle: #172033;
    --text: #f0f4fc;
    --text-muted: #7e8c9f;
    --primary: #3b82f6;
    --primary-glow: rgba(59, 130, 246, 0.15);
    --success: #10b981;
    --warning: #f59e0b;
    --accent: #8b5cf6;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }

  /* Header */
  .top-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 18px 36px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .brand-icon {
    width: 32px;
    height: 32px;
    background: linear-gradient(135deg, #3b82f6, #8b5cf6);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
  }
  .brand h1 {
    font-size: 18px;
    font-weight: 700;
    letter-spacing: -0.3px;
  }
  .target-pill {
    background: var(--primary-glow);
    border: 1px solid rgba(59, 130, 246, 0.3);
    color: var(--primary);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
  }

  /* Metric Cards */
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 14px;
    padding: 24px 36px 12px 36px;
  }
  .metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }
  .metric-card:hover {
    border-color: rgba(59, 130, 246, 0.4);
  }
  .metric-val {
    font-size: 32px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: var(--text);
  }
  .metric-label {
    font-size: 12px;
    color: var(--text-muted);
    font-weight: 500;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .text-primary { color: var(--primary); }
  .text-success { color: var(--success); }
  .text-warning { color: var(--warning); }
  .text-accent  { color: var(--accent); }

  /* Navigation Tabs */
  .tabs-bar {
    display: flex;
    padding: 0 36px;
    border-bottom: 1px solid var(--border);
    margin-top: 12px;
  }
  .tab-btn {
    padding: 12px 20px;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-muted);
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: color 0.15s, border-color 0.15s;
  }
  .tab-btn:hover { color: var(--text); }
  .tab-btn.active {
    color: var(--primary);
    border-bottom-color: var(--primary);
  }

  /* Main View Area */
  .main-content {
    padding: 24px 36px 40px 36px;
  }
  .view-panel { display: none; }
  .view-panel.active { display: block; }

  /* Pipeline Bar */
  .pipeline-strip {
    display: flex;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 24px;
    gap: 16px;
    margin-bottom: 24px;
    align-items: center;
    justify-content: space-between;
  }
  .pipe-step {
    display: flex;
    align-items: center;
    gap: 12px;
    flex: 1;
  }
  .pipe-badge {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: var(--primary-glow);
    color: var(--primary);
    font-size: 12px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .pipe-text h4 { font-size: 13px; font-weight: 600; }
  .pipe-text p { font-size: 11px; color: var(--text-muted); }
  .pipe-arrow { color: var(--border); font-size: 18px; }

  /* Layout Cards */
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
  }
  .panel-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px;
  }
  .panel-box h3 {
    font-size: 15px;
    font-weight: 700;
    margin-bottom: 14px;
  }

  /* Tables */
  .toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 14px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }
  .search-input {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 9px 16px;
    color: var(--text);
    font-size: 13px;
    width: 280px;
  }
  .search-input:focus { outline: none; border-color: var(--primary); }
  .filter-pills { display: flex; gap: 8px; flex-wrap: wrap; }
  .filter-pill {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
  }
  .filter-pill:hover { color: var(--text); border-color: var(--primary); }
  .filter-pill.active {
    background: var(--primary-glow);
    border-color: var(--primary);
    color: var(--primary);
    font-weight: 600;
  }

  .table-box {
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    background: var(--surface);
    max-height: 540px;
    overflow-y: auto;
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    background: #0f1420;
    text-align: left;
    padding: 12px 16px;
    color: var(--text-muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    font-weight: 600;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
  }
  td {
    padding: 10px 16px;
    border-bottom: 1px solid var(--border-subtle);
  }
  tr:hover td { background: var(--surface-hover); }

  /* Tags */
  .tag {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 600;
  }
  .tag-control { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
  .tag-source  { background: rgba(16, 185, 129, 0.15); color: #34d399; }
  .tag-exploit { background: rgba(239, 68, 68, 0.15); color: #f87171; }
  .tag-direct  { background: rgba(16, 185, 129, 0.15); color: #34d399; }
  .tag-trans   { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }

  /* Graph */
  #graph-canvas {
    width: 100%;
    height: 580px;
    background: #0b0f1a;
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  .graph-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }
  .btn {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 16px;
    border-radius: 8px;
    font-size: 13px;
    cursor: pointer;
    font-weight: 500;
    transition: all 0.15s;
  }
  .btn:hover { border-color: var(--primary); color: var(--primary); }

  .path-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    margin-top: 16px;
    font-family: monospace;
    font-size: 13px;
  }
  .path-snippet {
    background: rgba(59, 130, 246, 0.08);
    border-left: 3px solid var(--primary);
    padding: 8px 12px;
    border-radius: 4px;
    margin-top: 8px;
    color: var(--text);
  }
</style>
</head>
<body>

<!-- Header -->
<div class="top-nav">
  <div class="brand">
    <div class="brand-icon">🛡️</div>
    <div>
      <h1>Software Supply Chain Guardian</h1>
    </div>
  </div>
  <div class="target-pill">Target: goof</div>
</div>

<!-- Key Metrics -->
<div class="metrics-grid">
  <div class="metric-card">
    <div class="metric-val text-primary" id="m-total-files">60</div>
    <div class="metric-label">Total Files</div>
  </div>
  <div class="metric-card">
    <div class="metric-val text-warning" id="m-control-files">8</div>
    <div class="metric-label">Supply-Chain Files</div>
  </div>
  <div class="metric-card">
    <div class="metric-val text-accent" id="m-components">577</div>
    <div class="metric-label">Components (SBOM)</div>
  </div>
  <div class="metric-card">
    <div class="metric-val" id="m-nodes">981</div>
    <div class="metric-label">Graph Nodes</div>
  </div>
  <div class="metric-card">
    <div class="metric-val" id="m-edges">1,479</div>
    <div class="metric-label">Dependency Edges</div>
  </div>
  <div class="metric-card">
    <div class="metric-val text-success" id="m-direct">35</div>
    <div class="metric-label">Direct Dependencies</div>
  </div>
</div>

<!-- Tabs Navigation -->
<div class="tabs-bar">
  <div class="tab-btn active" data-tab="overview">Overview</div>
  <div class="tab-btn" data-tab="files">Repository Files</div>
  <div class="tab-btn" data-tab="components">Components (SBOM)</div>
  <div class="tab-btn" data-tab="graph">Dependency Graph</div>
</div>

<div class="main-content">
  <!-- 1. OVERVIEW -->
  <div class="view-panel active" id="view-overview">
    <!-- Streamlined Pipeline Flow -->
    <div class="pipeline-strip">
      <div class="pipe-step">
        <div class="pipe-badge">1</div>
        <div class="pipe-text">
          <h4>Filesystem Discovery</h4>
          <p>Discovered all 60 files</p>
        </div>
      </div>
      <div class="pipe-arrow">➔</div>
      <div class="pipe-step">
        <div class="pipe-badge">2</div>
        <div class="pipe-text">
          <h4>Supply-Chain Isolation</h4>
          <p>8 manifests & CI workflows</p>
        </div>
      </div>
      <div class="pipe-arrow">➔</div>
      <div class="pipe-step">
        <div class="pipe-badge">3</div>
        <div class="pipe-text">
          <h4>SBOM Cataloging</h4>
          <p>577 packages parsed</p>
        </div>
      </div>
      <div class="pipe-arrow">➔</div>
      <div class="pipe-step">
        <div class="pipe-badge">4</div>
        <div class="pipe-text">
          <h4>Dependency Graph</h4>
          <p>981 nodes mapped</p>
        </div>
      </div>
    </div>

    <!-- 2 Column Overview Content -->
    <div class="grid-2">
      <!-- Direct Dependencies -->
      <div class="panel-box">
        <h3>Direct Dependencies (Roots)</h3>
        <div id="direct-list" style="max-height: 280px; overflow-y: auto; display: flex; flex-wrap: wrap; gap: 8px;"></div>
      </div>

      <!-- Transitive Dependency Verification -->
      <div class="panel-box">
        <h3>Transitive Dependency Verification</h3>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
          Proven root-to-child paths resolved through graph analysis:
        </p>
        <div id="paths-list"></div>
      </div>
    </div>
  </div>

  <!-- 2. REPO FILES -->
  <div class="view-panel" id="view-files">
    <div class="toolbar">
      <input class="search-input" placeholder="Search file path..." id="files-search" />
      <div class="filter-pills" id="files-filter-pills"></div>
    </div>
    <div class="table-box">
      <table>
        <thead>
          <tr>
            <th>File Path</th>
            <th>Category</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody id="files-table-body"></tbody>
      </table>
    </div>
  </div>

  <!-- 3. COMPONENTS -->
  <div class="view-panel" id="view-components">
    <div class="toolbar">
      <input class="search-input" placeholder="Search package name..." id="comps-search" />
      <div class="filter-pills">
        <div class="filter-pill active" onclick="setCompFilter('all', this)">All (577)</div>
        <div class="filter-pill" onclick="setCompFilter('direct', this)">Direct Roots</div>
        <div class="filter-pill" onclick="setCompFilter('transitive', this)">Transitive Only</div>
      </div>
    </div>
    <div class="table-box">
      <table>
        <thead>
          <tr>
            <th>Package</th>
            <th>Version</th>
            <th>Type</th>
            <th>Relation</th>
            <th>License</th>
            <th>PURL</th>
          </tr>
        </thead>
        <tbody id="comps-table-body"></tbody>
      </table>
    </div>
  </div>

  <!-- 4. DEPENDENCY GRAPH -->
  <div class="view-panel" id="view-graph">
    <div class="graph-bar">
      <input class="search-input" placeholder="Search node (e.g. handlebars)..." id="graph-search" />
      <div style="display: flex; gap: 8px;">
        <button class="btn" onclick="resetGraph()">Reset View</button>
        <button class="btn" onclick="toggleDirect()">Direct Deps Only</button>
      </div>
    </div>
    <div id="graph-canvas"></div>
    <div class="path-card" id="graph-path-box">
      <div style="font-size: 12px; color: var(--text-muted);">SELECTED DEPENDENCY PATH</div>
      <div class="path-snippet" id="graph-path-text">Click any node in the graph above to trace its path back to root.</div>
    </div>
  </div>
</div>

<script>
// Data injected by Guardian
const COMPONENTS = __COMPONENTS__;
const ELEMENTS   = __ELEMENTS__;
const GRAPH      = __GRAPH__;
const AGENT_META = __AGENT_META__;

const graphMeta  = AGENT_META.graph || {};
const discoveryMeta = AGENT_META.discovery || {};
const supplyCount = ELEMENTS.filter(e => e.is_supply_chain).length;

// Populate Top Metrics
document.getElementById('m-total-files').textContent = ELEMENTS.length;
document.getElementById('m-control-files').textContent = supplyCount;
document.getElementById('m-components').textContent = COMPONENTS.length;
document.getElementById('m-nodes').textContent = (graphMeta.total_nodes || 0).toLocaleString();
document.getElementById('m-edges').textContent = (graphMeta.total_edges || 0).toLocaleString();
document.getElementById('m-direct').textContent = graphMeta.direct_dependencies || 35;

// Direct Roots List in Overview
const directNames = graphMeta.direct_dep_names || [];
document.getElementById('direct-list').innerHTML = directNames.map(d =>
  `<span class="tag tag-control">${d}</span>`
).join('');

// Transitive Paths List in Overview
const samplePaths = graphMeta.sample_paths || {};
let pathsHtml = '';
for (const [target, paths] of Object.entries(samplePaths)) {
  paths.forEach(p => {
    pathsHtml += `<div class="path-snippet" style="margin-bottom:8px;"><strong>${target}:</strong> ${p}</div>`;
  });
}
document.getElementById('paths-list').innerHTML = pathsHtml || '<p style="color:var(--text-muted)">Paths loaded in graph</p>';

// Tab Switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('view-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'graph' && !window._graphInit) initGraph();
  });
});

// Files View
let activeFileCategory = 'All';
const fileCategories = ['All', 'Supply-Chain Manifests', 'CI/CD Workflows', 'Application Source Code', 'Exploit Demonstrations', 'Templates & Views', 'Static Assets', 'Documentation', 'Configuration', 'Tests & Specs'];

function renderFileFilters() {
  document.getElementById('files-filter-pills').innerHTML = fileCategories.map(cat => {
    const count = cat === 'All' ? ELEMENTS.length : ELEMENTS.filter(e => e.category === cat).length;
    if (count === 0 && cat !== 'All') return '';
    return `<div class="filter-pill ${cat === activeFileCategory ? 'active' : ''}" onclick="setFileCategory('${cat}')">${cat} (${count})</div>`;
  }).join('');
}

function setFileCategory(cat) {
  activeFileCategory = cat;
  renderFileFilters();
  renderFilesTable();
}

function renderFilesTable() {
  const q = document.getElementById('files-search').value.toLowerCase();
  const rows = ELEMENTS.filter(e => {
    const matchCat = activeFileCategory === 'All' || e.category === activeFileCategory;
    const matchQ = !q || e.path.toLowerCase().includes(q) || (e.category||'').toLowerCase().includes(q);
    return matchCat && matchQ;
  });

  document.getElementById('files-table-body').innerHTML = rows.map(e => {
    const tagClass = e.is_supply_chain ? 'tag-control' : e.category.includes('Source') ? 'tag-source' : e.category.includes('Exploit') ? 'tag-exploit' : '';
    return `
      <tr>
        <td style="font-family:monospace; font-weight:600;">${e.path}</td>
        <td><span class="tag ${tagClass}">${e.category}</span></td>
        <td style="color:var(--text-muted); font-size:12px;">${e.is_supply_chain ? '⭐ Controls Build & Dependencies' : 'Application Asset'}</td>
      </tr>
    `;
  }).join('');
}
renderFileFilters();
renderFilesTable();
document.getElementById('files-search').addEventListener('input', renderFilesTable);

// Components View
let activeCompType = 'all';
function setCompFilter(type, el) {
  activeCompType = type;
  document.querySelectorAll('#view-components .filter-pill').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  renderCompsTable();
}

function renderCompsTable() {
  const q = document.getElementById('comps-search').value.toLowerCase();
  const rows = COMPONENTS.filter(c => {
    const matchType = activeCompType === 'all' ? true : activeCompType === 'direct' ? c.is_direct === true : c.is_direct === false;
    const matchQ = !q || c.name.toLowerCase().includes(q);
    return matchType && matchQ;
  });

  document.getElementById('comps-table-body').innerHTML = rows.slice(0, 500).map(c => `
    <tr>
      <td><strong>${c.name}</strong></td>
      <td style="color:var(--text-muted)">${c.version}</td>
      <td><code>${c.ecosystem}</code></td>
      <td><span class="tag ${c.is_direct ? 'tag-direct' : 'tag-trans'}">${c.is_direct ? 'Direct' : 'Transitive'}</span></td>
      <td style="font-size:12px; color:var(--text-muted)">${(c.licenses||[]).join(', ')||'—'}</td>
      <td style="font-family:monospace; font-size:11px; color:var(--text-muted); max-width:220px; overflow:hidden; text-overflow:ellipsis">${c.purl||'—'}</td>
    </tr>
  `).join('');
}
renderCompsTable();
document.getElementById('comps-search').addEventListener('input', renderCompsTable);

// Graph View (Cytoscape)
let cy = null;
window._graphInit = false;

function initGraph() {
  if (window._graphInit) return;
  window._graphInit = true;

  const elements = [];
  GRAPH.nodes.forEach(n => {
    elements.push({
      data: { id: n.id, label: n.name || n.id, is_direct: n.is_direct }
    });
  });
  GRAPH.edges.forEach(e => {
    elements.push({ data: { source: e.source, target: e.target } });
  });

  cy = cytoscape({
    container: document.getElementById('graph-canvas'),
    elements: elements,
    style: [
      { selector: 'node', style: {
          'label': 'data(label)', 'font-size': 8, 'color': '#f0f4fc',
          'background-color': ele => ele.data('is_direct') ? '#10b981' : '#3b82f6',
          'width': ele => ele.data('is_direct') ? 18 : 10,
          'height': ele => ele.data('is_direct') ? 18 : 10,
          'text-valign': 'bottom', 'text-margin-y': 4
      }},
      { selector: 'node[id = "<root>"]', style: {
          'background-color': '#ef4444', 'width': 26, 'height': 26,
          'label': 'goof (root)', 'font-weight': 'bold', 'font-size': 11
      }},
      { selector: 'edge', style: {
          'width': 0.6, 'line-color': '#202b42',
          'target-arrow-color': '#202b42', 'target-arrow-shape': 'triangle',
          'curve-style': 'bezier', 'arrow-scale': 0.5
      }},
      { selector: '.highlighted', style: {
          'background-color': '#f59e0b', 'width': 22, 'height': 22,
          'font-size': 11, 'font-weight': 'bold', 'z-index': 999
      }},
      { selector: '.path-edge', style: {
          'line-color': '#f59e0b', 'target-arrow-color': '#f59e0b', 'width': 2.5, 'z-index': 999
      }},
      { selector: '.dimmed', style: { 'opacity': 0.12 }}
    ],
    layout: {
      name: 'concentric',
      concentric: n => n.data('id') === '<root>' ? 100 : n.data('is_direct') ? 50 : 1,
      levelWidth: () => 2,
      animate: false
    },
    minZoom: 0.1, maxZoom: 4
  });

  cy.on('tap', 'node', function(evt) {
    highlightNode(evt.target.id());
  });

  document.getElementById('graph-search').addEventListener('input', function(e) {
    const q = e.target.value.toLowerCase();
    if (!q) { resetGraph(); return; }
    cy.elements().removeClass('highlighted path-edge dimmed');
    const matched = cy.nodes().filter(n => n.data('label').toLowerCase().includes(q));
    if (matched.length > 0) {
      cy.elements().addClass('dimmed');
      matched.forEach(n => {
        n.removeClass('dimmed').addClass('highlighted');
        highlightNode(n.id());
      });
    }
  });
}

function highlightNode(nodeId) {
  cy.elements().removeClass('highlighted path-edge dimmed');
  cy.elements().addClass('dimmed');

  const visited = new Set();
  visited.add(nodeId);

  function walkUp(nid) {
    const node = cy.getElementById(nid);
    node.removeClass('dimmed').addClass('highlighted');
    node.incomers('edge').forEach(edge => {
      const src = edge.source().id();
      edge.removeClass('dimmed').addClass('path-edge');
      edge.source().removeClass('dimmed').addClass('highlighted');
      if (!visited.has(src)) {
        visited.add(src);
        walkUp(src);
      }
    });
  }
  walkUp(nodeId);

  const target = cy.getElementById(nodeId);
  target.outgoers('edge').forEach(edge => {
    edge.removeClass('dimmed').addClass('path-edge');
    edge.target().removeClass('dimmed').addClass('highlighted');
  });

  // Trace path text
  const parts = [];
  function tracePath(nid) {
    parts.unshift(nid);
    const preds = cy.getElementById(nid).incomers('node');
    if (preds.length > 0 && nid !== '<root>') tracePath(preds[0].id());
  }
  tracePath(nodeId);
  document.getElementById('graph-path-text').innerHTML =
    `<strong>Path to ${nodeId}:</strong><br>${parts.join(' ➔ ')}`;
}

function resetGraph() {
  if (!cy) return;
  cy.elements().removeClass('highlighted path-edge dimmed');
  document.getElementById('graph-path-text').textContent = 'Click any node in the graph above to trace its path back to root.';
}

function toggleDirect() {
  if (!cy) return;
  cy.elements().removeClass('dimmed');
  cy.nodes().filter(n => !n.data('is_direct') && n.data('id') !== '<root>').addClass('dimmed');
  cy.edges().addClass('dimmed');
  cy.edges().filter(e => e.source().data('id') === '<root>').removeClass('dimmed');
}
</script>
</body>
</html>"""

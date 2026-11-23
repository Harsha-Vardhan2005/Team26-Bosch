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

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        repo_path: str,
        *,
        sbom_path: Optional[str] = None,
        grype_path: Optional[str] = None,
        output_path: Optional[str] = None,
    ) -> ScanResult:
        """
        Execute all agents against *repo_path* and return a ScanResult.

        Parameters
        ----------
        repo_path : str
            Local path to the repository to analyse.
        sbom_path : str, optional
            Pre-generated CycloneDX SBOM file (skips Syft).
        grype_path : str, optional
            Pre-generated Grype results file (skips Grype).
        output_path : str, optional
            Where to write the final JSON report.
        """
        repo_path = str(Path(repo_path).resolve())

        context = ScanContext(
            repo_path=repo_path,
            repo_name=Path(repo_path).name,
            commit_hash=_detect_commit(repo_path),
        )

        # Shared mutable state passed between agents in pipeline order.
        shared_state: dict = {
            "sbom_path": sbom_path,
            "grype_path": grype_path,
            "sbom_data": None,
            "grype_data": None,
            "components": [],
            "findings": [],
            "elements": [],
            "dependency_graph": None,  # NetworkX DiGraph, set by GraphAgent
        }

        scan_result = ScanResult(context=context)

        for agent in self.agents:
            print(f"[guardian] Running {agent.name} agent …")
            agent_result: AgentResult = agent.run(context, shared_state)

            # Store per-agent result
            scan_result.agent_results[agent_result.agent_name] = agent_result

            # Accumulate into consolidated result
            scan_result.components.extend(agent_result.components)
            scan_result.findings.extend(agent_result.findings)
            scan_result.elements.extend(agent_result.elements)

            # Feed forward into shared state for the next agent
            shared_state["components"].extend(agent_result.components)
            shared_state["findings"].extend(agent_result.findings)
            shared_state["elements"].extend(agent_result.elements)

            if agent_result.errors:
                for err in agent_result.errors:
                    print(f"  ⚠ {agent.name}: {err}")

        # Write report if requested
        if output_path:
            _write_report(scan_result, output_path)

        # Always generate the dashboard
        graph = shared_state.get("dependency_graph")
        dashboard_path = Path(output_path).parent / "dashboard.html" if output_path else Path("reports/dashboard.html")
        _write_dashboard(scan_result, graph, str(dashboard_path))

        return scan_result


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _detect_commit(repo_path: str) -> Optional[str]:
    """Try to read the current HEAD commit from a git repo."""
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
    """Serialise the ScanResult to JSON."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(scan_result.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )
    print(f"[guardian] Report written to {out}")


def _graph_to_json(graph: Optional[nx.DiGraph]) -> dict:
    """Convert a NetworkX DiGraph to a JSON-serializable dict for the dashboard."""
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
    """Generate an interactive HTML dashboard."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Prepare data for the dashboard
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

    # Agent metadata
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
# Dashboard HTML template (single self-contained file)
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Supply Chain Guardian — Day 1 Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #e6edf3; --text2: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --orange: #d29922; --purple: #bc8cff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.5; }
  .header { background: linear-gradient(135deg, #1a1f36 0%, #0d1117 100%);
            border-bottom: 1px solid var(--border); padding: 24px 32px; }
  .header h1 { font-size: 24px; font-weight: 600; }
  .header h1 span { color: var(--accent); }
  .header .meta { color: var(--text2); font-size: 13px; margin-top: 6px; }
  .stats { display: flex; gap: 12px; padding: 20px 32px; flex-wrap: wrap; }
  .stat-card { background: var(--card); border: 1px solid var(--border);
               border-radius: 8px; padding: 14px 18px; min-width: 140px; flex: 1; }
  .stat-card .value { font-size: 28px; font-weight: 700; }
  .stat-card .label { color: var(--text2); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
  .stat-card.green .value { color: var(--green); }
  .stat-card.blue .value { color: var(--accent); }
  .stat-card.orange .value { color: var(--orange); }
  .stat-card.purple .value { color: var(--purple); }
  .stat-card.red .value { color: var(--red); }
  .tabs { display: flex; border-bottom: 1px solid var(--border); padding: 0 32px; }
  .tab { padding: 10px 20px; cursor: pointer; color: var(--text2); font-size: 14px;
         border-bottom: 2px solid transparent; transition: all 0.2s; }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .content { padding: 20px 32px; }
  .panel { display: none; }
  .panel.active { display: block; }
  /* Elements & Components tables */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; background: var(--card); color: var(--text2);
       border-bottom: 1px solid var(--border); position: sticky; top: 0; font-weight: 600;
       text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tr:hover td { background: rgba(88,166,255,0.04); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-npm { background: #cb393520; color: #f97583; }
  .badge-pypi { background: #3572a520; color: #79c0ff; }
  .badge-github { background: #8b949e20; color: #8b949e; }
  .badge-direct { background: #3fb95020; color: #3fb950; }
  .badge-transitive { background: #d2992220; color: #d29922; }
  .badge-supply { background: #58a6ff25; color: #58a6ff; border: 1px solid #58a6ff40; }
  .badge-source { background: #3fb95020; color: #3fb950; }
  .badge-exploit { background: #f8514920; color: #f85149; }
  .badge-test { background: #bc8cff20; color: #bc8cff; }
  .badge-view { background: #e3b34120; color: #e3b341; }
  .badge-asset { background: #8b949e20; color: #8b949e; }
  /* Search & Filter Buttons */
  .toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
  .search-box { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
                padding: 8px 14px; color: var(--text); width: 280px; font-size: 13px; }
  .search-box:focus { outline: none; border-color: var(--accent); }
  .pill-group { display: flex; gap: 6px; flex-wrap: wrap; }
  .pill { background: var(--card); border: 1px solid var(--border); color: var(--text2);
          padding: 5px 12px; border-radius: 20px; font-size: 12px; cursor: pointer; transition: all 0.2s; }
  .pill:hover { border-color: var(--accent); color: var(--text); }
  .pill.active { background: #58a6ff20; border-color: var(--accent); color: var(--accent); font-weight: 600; }
  /* Graph */
  #graph-container { width: 100%; height: 600px; background: var(--card);
                     border: 1px solid var(--border); border-radius: 8px; }
  .graph-controls { display: flex; gap: 10px; margin-bottom: 12px; align-items: center; }
  .graph-controls button { background: var(--card); border: 1px solid var(--border);
                           color: var(--text); padding: 6px 14px; border-radius: 6px;
                           cursor: pointer; font-size: 13px; }
  .graph-controls button:hover { border-color: var(--accent); color: var(--accent); }
  .path-display { background: var(--card); border: 1px solid var(--border);
                  border-radius: 8px; padding: 16px; margin-top: 12px;
                  font-family: monospace; font-size: 13px; white-space: pre-wrap; }
  .path-display .path-item { margin: 4px 0; padding: 6px 10px; background: rgba(88,166,255,0.06);
                             border-radius: 4px; }
  .table-wrapper { max-height: 520px; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px; }
  .info-row { display: flex; gap: 8px; margin: 6px 0; }
  .info-label { color: var(--text2); min-width: 140px; }
  .stage-box { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .stage-num { font-size: 11px; text-transform: uppercase; color: var(--accent); font-weight: 700; letter-spacing: 0.5px; }
  .stage-title { font-size: 15px; font-weight: 600; margin: 4px 0 8px 0; }
  .stage-desc { font-size: 12px; color: var(--text2); }
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ <span>Supply Chain Guardian</span> — Day 1 Dashboard</h1>
  <div class="meta" id="header-meta"></div>
</div>

<div class="stats" id="stats-bar"></div>

<div class="tabs">
  <div class="tab active" data-panel="overview">Overview</div>
  <div class="tab" data-panel="elements">Repo Inventory (<span id="elements-tab-count">0</span>)</div>
  <div class="tab" data-panel="components">Components - SBOM (<span id="components-tab-count">0</span>)</div>
  <div class="tab" data-panel="graph">Dependency Graph</div>
</div>

<div class="content">
  <!-- OVERVIEW -->
  <div class="panel active" id="panel-overview">
    <h2 style="margin-bottom:16px;">Scan Overview & Architecture Pipeline</h2>
    
    <!-- Pipeline Methodology Cards -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:14px;margin-bottom:24px;">
      <div class="stage-box">
        <div class="stage-num">Checkpoint 1A</div>
        <div class="stage-title">Filesystem Discovery</div>
        <div class="stage-desc" id="step1-desc">Walks entire repository tree. Catalogs all source, exploit, test, view, and config files dynamically.</div>
      </div>
      <div class="stage-box">
        <div class="stage-num">Checkpoint 1B</div>
        <div class="stage-title">Supply-Chain Isolation</div>
        <div class="stage-desc" id="step2-desc">Isolates critical control files: manifests, lockfiles, Dockerfiles, and CI/CD automation pipelines.</div>
      </div>
      <div class="stage-box">
        <div class="stage-num">Checkpoint 2</div>
        <div class="stage-title">SBOM Cataloging</div>
        <div class="stage-desc" id="step3-desc">Syft catalogers extract full component inventory, licenses, purls, and direct/transitive metadata.</div>
      </div>
      <div class="stage-box">
        <div class="stage-num">Checkpoint 3</div>
        <div class="stage-title">Dependency Graph</div>
        <div class="stage-desc">NetworkX builds parent-child dependency trees, enabling direct-root path tracing for all transitive components.</div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
      <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;">
        <h3 style="margin-bottom:12px;color:var(--accent);">Repository Metadata</h3>
        <div class="info-row"><span class="info-label">Repository Name:</span> <strong id="meta-repo-name"></strong></div>
        <div class="info-row"><span class="info-label">Git Commit Hash:</span> <code id="meta-commit-hash"></code></div>
        <div class="info-row"><span class="info-label">Ecosystems:</span> <span id="meta-ecosystems"></span></div>
        <div class="info-row"><span class="info-label">SBOM Standard:</span> <span id="meta-sbom-format"></span></div>
        <div class="info-row"><span class="info-label">Syft Catalogers:</span> <span id="meta-syft-catalogers" style="font-size:12px;color:var(--accent)"></span></div>
        <div class="info-row"><span class="info-label">Lockfile Format:</span> <span id="meta-lockfile-ver"></span></div>
      </div>
      <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;">
        <h3 style="margin-bottom:12px;color:var(--accent);">Direct Dependencies (Roots)</h3>
        <div style="max-height:220px;overflow-y:auto;font-size:13px;" id="direct-deps-list"></div>
      </div>
    </div>

    <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-top:20px;">
      <h3 style="margin-bottom:12px;color:var(--accent);">Transitive Dependency Path Tracing (Verification)</h3>
      <div id="sample-paths-container"></div>
    </div>
  </div>

  <!-- ELEMENTS -->
  <div class="panel" id="panel-elements">
    <div class="toolbar">
      <input class="search-box" placeholder="Search files (e.g. Dockerfile, app.js)..." id="elements-search" />
      <div class="pill-group" id="category-pills"></div>
    </div>
    <div class="table-wrapper">
      <table><thead><tr><th>Path</th><th>Category</th><th>Type</th><th>Supply Chain Role</th><th>Ecosystem</th></tr></thead>
      <tbody id="elements-body"></tbody></table>
    </div>
  </div>

  <!-- COMPONENTS -->
  <div class="panel" id="panel-components">
    <div class="toolbar">
      <input class="search-box" placeholder="Search components (e.g. handlebars, lodash)..." id="components-search" />
      <div class="pill-group" id="component-pills">
        <div class="pill active" onclick="filterComponentType('all')">All (<span id="comp-count-all"></span>)</div>
        <div class="pill" onclick="filterComponentType('direct')">Direct Only (<span id="comp-count-direct"></span>)</div>
        <div class="pill" onclick="filterComponentType('transitive')">Transitive Only (<span id="comp-count-transitive"></span>)</div>
      </div>
    </div>
    <div class="table-wrapper">
      <table><thead><tr><th>Name</th><th>Version</th><th>Ecosystem</th><th>Type</th><th>Direct?</th><th>License</th><th>PURL</th></tr></thead>
      <tbody id="components-body"></tbody></table>
    </div>
  </div>

  <!-- GRAPH -->
  <div class="panel" id="panel-graph">
    <div class="graph-controls">
      <input class="search-box" placeholder="Search node (e.g. handlebars)..." id="graph-search" style="margin-bottom:0"/>
      <button onclick="resetGraph()">Reset View</button>
      <button onclick="showDirectOnly()">Direct Deps Only</button>
      <button onclick="showAll()">Show All</button>
      <span style="color:var(--text2);font-size:12px;" id="graph-info"></span>
    </div>
    <div id="graph-container"></div>
    <div class="path-display" id="path-display">
      <strong>Dependency Paths</strong><br>
      Click a node to see its path from root, or search above.
    </div>
  </div>
</div>

<script>
// ---- Injected Data ----
const CTX       = __CONTEXT__;
const COMPONENTS= __COMPONENTS__;
const ELEMENTS  = __ELEMENTS__;
const GRAPH     = __GRAPH__;
const AGENT_META= __AGENT_META__;

const discoveryMeta = AGENT_META.discovery || {};
const graphMeta = AGENT_META.graph || {};
const ecosystems = discoveryMeta.ecosystems_detected || [];
const supplyChainCount = discoveryMeta.supply_chain_files_count || ELEMENTS.filter(e => e.is_supply_chain).length;

// ---- Header ----
document.getElementById('header-meta').innerHTML =
  `Repository: <strong>${CTX.repo_name || 'unknown'}</strong> &nbsp;|&nbsp; ` +
  `Commit: <code>${(CTX.commit_hash||'unknown').slice(0,12)}</code> &nbsp;|&nbsp; ` +
  `Scanned: ${new Date(CTX.scan_timestamp).toLocaleString()}`;

// ---- Tab Counts ----
document.getElementById('elements-tab-count').textContent = ELEMENTS.length;
document.getElementById('components-tab-count').textContent = COMPONENTS.length;

// ---- Stats Bar (Exact 7 Metrics) ----
document.getElementById('stats-bar').innerHTML = `
  <div class="stat-card green"><div class="value">${ELEMENTS.length}</div><div class="label">Total Repo Files</div></div>
  <div class="stat-card blue"><div class="value">${supplyChainCount}</div><div class="label">Supply-Chain Files</div></div>
  <div class="stat-card purple"><div class="value">${COMPONENTS.length}</div><div class="label">Components (SBOM)</div></div>
  <div class="stat-card orange"><div class="value">${graphMeta.total_nodes || 0}</div><div class="label">Graph Nodes</div></div>
  <div class="stat-card"><div class="value">${graphMeta.total_edges || 0}</div><div class="label">Graph Edges</div></div>
  <div class="stat-card"><div class="value">${graphMeta.direct_dependencies || 0}</div><div class="label">Direct Deps</div></div>
  <div class="stat-card"><div class="value">${ecosystems.length}</div><div class="label">Ecosystems</div></div>
`;

// ---- Metadata Fields ----
document.getElementById('meta-repo-name').textContent = CTX.repo_name || 'unknown';
document.getElementById('meta-commit-hash').textContent = CTX.commit_hash || 'unknown';
document.getElementById('meta-ecosystems').textContent = ecosystems.join(', ');
document.getElementById('meta-sbom-format').textContent = `${discoveryMeta.sbom_format || 'CycloneDX'} ${discoveryMeta.sbom_spec_version || ''}`;
document.getElementById('meta-syft-catalogers').textContent = (discoveryMeta.syft_catalogers_verified || []).join(', ') || 'lockfile & actions catalogers';
document.getElementById('meta-lockfile-ver').textContent = `v${graphMeta.lockfile_version || '2'}`;

document.getElementById('step1-desc').textContent = `Walked entire repository tree. Catalogs all ${ELEMENTS.length} files across source, exploits, tests, views, and configs.`;
document.getElementById('step2-desc').textContent = `Identified ${supplyChainCount} control files: manifests, lockfiles, Dockerfiles, and CI/CD pipelines.`;
document.getElementById('step3-desc').textContent = `Syft catalogers verified: ${(discoveryMeta.syft_catalogers_verified||[]).join(', ')}. Parsed ${COMPONENTS.length} components.`;

// ---- Direct Deps & Sample Paths ----
document.getElementById('direct-deps-list').innerHTML =
  (graphMeta.direct_dep_names||[]).map(n => `<div style="padding:2px 0">📦 ${n}</div>`).join('');

const samplePaths = graphMeta.sample_paths || {};
let pathsHtml = '';
for (const [pkg, paths] of Object.entries(samplePaths)) {
  pathsHtml += `<div style="margin:8px 0"><strong>${pkg}:</strong></div>`;
  paths.forEach(p => { pathsHtml += `<div class="path-item">${p}</div>`; });
}
document.getElementById('sample-paths-container').innerHTML = pathsHtml || '<span style="color:var(--text2)">No paths traced yet</span>';

// ---- Tabs ----
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.panel).classList.add('active');
    if (tab.dataset.panel === 'graph' && !window._cyInitialized) initGraph();
  });
});

// ---- Category Pills for Elements ----
const categories = ['All', 'Supply-Chain Manifests', 'CI/CD Workflows', 'Application Source Code', 'Exploit Demonstrations', 'Templates & Views', 'Static Assets', 'Documentation', 'Configuration', 'Tests & Specs'];
let activeCategory = 'All';

function renderCategoryPills() {
  const container = document.getElementById('category-pills');
  container.innerHTML = categories.map(cat => {
    const count = cat === 'All' ? ELEMENTS.length : ELEMENTS.filter(e => e.category === cat).length;
    if (count === 0 && cat !== 'All') return '';
    return `<div class="pill ${cat === activeCategory ? 'active' : ''}" onclick="selectCategory('${cat}')">${cat} (${count})</div>`;
  }).join('');
}

function selectCategory(cat) {
  activeCategory = cat;
  renderCategoryPills();
  renderElements();
}

// ---- Elements Table ----
function renderElements() {
  const q = document.getElementById('elements-search').value.toLowerCase();
  const rows = ELEMENTS.filter(e => {
    const matchesCat = activeCategory === 'All' || e.category === activeCategory;
    const matchesQuery = !q || e.path.toLowerCase().includes(q) || (e.element_type||'').toLowerCase().includes(q) || (e.category||'').toLowerCase().includes(q);
    return matchesCat && matchesQuery;
  });

  document.getElementById('elements-body').innerHTML = rows.map(e => {
    const isSupply = e.is_supply_chain;
    const badgeClass = isSupply ? 'badge-supply' : e.category.includes('Source') ? 'badge-source' : e.category.includes('Exploit') ? 'badge-exploit' : e.category.includes('Test') ? 'badge-test' : e.category.includes('View') ? 'badge-view' : 'badge-asset';
    return `
      <tr>
        <td style="font-family:monospace;font-size:12px"><strong>${e.path}</strong></td>
        <td><span class="badge ${badgeClass}">${e.category}</span></td>
        <td><code>${e.element_type}</code></td>
        <td>${isSupply ? '⭐ <strong>Controls Dependencies / Build</strong>' : '<span style="color:var(--text2)">Application Asset</span>'}</td>
        <td>${e.ecosystem || '—'}</td>
      </tr>
    `;
  }).join('');
}
renderCategoryPills();
renderElements();
document.getElementById('elements-search').addEventListener('input', renderElements);

// ---- Components Table ----
let activeCompType = 'all';
const directComps = COMPONENTS.filter(c => c.is_direct === true);
const transComps = COMPONENTS.filter(c => c.is_direct === false);
document.getElementById('comp-count-all').textContent = COMPONENTS.length;
document.getElementById('comp-count-direct').textContent = directComps.length;
document.getElementById('comp-count-transitive').textContent = transComps.length;

function filterComponentType(type) {
  activeCompType = type;
  document.querySelectorAll('#component-pills .pill').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  renderComponents();
}

function renderComponents() {
  const q = document.getElementById('components-search').value.toLowerCase();
  const rows = COMPONENTS.filter(c => {
    const matchesType = activeCompType === 'all' ? true : activeCompType === 'direct' ? c.is_direct === true : c.is_direct === false;
    const matchesQuery = !q || c.name.toLowerCase().includes(q) || c.ecosystem.toLowerCase().includes(q);
    return matchesType && matchesQuery;
  });

  document.getElementById('components-body').innerHTML = rows.slice(0, 500).map(c => `
    <tr>
      <td><strong>${c.name}</strong></td>
      <td>${c.version}</td>
      <td><span class="badge badge-${c.ecosystem==='npm'?'npm':c.ecosystem==='pypi'?'pypi':'github'}">${c.ecosystem}</span></td>
      <td>${c.component_type}</td>
      <td>${c.is_direct===true?'<span class="badge badge-direct">Direct</span>':c.is_direct===false?'<span class="badge badge-transitive">Transitive</span>':'—'}</td>
      <td style="font-size:11px">${(c.licenses||[]).join(', ')||'—'}</td>
      <td style="font-size:11px;font-family:monospace;max-width:200px;overflow:hidden;text-overflow:ellipsis">${c.purl||'—'}</td>
    </tr>
  `).join('');
}
renderComponents();
document.getElementById('components-search').addEventListener('input', renderComponents);

// ---- Graph (Cytoscape) ----
let cy = null;
window._cyInitialized = false;

function initGraph() {
  if (window._cyInitialized) return;
  window._cyInitialized = true;

  const elements = [];
  GRAPH.nodes.forEach(n => {
    elements.push({
      data: { id: n.id, label: n.name || n.id, version: n.version, is_direct: n.is_direct },
    });
  });
  GRAPH.edges.forEach(e => {
    elements.push({ data: { source: e.source, target: e.target } });
  });

  document.getElementById('graph-info').textContent =
    `${GRAPH.nodes.length} nodes, ${GRAPH.edges.length} edges`;

  cy = cytoscape({
    container: document.getElementById('graph-container'),
    elements: elements,
    style: [
      { selector: 'node', style: {
          'label': 'data(label)', 'font-size': 8, 'color': '#e6edf3',
          'text-outline-width': 1, 'text-outline-color': '#0d1117',
          'background-color': ele => ele.data('is_direct') ? '#3fb950' : '#58a6ff',
          'width': ele => ele.data('is_direct') ? 20 : 10,
          'height': ele => ele.data('is_direct') ? 20 : 10,
          'text-valign': 'bottom', 'text-margin-y': 4,
      }},
      { selector: 'node[id = "<root>"]', style: {
          'background-color': '#f85149', 'width': 30, 'height': 30,
          'label': 'goof (root)', 'font-size': 10, 'font-weight': 'bold',
      }},
      { selector: 'edge', style: {
          'width': 0.5, 'line-color': '#30363d', 'target-arrow-color': '#30363d',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
          'arrow-scale': 0.5,
      }},
      { selector: '.highlighted', style: {
          'background-color': '#f0883e', 'width': 24, 'height': 24,
          'font-size': 11, 'font-weight': 'bold', 'z-index': 999,
      }},
      { selector: '.path-edge', style: {
          'line-color': '#f0883e', 'target-arrow-color': '#f0883e', 'width': 2, 'z-index': 999,
      }},
      { selector: '.dimmed', style: { 'opacity': 0.15 }},
    ],
    layout: { name: 'concentric',
              concentric: n => n.data('id') === '<root>' ? 100 : n.data('is_direct') ? 50 : 1,
              levelWidth: () => 2, animate: false, spacingFactor: 1.2 },
    minZoom: 0.1, maxZoom: 5,
  });

  cy.on('tap', 'node', function(evt) {
    const node = evt.target;
    highlightPath(node.id());
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
        highlightPath(n.id());
      });
    }
  });
}

function highlightPath(nodeId) {
  cy.elements().removeClass('highlighted path-edge dimmed');
  cy.elements().addClass('dimmed');

  const visited = new Set();
  visited.add(nodeId);

  function walkUp(nid) {
    const node = cy.getElementById(nid);
    node.removeClass('dimmed').addClass('highlighted');
    const incomers = node.incomers('edge');
    incomers.forEach(edge => {
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

  const pathParts = [];
  function traceUp(nid) {
    pathParts.unshift(nid);
    const preds = cy.getElementById(nid).incomers('node');
    if (preds.length > 0 && nid !== '<root>') traceUp(preds[0].id());
  }
  traceUp(nodeId);
  document.getElementById('path-display').innerHTML =
    `<strong>Path to ${nodeId}:</strong><div class="path-item">${pathParts.join(' → ')}</div>`;
}

function resetGraph() {
  if (!cy) return;
  cy.elements().removeClass('highlighted path-edge dimmed');
  document.getElementById('path-display').innerHTML =
    '<strong>Dependency Paths</strong><br>Click a node to see its path from root.';
}
function showDirectOnly() {
  if (!cy) return;
  cy.elements().removeClass('dimmed');
  cy.nodes().filter(n => !n.data('is_direct') && n.data('id') !== '<root>').addClass('dimmed');
  cy.edges().addClass('dimmed');
  cy.edges().filter(e => e.source().data('id') === '<root>').removeClass('dimmed');
}
function showAll() { resetGraph(); }
</script>
</body>
</html>"""

"""
Interactive Dashboard HTML Template for Software Supply Chain Guardian.

Includes interactive Cytoscape dependency graph, live AI Security Copilot chat,
real-time SSE scan execution visualizer, vulnerability filtering, and Markdown report viewer.
"""

from __future__ import annotations

import json
from typing import Optional

import networkx as nx

from guardian.models import ScanResult


def graph_to_dict(graph: Optional[nx.DiGraph]) -> dict:
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


def render_dashboard(scan_result: ScanResult, graph: Optional[nx.DiGraph]) -> str:
    components_json = json.dumps([c.model_dump(mode="json") for c in scan_result.components], default=str)
    elements_json = json.dumps([e.model_dump(mode="json") for e in scan_result.elements], default=str)
    findings_json = json.dumps([f.model_dump(mode="json") for f in scan_result.findings], default=str)
    graph_json = json.dumps(graph_to_dict(graph), default=str)
    context_json = json.dumps(scan_result.context.model_dump(mode="json"), default=str)

    agent_meta = {}
    for aname, ares in scan_result.agent_results.items():
        agent_meta[aname] = ares.metadata
    agent_meta_json = json.dumps(agent_meta, default=str)

    html = _TEMPLATE.replace("__CONTEXT__", context_json)
    html = html.replace("__COMPONENTS__", components_json)
    html = html.replace("__ELEMENTS__", elements_json)
    html = html.replace("__FINDINGS__", findings_json)
    html = html.replace("__GRAPH__", graph_json)
    html = html.replace("__AGENT_META__", agent_meta_json)
    return html


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Software Supply Chain Guardian — Live Command Center</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
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
    --danger: #ef4444;
    --danger-glow: rgba(239, 68, 68, 0.15);
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
    padding: 14px 32px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-icon {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, #3b82f6, #8b5cf6);
    border-radius: 9px; display: flex; align-items: center; justify-content: center;
    font-size: 20px; box-shadow: 0 0 15px rgba(59,130,246,0.3);
  }
  .brand h1 { font-size: 18px; font-weight: 700; letter-spacing: -0.3px; }
  .brand-subtitle { font-size: 11px; color: var(--text-muted); font-weight: 500; }
  .nav-actions { display: flex; gap: 10px; align-items: center; }
  .status-badge {
    padding: 5px 12px; border-radius: 20px; font-size: 11px; font-weight: 600;
    display: flex; align-items: center; gap: 6px;
  }
  .badge-live { background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: var(--success); }
  .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); animation: pulse 1.8s infinite; }
  @keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.85); } 100% { opacity: 1; transform: scale(1); } }
  .btn {
    padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 600;
    cursor: pointer; border: 1px solid var(--border); background: var(--surface); color: var(--text);
    display: inline-flex; align-items: center; gap: 6px; transition: all 0.15s ease;
  }
  .btn:hover { background: var(--surface-hover); border-color: var(--primary); }
  .btn-primary { background: var(--primary); border-color: var(--primary); color: #fff; }
  .btn-primary:hover { background: #2563eb; }
  .btn-accent { background: var(--accent); border-color: var(--accent); color: #fff; }
  .btn-accent:hover { background: #7c3aed; }

  /* Metrics Grid */
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    padding: 20px 32px 8px 32px;
  }
  .metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 18px;
    cursor: pointer;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }
  .metric-card:hover { border-color: var(--primary); transform: translateY(-2px); }
  .metric-val { font-size: 26px; font-weight: 800; letter-spacing: -0.5px; }
  .metric-label { font-size: 11px; color: var(--text-muted); font-weight: 600; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .text-danger { color: var(--danger); }
  .text-warning { color: var(--warning); }
  .text-primary { color: var(--primary); }
  .text-success { color: var(--success); }
  .text-accent  { color: var(--accent); }

  /* Navigation Tabs */
  .tabs-bar {
    display: flex;
    padding: 0 32px;
    border-bottom: 1px solid var(--border);
    margin-top: 8px;
    gap: 4px;
    overflow-x: auto;
  }
  .tab-btn {
    padding: 12px 18px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: all 0.15s;
    display: flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
  }
  .tab-btn:hover { color: var(--text); }
  .tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }
  .tab-counter {
    background: var(--border);
    padding: 2px 7px;
    border-radius: 10px;
    font-size: 11px;
  }

  /* Content Container */
  .container { padding: 24px 32px 48px 32px; }
  .view-panel { display: none; }
  .view-panel.active { display: block; }

  /* Cards & Layout */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
  }
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-subtle);
  }
  .card-title { font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
  .card-body { color: var(--text); font-size: 13.5px; line-height: 1.6; }

  /* Tables */
  .table-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow-x: auto;
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
  th {
    background: #0d121f;
    color: var(--text-muted);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
  }
  td { padding: 12px 16px; border-bottom: 1px solid var(--border-subtle); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--surface-hover); }

  /* Badges & Tags */
  .tag {
    display: inline-flex; align-items: center;
    padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; font-family: monospace;
  }
  .tag-critical { background: var(--danger-glow); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
  .tag-high     { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
  .tag-medium   { background: var(--primary-glow); color: var(--primary); border: 1px solid rgba(59, 130, 246, 0.3); }
  .tag-low      { background: rgba(126, 140, 159, 0.15); color: var(--text-muted); border: 1px solid rgba(126, 140, 159, 0.3); }
  .tag-direct   { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
  .tag-trans    { background: rgba(139, 92, 246, 0.15); color: var(--accent); border: 1px solid rgba(139, 92, 246, 0.3); }
  .tag-control  { background: rgba(239, 68, 68, 0.1); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.2); }

  /* Search & Filter Toolbar */
  .toolbar {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 16px; gap: 12px; flex-wrap: wrap;
  }
  .search-input {
    background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 9px 14px; border-radius: 8px; font-size: 13px; width: 280px; outline: none;
  }
  .search-input:focus { border-color: var(--primary); }
  .filter-pills { display: flex; gap: 6px; flex-wrap: wrap; }
  .filter-pill {
    padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;
    cursor: pointer; background: var(--surface); border: 1px solid var(--border); color: var(--text-muted);
  }
  .filter-pill.active { background: var(--primary); color: #fff; border-color: var(--primary); }

  /* Graph Canvas */
  #graph-canvas {
    width: 100%; height: 560px;
    background: #0a0f1a;
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-top: 10px;
  }
  .graph-bar {
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;
  }
  .path-card {
    background: #0d1322; border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; margin-top: 12px;
    font-size: 12.5px;
  }
  .path-snippet {
    font-family: monospace; font-size: 12px; color: #38bdf8; margin-top: 4px;
    word-break: break-all;
  }

  /* AI Security Team Cards */
  .agent-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 18px;
    position: relative;
    overflow: hidden;
  }
  .agent-card::before {
    content: ""; position: absolute; top: 0; left: 0; width: 4px; height: 100%;
    background: var(--accent);
  }
  .agent-card.agent-risk::before { background: var(--danger); }
  .agent-card.agent-recs::before { background: var(--success); }
  .agent-card.agent-reach::before { background: var(--primary); }
  .agent-card.agent-context::before { background: var(--warning); }
  .agent-meta-badge {
    font-size: 11px; padding: 3px 8px; border-radius: 6px;
    background: rgba(139, 92, 246, 0.15); color: var(--accent); font-weight: 600;
  }
  .agent-markdown h3, .agent-markdown h4 { margin-top: 12px; margin-bottom: 6px; color: #fff; font-size: 14px; }
  .agent-markdown ul { margin-left: 20px; margin-bottom: 10px; }
  .agent-markdown li { margin-bottom: 4px; }
  .agent-markdown code { background: #1c263c; padding: 2px 5px; border-radius: 4px; font-size: 12px; color: #38bdf8; }
  .agent-markdown table { margin-top: 10px; margin-bottom: 10px; }

  /* AI Copilot Chat */
  .chat-layout {
    display: flex; flex-direction: column; height: 600px;
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    overflow: hidden;
  }
  .chat-header {
    padding: 14px 20px; background: #0d121f; border-bottom: 1px solid var(--border);
    display: flex; justify-content: space-between; align-items: center;
  }
  .chat-messages {
    flex: 1; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 14px;
  }
  .chat-msg {
    max-width: 82%; padding: 12px 16px; border-radius: 10px; font-size: 13.5px; line-height: 1.5;
  }
  .msg-user {
    align-self: flex-end; background: var(--primary); color: #fff; border-bottom-right-radius: 2px;
  }
  .msg-ai {
    align-self: flex-start; background: #172033; border: 1px solid var(--border); border-bottom-left-radius: 2px;
  }
  .msg-ai pre { background: #0b0f19; padding: 10px; border-radius: 6px; overflow-x: auto; margin: 8px 0; }
  .chat-input-bar {
    padding: 14px 20px; border-top: 1px solid var(--border); display: flex; gap: 10px; background: #0d121f;
  }
  .chat-input {
    flex: 1; background: var(--surface); border: 1px solid var(--border); color: #fff;
    padding: 10px 14px; border-radius: 8px; font-size: 13.5px; outline: none;
  }
  .chat-input:focus { border-color: var(--primary); }
  .prompt-chips { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
  .prompt-chip {
    background: var(--surface); border: 1px solid var(--border); padding: 5px 12px;
    border-radius: 16px; font-size: 12px; color: var(--text-muted); cursor: pointer; transition: all 0.15s;
  }
  .prompt-chip:hover { border-color: var(--primary); color: var(--text); }

  /* Modals */
  .modal-overlay {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(4, 7, 13, 0.75); backdrop-filter: blur(4px);
    display: none; align-items: center; justify-content: center; z-index: 1000;
  }
  .modal-overlay.active { display: flex; }
  .modal-box {
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    width: 720px; max-width: 90vw; max-height: 85vh; display: flex; flex-direction: column;
    box-shadow: 0 20px 40px rgba(0,0,0,0.5); overflow: hidden;
  }
  .modal-header {
    padding: 16px 22px; border-bottom: 1px solid var(--border); display: flex;
    justify-content: space-between; align-items: center; background: #0d121f;
  }
  .modal-title { font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
  .modal-body { padding: 22px; overflow-y: auto; flex: 1; }
  .modal-footer {
    padding: 14px 22px; border-top: 1px solid var(--border); display: flex;
    justify-content: flex-end; gap: 10px; background: #0d121f;
  }

  /* Live Pipeline Steps */
  .pipeline-steps { display: flex; flex-direction: column; gap: 10px; margin-bottom: 18px; }
  .pipe-step {
    display: flex; align-items: center; justify-content: space-between;
    background: #0d1322; border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px;
  }
  .pipe-info { display: flex; align-items: center; gap: 12px; font-size: 13.5px; font-weight: 600; }
  .step-status { font-size: 12px; font-weight: 600; padding: 3px 8px; border-radius: 6px; }
  .step-idle { background: #1c263c; color: var(--text-muted); }
  .step-running { background: rgba(59, 130, 246, 0.2); color: #60a5fa; animation: pulse 1s infinite; }
  .step-done { background: rgba(16, 185, 129, 0.2); color: #34d399; }
  .live-console {
    background: #070a10; border: 1px solid #1c263c; border-radius: 8px; padding: 12px;
    font-family: monospace; font-size: 12px; color: #a5f3fc; height: 180px; overflow-y: auto;
    white-space: pre-wrap;
  }
</style>
</head>
<body>

<!-- Top Navigation -->
<header class="top-nav">
  <div class="brand">
    <div class="brand-icon">🛡️</div>
    <div>
      <h1>Software Supply Chain Guardian</h1>
      <div class="brand-subtitle">Autonomous Multi-Agent Security Command Center (Team 26)</div>
    </div>
  </div>

  <div class="nav-actions">
    <div class="status-badge badge-live" id="live-indicator">
      <span class="live-dot"></span>
      <span id="live-text">Live Server Active</span>
    </div>
    <button class="btn btn-primary" onclick="openLiveScanModal()">⚡ Run Live Scan</button>
    <button class="btn" onclick="openReportModal()">📄 Executive Report</button>
    <button class="btn" onclick="downloadJSON()">⬇️ Export JSON</button>
  </div>
</header>

<!-- Metrics Overview Grid -->
<div class="metrics-grid">
  <div class="metric-card" onclick="switchTab('files')">
    <div class="metric-val text-primary" id="m-files">--</div>
    <div class="metric-label">Repository Files</div>
  </div>
  <div class="metric-card" onclick="switchTab('components')">
    <div class="metric-val text-accent" id="m-components">--</div>
    <div class="metric-label">Software Components</div>
  </div>
  <div class="metric-card" onclick="switchTab('graph')">
    <div class="metric-val text-success" id="m-nodes">--</div>
    <div class="metric-label">Graph Nodes (Edges)</div>
  </div>
  <div class="metric-card" onclick="switchTab('vulns')">
    <div class="metric-val text-warning" id="m-total-vulns">--</div>
    <div class="metric-label">Deduplicated Risks</div>
  </div>
  <div class="metric-card" onclick="switchTab('vulns')">
    <div class="metric-val text-danger" id="m-critical-vulns">--</div>
    <div class="metric-label">Direct Critical Risks</div>
  </div>
  <div class="metric-card" onclick="switchTab('copilot')">
    <div class="metric-val text-accent" style="font-size: 20px; padding-top: 4px;">Groq 120B</div>
    <div class="metric-label">AI Security Team</div>
  </div>
</div>

<!-- Tabs Bar -->
<div class="tabs-bar">
  <div class="tab-btn active" onclick="switchTab('overview')">
    📊 Overview
  </div>
  <div class="tab-btn" onclick="switchTab('ai')">
    🤖 AI Security Team
  </div>
  <div class="tab-btn" onclick="switchTab('copilot')">
    💬 AI Copilot (Live Q&A)
  </div>
  <div class="tab-btn" onclick="switchTab('vulns')">
    🚨 Vulnerabilities <span class="tab-counter" id="tab-cnt-vulns">0</span>
  </div>
  <div class="tab-btn" onclick="switchTab('graph')">
    🕸️ Dependency Graph
  </div>
  <div class="tab-btn" onclick="switchTab('components')">
    📦 Components <span class="tab-counter" id="tab-cnt-comps">0</span>
  </div>
  <div class="tab-btn" onclick="switchTab('files')">
    📁 Repo Files <span class="tab-counter" id="tab-cnt-files">0</span>
  </div>
</div>

<div class="container">
  <!-- 1. OVERVIEW VIEW -->
  <div class="view-panel active" id="view-overview">
    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <div class="card-title">🎯 Verified Repository Target</div>
          <span class="tag tag-direct" id="ov-repo-name">goof</span>
        </div>
        <div class="card-body">
          <p><strong>Path:</strong> <code id="ov-repo-path">targets/goof</code></p>
          <p style="margin-top: 6px;"><strong>Git Commit:</strong> <code id="ov-commit">--</code></p>
          <p style="margin-top: 6px;"><strong>Ecosystem:</strong> Node.js (npm lockfile v1/v2)</p>
          <p style="margin-top: 6px;"><strong>Cataloger:</strong> Anchore Syft (CycloneDX 1.7 JSON)</p>
          <p style="margin-top: 6px;"><strong>Detector:</strong> Anchore Grype Vulnerability DB</p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">⚖️ Severity vs. Guardian Risk Decoupling</div>
        </div>
        <div class="card-body">
          <p>Scanners flag <strong>all</strong> matches uniformly, causing alert fatigue. Guardian separates <em>Scanner Severity</em> from <em>Contextual Risk</em>:</p>
          <div style="margin-top: 10px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
            <div style="background:#0d121f; padding:8px 12px; border-radius:6px; border:1px solid var(--border)">
              <div style="font-size:11px; color:var(--text-muted)">GRYPE SCANNER</div>
              <div style="font-weight:700; color:var(--danger); margin-top:2px;">39 Critical | 106 High</div>
            </div>
            <div style="background:#0d121f; padding:8px 12px; border-radius:6px; border:1px solid var(--border)">
              <div style="font-size:11px; color:var(--text-muted)">GUARDIAN RISK LEVEL</div>
              <div style="font-weight:700; color:var(--success); margin-top:2px;">11 Direct Critical Risks</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Priority Direct Critical Action Items -->
    <div class="card" style="border-color: rgba(239, 68, 68, 0.4);">
      <div class="card-header">
        <div class="card-title" style="color: #f87171;">⚠️ Immediate Attack Surface (Direct Critical Dependencies)</div>
        <span class="tag tag-critical">Action Required</span>
      </div>
      <div class="card-body">
        <div class="table-box">
          <table>
            <thead>
              <tr>
                <th>Package</th>
                <th>Type</th>
                <th>Advisories</th>
                <th>Remediation Fix</th>
                <th>Graph Action</th>
              </tr>
            </thead>
            <tbody id="top-critical-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Multi-Agent Architecture Pipeline Diagram -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">🤖 Guardian Multi-Agent System Architecture</div>
        <span class="agent-meta-badge">Autonomous Pipeline</span>
      </div>
      <div class="card-body">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
          <div style="background:#0d1322; padding:12px; border-radius:8px; border:1px solid var(--border);">
            <div style="color:var(--primary); font-weight:700; font-size:12px;">1. DISCOVERY AGENT</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Walks filesystem, categorizes 60 files, flags supply-chain manifest controls.</div>
          </div>
          <div style="background:#0d1322; padding:12px; border-radius:8px; border:1px solid var(--border);">
            <div style="color:var(--accent); font-weight:700; font-size:12px;">2. GRAPH AGENT</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Ingests CycloneDX SBOM, builds NetworkX graph with 981 nodes, 1,479 edges.</div>
          </div>
          <div style="background:#0d1322; padding:12px; border-radius:8px; border:1px solid var(--border);">
            <div style="color:var(--warning); font-weight:700; font-size:12px;">3. VULNERABILITY AGENT</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Deduplicates 244 CVEs/GHSAs, correlates reachability and shortest paths.</div>
          </div>
          <div style="background:#0d1322; padding:12px; border-radius:8px; border:1px solid var(--border);">
            <div style="color:var(--danger); font-weight:700; font-size:12px;">4. CHANGE AGENT</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Detects unpinned packages ("latest"), mutable Docker tags, CI/CD action drift.</div>
          </div>
          <div style="background:#0d1322; padding:12px; border-radius:8px; border:1px solid var(--border);">
            <div style="color:var(--success); font-weight:700; font-size:12px;">5. AI ORCHESTRATOR</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Groq 120B multi-agent council evaluates reachability, risk, and exact fix commands.</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 2. AI SECURITY TEAM VIEW -->
  <div class="view-panel" id="view-ai">
    <div class="agent-card agent-reach">
      <div class="card-header">
        <div class="card-title">🤖 AI Agent 1: Reachability Agent</div>
        <span class="agent-meta-badge">Dependency Graph Path Analysis</span>
      </div>
      <div class="card-body agent-markdown" id="ai-reach-content">Loading...</div>
    </div>

    <div class="agent-card agent-context">
      <div class="card-header">
        <div class="card-title">🤖 AI Agent 2: Context Analysis Agent</div>
        <span class="agent-meta-badge">Configuration, Dockerfile & Unpinned Packages</span>
      </div>
      <div class="card-body agent-markdown" id="ai-context-content">Loading...</div>
    </div>

    <div class="agent-card agent-risk">
      <div class="card-header">
        <div class="card-title">🤖 AI Agent 3: Risk Analysis Agent (Lead)</div>
        <span class="agent-meta-badge">Business Impact & Priority Matrix</span>
      </div>
      <div class="card-body agent-markdown" id="ai-risk-content">Loading...</div>
    </div>

    <div class="agent-card agent-recs">
      <div class="card-header">
        <div class="card-title">🤖 AI Agent 4: Recommendation Agent</div>
        <span class="agent-meta-badge">Developer Remediation Playbook</span>
      </div>
      <div class="card-body agent-markdown" id="ai-recs-content">Loading...</div>
    </div>
  </div>

  <!-- 3. AI COPILOT CHAT VIEW (LIVE INTERACTIVE Q&A) -->
  <div class="view-panel" id="view-copilot">
    <div class="prompt-chips">
      <span class="prompt-chip" onclick="askCopilot('Why is Handlebars 4.0.14 marked as High Risk if we do not import it directly?')">❓ Why is Handlebars transitive risk?</span>
      <span class="prompt-chip" onclick="askCopilot('Which direct dependencies have critical vulnerabilities and what are the exact fix commands?')">⚡ Direct Critical Fix Commands</span>
      <span class="prompt-chip" onclick="askCopilot('Explain the supply chain risks found in the Dockerfile and package.json floating tags.')">🐳 Dockerfile & Floating Tags Risk</span>
      <span class="prompt-chip" onclick="askCopilot('Can an attacker execute code via ejs@1.0.0 in this repository?')">💥 Explain ejs RCE attack exposure</span>
    </div>

    <div class="chat-layout">
      <div class="chat-header">
        <div style="font-weight:700; font-size:14px; display:flex; align-items:center; gap:8px;">
          <span>💬</span> Guardian AI Security Copilot
          <span class="agent-meta-badge">Groq 120B Model</span>
        </div>
        <div style="font-size:12px; color:var(--text-muted)">Grounded in Live Repository Context</div>
      </div>
      <div class="chat-messages" id="chat-stream">
        <div class="chat-msg msg-ai">
          👋 Hello! I am the <strong>Software Supply Chain Guardian AI Copilot</strong>. I have ingested the live dependency graph, Grype vulnerability catalog, and configuration manifests for this repository.<br><br>
          Ask me anything about dependency reachability, CVE impact, transitive root causes, or exact remediation steps!
        </div>
      </div>
      <div class="chat-input-bar">
        <input class="chat-input" id="copilot-input" placeholder="Ask Guardian Security Copilot (e.g. How do I patch handlebars without breaking hbs?)..." onkeypress="if(event.key==='Enter') sendChatMessage()" />
        <button class="btn btn-primary" onclick="sendChatMessage()">Send ➔</button>
      </div>
    </div>
  </div>

  <!-- 4. VULNERABILITIES VIEW -->
  <div class="view-panel" id="view-vulns">
    <div class="toolbar">
      <input class="search-input" placeholder="Search vulnerability (e.g. CVE, ejs)..." id="vulns-search" />
      <div class="filter-pills">
        <div class="filter-pill active" onclick="setVulnFilter('all', this)">All (<span id="vf-all-cnt">244</span>)</div>
        <div class="filter-pill" onclick="setVulnFilter('Critical', this)">Critical (<span id="vf-crit-cnt">39</span>)</div>
        <div class="filter-pill" onclick="setVulnFilter('High', this)">High (<span id="vf-high-cnt">106</span>)</div>
        <div class="filter-pill" onclick="setVulnFilter('direct', this)">Direct Only (<span id="vf-dir-cnt">11</span>)</div>
        <div class="filter-pill" onclick="setVulnFilter('transitive', this)">Transitive Only (<span id="vf-trans-cnt">54</span>)</div>
      </div>
    </div>
    <div class="table-box">
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Severity</th>
            <th>Risk Level</th>
            <th>Advisories</th>
            <th>Fix Version</th>
            <th>Dependency Path</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="vulns-table-body"></tbody>
      </table>
    </div>
  </div>

  <!-- 5. DEPENDENCY GRAPH VIEW -->
  <div class="view-panel" id="view-graph">
    <div class="graph-bar">
      <input class="search-input" placeholder="Search node (e.g. handlebars, ejs)..." id="graph-search" />
      <div style="display: flex; gap: 8px;">
        <button class="btn" onclick="resetGraph()">Reset View</button>
        <button class="btn" onclick="toggleDirect()">Direct Deps Only</button>
      </div>
    </div>
    <div id="graph-canvas"></div>
    <div class="path-card" id="graph-path-box">
      <div style="font-size: 11px; color: var(--text-muted); text-transform:uppercase; font-weight:700;">SELECTED DEPENDENCY PATH</div>
      <div class="path-snippet" id="graph-path-text">Click any node in the graph above or click "Trace on Graph" from the Vulnerabilities tab.</div>
    </div>
  </div>

  <!-- 6. COMPONENTS VIEW -->
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

  <!-- 7. REPO FILES VIEW -->
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
</div>

<!-- Modal 1: Live Multi-Agent Scan Modal -->
<div class="modal-overlay" id="modal-live-scan">
  <div class="modal-box">
    <div class="modal-header">
      <div class="modal-title">⚡ Live Multi-Agent Scan Orchestrator</div>
      <button class="btn" onclick="closeLiveScanModal()">✕</button>
    </div>
    <div class="modal-body">
      <div style="margin-bottom: 14px; font-size: 13.5px; color: var(--text-muted);">
        Execute the autonomous 5-stage agent pipeline with real-time SSE streaming:
      </div>
      <div class="pipeline-steps">
        <div class="pipe-step" id="step-pipe-discovery">
          <div class="pipe-info"><span>🔍</span> Discovery Agent (Filesystem & Manifests)</div>
          <span class="step-status step-idle" id="badge-pipe-discovery">Idle</span>
        </div>
        <div class="pipe-step" id="step-pipe-graph">
          <div class="pipe-info"><span>🕸️</span> Dependency Graph Agent (SBOM & Topology)</div>
          <span class="step-status step-idle" id="badge-pipe-graph">Idle</span>
        </div>
        <div class="pipe-step" id="step-pipe-vulnerability">
          <div class="pipe-info"><span>🛡️</span> Vulnerability Agent (Grype & Reachability)</div>
          <span class="step-status step-idle" id="badge-pipe-vulnerability">Idle</span>
        </div>
        <div class="pipe-step" id="step-pipe-change_detection">
          <div class="pipe-info"><span>⚠️</span> Change Detection Agent (Docker & Actions Drift)</div>
          <span class="step-status step-idle" id="badge-pipe-change_detection">Idle</span>
        </div>
        <div class="pipe-step" id="step-pipe-analyst">
          <div class="pipe-info"><span>🤖</span> AI Security Team Layer (Groq 120B Multi-Agent)</div>
          <span class="step-status step-idle" id="badge-pipe-analyst">Idle</span>
        </div>
      </div>

      <div style="font-size:11px; color:var(--text-muted); font-weight:700; margin-bottom:4px; text-transform:uppercase;">Agent Execution Live Log:</div>
      <div class="live-console" id="scan-live-console">System ready. Click "Start Autonomous Scan" to execute...</div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="closeLiveScanModal()">Close</button>
      <button class="btn btn-primary" id="btn-start-scan" onclick="triggerLiveScanSSE()">🚀 Start Autonomous Scan</button>
    </div>
  </div>
</div>

<!-- Modal 2: Executive Markdown Report Modal -->
<div class="modal-overlay" id="modal-report">
  <div class="modal-box" style="width: 860px;">
    <div class="modal-header">
      <div class="modal-title">📄 Software Supply Chain Guardian — Executive Security Report</div>
      <button class="btn" onclick="closeReportModal()">✕</button>
    </div>
    <div class="modal-body agent-markdown" id="report-md-content" style="font-size: 13.5px; line-height: 1.6;">
      Loading report...
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="downloadMarkdown()">⬇️ Download .MD</button>
      <button class="btn" onclick="window.print()">🖨️ Print / Save PDF</button>
      <button class="btn btn-primary" onclick="closeReportModal()">Done</button>
    </div>
  </div>
</div>

<script>
// Data injected by Guardian
const COMPONENTS = __COMPONENTS__;
const ELEMENTS   = __ELEMENTS__;
const FINDINGS   = __FINDINGS__;
const GRAPH      = __GRAPH__;
const AGENT_META = __AGENT_META__;
const CONTEXT    = __CONTEXT__;

const graphMeta  = AGENT_META.graph || {};
const analystMeta= AGENT_META.analyst || {};
const vulnMeta   = AGENT_META.vulnerability || {};

// Populate Metrics
const critCount = FINDINGS.filter(f => f.severity === 'Critical').length;
document.getElementById('m-critical-vulns').textContent = critCount;
document.getElementById('m-total-vulns').textContent = FINDINGS.length;
document.getElementById('m-components').textContent = COMPONENTS.length;
document.getElementById('m-files').textContent = ELEMENTS.length;
document.getElementById('m-nodes').textContent = `${graphMeta.total_nodes || GRAPH.nodes.length} (${graphMeta.total_edges || GRAPH.edges.length})`;

document.getElementById('tab-cnt-vulns').textContent = FINDINGS.length;
document.getElementById('tab-cnt-comps').textContent = COMPONENTS.length;
document.getElementById('tab-cnt-files').textContent = ELEMENTS.length;

document.getElementById('ov-repo-name').textContent = CONTEXT.repo_name || 'goof';
document.getElementById('ov-repo-path').textContent = CONTEXT.repo_path || 'targets/goof';
document.getElementById('ov-commit').textContent = (CONTEXT.commit_hash || 'add14ba59e98240d9e00a235dd7d42cd61ae9912').substring(0, 10);

// Populate Top Critical Action Items
const topCrit = analystMeta.top_critical_risks || [];
document.getElementById('top-critical-body').innerHTML = topCrit.slice(0, 4).map(item => `
  <tr>
    <td><strong>${item.package}</strong></td>
    <td><span class="tag tag-direct">Direct</span></td>
    <td>${(item.advisories||[]).map(a => `<code style="font-size:11px;">${a}</code>`).join(' ')}</td>
    <td><strong style="color:var(--success)">${item.fix ? 'v' + item.fix : 'No direct patch'}</strong></td>
    <td><button class="btn" style="padding:3px 8px; font-size:11px;" onclick="traceOnGraph('${item.package}')">Trace on Graph</button></td>
  </tr>
`).join('');

// Populate AI Insights
document.getElementById('ai-reach-content').innerHTML = marked.parse(analystMeta.reachability_agent_assessment || 'Reachability analysis pending.');
document.getElementById('ai-context-content').innerHTML = marked.parse(analystMeta.context_analysis_assessment || 'Context analysis pending.');
document.getElementById('ai-risk-content').innerHTML = marked.parse(analystMeta.risk_analysis_assessment || 'Risk analysis pending.');
document.getElementById('ai-recs-content').innerHTML = marked.parse(analystMeta.recommendation_agent_actions || 'Remediation playbook pending.');

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  const targetView = document.getElementById(`view-${tabId}`);
  if (targetView) targetView.classList.add('active');

  const btns = document.querySelectorAll('.tab-btn');
  const mapping = { overview: 0, ai: 1, copilot: 2, vulns: 3, graph: 4, components: 5, files: 6 };
  if (mapping[tabId] !== undefined && btns[mapping[tabId]]) {
    btns[mapping[tabId]].classList.add('active');
  }

  if (tabId === 'graph') {
    setTimeout(initGraph, 100);
  }
}

// Vulnerabilities Filtering
let activeVulnFilter = 'all';
function setVulnFilter(filter, el) {
  activeVulnFilter = filter;
  document.querySelectorAll('#view-vulns .filter-pill').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  renderVulnsTable();
}

function renderVulnsTable() {
  const q = document.getElementById('vulns-search').value.toLowerCase();
  const rows = FINDINGS.filter(f => {
    let matchPill = true;
    if (activeVulnFilter === 'direct') matchPill = f.risk_level === 'critical';
    else if (activeVulnFilter === 'transitive') matchPill = f.risk_level === 'high';
    else if (activeVulnFilter !== 'all') matchPill = f.severity === activeVulnFilter;

    const matchQ = !q ||
      (f.component_name || '').toLowerCase().includes(q) ||
      (f.id || '').toLowerCase().includes(q) ||
      (f.aliases || []).some(a => a.toLowerCase().includes(q));

    return matchPill && matchQ;
  });

  document.getElementById('vulns-table-body').innerHTML = rows.slice(0, 200).map(f => {
    const sevClass = f.severity === 'Critical' ? 'tag-critical' : f.severity === 'High' ? 'tag-high' : f.severity === 'Medium' ? 'tag-medium' : 'tag-low';
    const riskClass = f.risk_level === 'critical' ? 'tag-critical' : f.risk_level === 'high' ? 'tag-high' : 'tag-medium';
    const pathStr = f.reachability_path ? f.reachability_path.join(' ➔ ') : '—';
    const advList = [f.id].concat(f.aliases || []).slice(0, 3).join(', ');

    return `
      <tr>
        <td><strong>${f.component_name}</strong><br><span style="font-size:11px; color:var(--text-muted)">v${f.component_version}</span></td>
        <td><span class="tag ${sevClass}">${f.severity}</span></td>
        <td><span class="tag ${riskClass}">${f.risk_level || 'medium'}</span></td>
        <td style="font-size:12px; font-family:monospace; color:var(--text-muted)">${advList}</td>
        <td><strong style="color:var(--success)">${f.fix_version ? 'v' + f.fix_version : '—'}</strong></td>
        <td style="font-family:monospace; font-size:11px; max-width:240px; overflow:hidden; text-overflow:ellipsis;" title="${pathStr}">${pathStr}</td>
        <td><button class="btn" style="padding:3px 8px; font-size:11px;" onclick="traceOnGraph('${f.component_name}')">Trace</button></td>
      </tr>
    `;
  }).join('');
}
renderVulnsTable();
document.getElementById('vulns-search').addEventListener('input', renderVulnsTable);

function traceOnGraph(pkgName) {
  switchTab('graph');
  document.getElementById('graph-search').value = pkgName;
  setTimeout(() => {
    if (cy) {
      cy.elements().removeClass('highlighted path-edge dimmed');
      const matched = cy.nodes().filter(n => (n.data('label') || '').toLowerCase().includes(pkgName.toLowerCase()));
      if (matched.length > 0) {
        cy.elements().addClass('dimmed');
        matched.forEach(n => {
          n.removeClass('dimmed').addClass('highlighted');
          highlightNode(n.id());
        });
      }
    }
  }, 100);
}

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
      <td style="font-family:monospace; font-size:11px; color:var(--text-muted); max-width:200px; overflow:hidden; text-overflow:ellipsis">${c.purl||'—'}</td>
    </tr>
  `).join('');
}
renderCompsTable();
document.getElementById('comps-search').addEventListener('input', renderCompsTable);

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

  document.getElementById('files-table-body').innerHTML = rows.map(e => `
    <tr>
      <td style="font-family:monospace; font-weight:600;">${e.path}</td>
      <td><span class="tag ${e.is_supply_chain ? 'tag-control' : ''}">${e.category}</span></td>
      <td style="color:var(--text-muted); font-size:12px;">${e.is_supply_chain ? '⭐ Controls Build & Dependencies' : 'Application Asset'}</td>
    </tr>
  `).join('');
}
renderFileFilters();
renderFilesTable();
document.getElementById('files-search').addEventListener('input', renderFilesTable);

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
          'label': `${CONTEXT.repo_name || 'goof'} (root)`, 'font-weight': 'bold', 'font-size': 11
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
    const matched = cy.nodes().filter(n => (n.data('label') || '').toLowerCase().includes(q));
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
  if (!cy) return;
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
  document.getElementById('graph-path-text').textContent = 'Click any node in the graph above or click "Trace on Graph" from the Vulnerabilities tab.';
}

function toggleDirect() {
  if (!cy) return;
  cy.elements().removeClass('dimmed');
  cy.nodes().filter(n => !n.data('is_direct') && n.data('id') !== '<root>').addClass('dimmed');
  cy.edges().addClass('dimmed');
  cy.edges().filter(e => e.source().data('id') === '<root>').removeClass('dimmed');
}

// ---------------------------------------------------------------------------
// AI Copilot Interactive Chat
// ---------------------------------------------------------------------------
function askCopilot(question) {
  document.getElementById('copilot-input').value = question;
  sendChatMessage();
}

async function sendChatMessage() {
  const input = document.getElementById('copilot-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';

  const stream = document.getElementById('chat-stream');
  stream.innerHTML += `<div class="chat-msg msg-user">${text}</div>`;
  stream.scrollTop = stream.scrollHeight;

  const aiPlaceholder = document.createElement('div');
  aiPlaceholder.className = 'chat-msg msg-ai';
  aiPlaceholder.innerHTML = '<em>Thinking with Groq 120B...</em>';
  stream.appendChild(aiPlaceholder);
  stream.scrollTop = stream.scrollHeight;

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    aiPlaceholder.innerHTML = marked.parse(data.reply || 'No response returned.');
  } catch (err) {
    aiPlaceholder.innerHTML = `<span style="color:var(--danger)">Offline Mode / API Notice:</span><br>Could not reach live API (${err.message}).<br><br><strong>Fallback Answer:</strong><br>In this repository (goof), <strong>ejs@1.0.0</strong>, <strong>typeorm@0.2.24</strong>, and <strong>mongoose@4.2.4</strong> are direct critical vulnerabilities. Transitive dependencies like <strong>handlebars@4.0.14</strong> (prototype pollution) enter via direct parent <code>hbs@4.0.4</code>; patch by bumping <code>hbs</code> to <code>^4.1.2</code>.`;
  }
  stream.scrollTop = stream.scrollHeight;
}

// ---------------------------------------------------------------------------
// Live Scan Modal & Real-time SSE Execution
// ---------------------------------------------------------------------------
function openLiveScanModal() {
  document.getElementById('modal-live-scan').classList.add('active');
}
function closeLiveScanModal() {
  document.getElementById('modal-live-scan').classList.remove('active');
}

function setPipeStep(stepId, state, text) {
  const badge = document.getElementById(`badge-pipe-${stepId}`);
  if (!badge) return;
  badge.className = `step-status step-${state}`;
  badge.textContent = text;
}

async function triggerLiveScanSSE() {
  const consoleEl = document.getElementById('scan-live-console');
  const btn = document.getElementById('btn-start-scan');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  consoleEl.textContent = '[guardian] Initiating multi-agent scan...\n';

  ['discovery', 'graph', 'vulnerability', 'change_detection', 'analyst'].forEach(s => setPipeStep(s, 'idle', 'Waiting'));

  try {
    const res = await fetch('/api/scan/live', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo_path: CONTEXT.repo_path || 'targets/goof' })
    });

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n\n');
      buf = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const payload = JSON.parse(line.replace('data: ', ''));

        if (payload.event === 'agent_update') {
          const ph = payload.phase;
          const st = payload.status;
          consoleEl.textContent += `[${ph}] ${st.toUpperCase()}: ${JSON.stringify(payload.data)}\n`;
          consoleEl.scrollTop = consoleEl.scrollHeight;

          if (st === 'running') setPipeStep(ph, 'running', 'Running');
          else if (st === 'completed') setPipeStep(ph, 'done', 'Done ✓');
        } else if (payload.event === 'scan_complete') {
          consoleEl.textContent += `\n[guardian] ✓ Scan complete! Summary: ${JSON.stringify(payload.summary)}\n`;
          consoleEl.scrollTop = consoleEl.scrollHeight;
          btn.textContent = '✓ Scan Finished';
          setTimeout(() => location.reload(), 1500);
        }
      }
    }
  } catch (err) {
    consoleEl.textContent += `\n[error] Failed to connect to live stream: ${err.message}\n(Make sure 'python -m guardian serve' is running)\n`;
    btn.disabled = false;
    btn.textContent = 'Retry Scan';
  }
}

// ---------------------------------------------------------------------------
// Executive Report Modal & Export
// ---------------------------------------------------------------------------
async function openReportModal() {
  document.getElementById('modal-report').classList.add('active');
  const content = document.getElementById('report-md-content');
  try {
    const res = await fetch('/api/report/markdown');
    if (!res.ok) throw new Error();
    const md = await res.text();
    window._lastMarkdown = md;
    content.innerHTML = marked.parse(md);
  } catch {
    content.innerHTML = `<h3>Software Supply Chain Guardian Security Report</h3><p>Report is available in <code>reports/SECURITY-REPORT.md</code>. Run the live server with <code>python -m guardian serve</code> to view live markdown rendering.</p>`;
  }
}
function closeReportModal() {
  document.getElementById('modal-report').classList.remove('active');
}

function downloadJSON() {
  const blob = new Blob([JSON.stringify({ context: CONTEXT, components: COMPONENTS, findings: FINDINGS, graph: GRAPH, agent_meta: AGENT_META }, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'guardian-scan-result.json'; a.click();
}

function downloadMarkdown() {
  const text = window._lastMarkdown || '# Software Supply Chain Guardian Report';
  const blob = new Blob([text], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'SECURITY-REPORT.md'; a.click();
}
</script>
</body>
</html>"""


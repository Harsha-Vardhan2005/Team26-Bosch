# Software Supply Chain Guardian 🛡️

> **"Know what you build. Trust what you ship."**  
> *Bosch Hackathon — Day 1: Build the Guardian's Eyes*

The **Software Supply Chain Guardian** is an agentic, modular repository-analysis and security-assessment system. It autonomously discovers the software components inside any repository, isolates critical supply-chain control files, maps direct and transitive dependency graphs, and generates evidence-backed audit reports.

---

## 🚀 Key Capabilities (Day 1)

1. **Complete Filesystem Discovery:** Dynamically catalogs all files in the target repository, classifying them by engineering role (Application Source, Templates/Views, Exploits, Tests, Configuration, Docs).
2. **Supply-Chain Control Isolation:** Automatically identifies files controlling dependencies and builds (`package.json`, `package-lock.json`, `Dockerfile`, `docker-compose.yml`, GitHub Actions workflows).
3. **CycloneDX SBOM Ingestion:** Ingests and parses CycloneDX v1.7 SBOMs (generated via Anchore Syft) into structured Component inventory models with Package URLs (PURLs) and licenses.
4. **Deterministic Dependency Graph:** Uses **NetworkX** to construct a directed parent-child dependency graph supporting both npm `lockfileVersion: 1` (nested) and `lockfileVersion: 2/3` (`packages` format).
5. **Transitive Path Tracing:** Mathematically traces any transitive dependency back through the graph to its direct parent root (e.g. verifying `hbs -> handlebars`).
6. **Interactive Visual Dashboard:** Generates a standalone, interactive HTML5 dashboard with Cytoscape.js graph visualization, searchable inventory tables, and direct-vs-transitive filters.

---

## 🏗️ Architecture Pipeline

```text
Target Repository Path
          │
          ▼
┌───────────────────────────┐
│   Discovery Agent         │ ──▶ Catalog all files (Source, Views, Exploits, Tests)
│                           │ ──▶ Isolate Supply-Chain files (Manifests, Lockfiles, Docker, CI)
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│   SBOM Ingestion (Syft)   │ ──▶ Extract 577 components with PURLs & licenses
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│   Graph Agent (NetworkX)  │ ──▶ Build 981-node, 1,479-edge dependency graph
│                           │ ──▶ Trace transitive paths (e.g. root ➜ hbs ➜ handlebars)
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│   Interactive Dashboard   │ ──▶ reports/dashboard.html
│   & JSON Audit Report     │ ──▶ reports/scan-result.json
└───────────────────────────┘
```

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10+
- (Optional for live scanning) Docker Desktop for running Syft and Grype

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## ⚡ Running the Guardian

### Quick Scan (Using Sample Goof Data)
```bash
python -m guardian scan targets/goof --sbom reports/goof.sbom.cdx.json -o reports/scan-result.json
```

### Opening the Interactive Dashboard
On Windows (PowerShell):
```powershell
Start-Process "reports/dashboard.html"
```
Or open `reports/dashboard.html` in any web browser.

---

## 🧪 Benchmark Target: Snyk Goof
- **Subject:** `snyk-labs/nodejs-goof` (deliberately vulnerable Node.js demo app)
- **Pinned Commit:** `add14ba59e98240d9e00a235dd7d42cd61ae9912` (documented in `docs/PINNED_COMMIT.txt`)
- **Verified Findings:**
  - 60 total repository files discovered
  - 8 supply-chain control files identified
  - 577 unique SBOM software components
  - 981 dependency graph nodes, 1,479 edges
  - Transitive verification: `<root> ➜ hbs@4.0.4 ➜ handlebars@4.0.14`


# Bosch Hackathon --- Software Supply Chain Guardian

## Project Context, Working Plan, and Day 1 Implementation Guide

**Project motto:** Know what you build. Trust what you ship.\
**Selected baseline repository:** [Snyk Goof ---
`snyk-labs/nodejs-goof`](https://github.com/snyk-labs/nodejs-goof)\
**Current working phase:** Day 1 --- Build the Guardian's Eyes\
**Document purpose:** Give the developer and the Antigravity coding
agent a shared, reliable project brief. Use this as persistent project
context.

------------------------------------------------------------------------

# 1. Project at a Glance

We are building a **Software Supply Chain Guardian**: a
repository-analysis and security-assessment system that discovers the
software components inside a project, maps how they depend on one
another, detects supply-chain risks, and presents evidence-backed
findings.

The system should behave like a small security team rather than a single
chatbot. Deterministic scanners and parsers do the technical inspection;
specialized AI agents investigate, correlate, challenge, prioritize, and
explain findings using evidence gathered from the repository and
scanners.

The selected Goof repository is a **baseline test subject**, not the
product itself. The Guardian must not be hardcoded to Goof. Its design
should be reusable across repositories and should be extensible to other
ecosystems such as npm, Python, Java/Maven, .NET, and Rust.

## Core design principle

**Build a general-purpose Guardian and use Goof to test it. Do not build
a Goof-specific scanner.**

Goof is the first repository we will use to understand the problem,
validate discovery, and test the Day 1 workflow. Repository-specific
paths, package names, versions, vulnerabilities, or assumptions must not
be embedded as fixed logic.

------------------------------------------------------------------------

# 2. Day 1 --- Build the Guardian's Eyes

The Day 1 objective is to discover the software supply chain, detect
risks, and explain what was found with evidence.

The Day 1 requirements supplied in the hackathon brief are grouped
below.

## 2.1 Discover components

The Guardian should:

-   Analyze dependency manifests and lockfiles, including examples such
    as `package.json`, `pom.xml`, and their ecosystem equivalents.
-   Identify direct dependencies.
-   Identify transitive dependencies wherever the available ecosystem
    data supports it.
-   Capture component/package names and versions.
-   Discover relevant repository elements that contribute to the
    software supply chain, not just the top-level manifest.

## 2.2 Build the supply-chain view

The Guardian should:

-   Generate or consume an SBOM using a standard such as **CycloneDX**
    or **SPDX**.
-   Build a dependency graph showing component relationships.
-   Identify component origins where the available metadata supports
    this.
-   Inspect at least one container image or CI/CD workflow.

## 2.3 Detect vulnerabilities

The Guardian should:

-   Correlate discovered components with known vulnerabilities.
-   Capture the vulnerability identifier (for example, CVE or another
    advisory ID).
-   Capture severity.
-   Capture affected component and version.
-   Capture available fixed versions or remediation information when
    supplied by the scanner/advisory source.
-   Trace vulnerable transitive dependencies back through the dependency
    graph to the relevant direct dependency or dependency path.

## 2.4 Detect suspicious changes and supply-chain risks

The Guardian should look for relevant signals such as:

-   Unexpected dependencies.
-   Typosquatting or suspiciously similar package names.
-   Suspicious package updates or version changes.
-   Risky or unexpected install scripts.
-   Unexpected lockfile or dependency changes.
-   Untrusted or unexpected container images.
-   Unsafe or unexpected CI/CD components and configuration.

Do not claim that a package is malicious based only on a name similarity
or one weak signal. Present the signal, evidence, confidence, and reason
for concern.

## 2.5 Present evidence

For each finding, the Guardian should make it clear:

-   What was detected.
-   Which component or repository element is affected.
-   The affected version or configuration, where applicable.
-   The dependency path, when applicable.
-   The supporting evidence and its source.
-   The initial risk level.
-   The reason for the assessment.

The output must be understandable and traceable. An AI-generated
explanation is not a substitute for the underlying evidence.

------------------------------------------------------------------------

# 3. Selected Baseline Repository: Snyk Goof

**Repository:** https://github.com/snyk-labs/nodejs-goof

Goof is a deliberately vulnerable Node.js demonstration application. It
is useful as a test subject because its README describes vulnerable
dependencies, insecure application code, Docker image scanning, and
runtime alerts.

The repository README describes these areas:

-   Exploitable packages with known vulnerabilities.
-   Docker image scanning for base-image/system-library vulnerabilities.
-   Runtime alerts for invocation of vulnerable functions in open-source
    dependencies.
-   A Node.js application using MongoDB.
-   A `package.json` and lockfile-based dependency setup.
-   A `Dockerfile` and `docker-compose.yml`.
-   An `exploits/` directory containing demonstrations.
-   Application code and routes, views, tests, and other project files.

The README also mentions examples of code-level weaknesses, including
open redirect, NoSQL injection, code injection, command execution, XSS,
hardcoded values, security misconfiguration, and insecure HTTP
communication.

**Important verification rule:** README descriptions are leads for
investigation, not proof that every issue is present in the exact
checkout being scanned. Inspect the actual repository contents and
record the commit being tested. Run the selected tools and report their
actual results. Do not copy old vulnerability counts or assume old
package versions are still present.

## How to use Goof

-   Use it as the first validation repository for the Guardian.
-   Inspect it before deciding exactly what the ingestion and discovery
    modules need to support.
-   Record the tested commit/hash so results are reproducible.
-   Run analysis in a controlled local environment.
-   Do not casually execute exploit demonstrations or suspicious
    scripts.
-   Do not publish malicious packages or expose credentials.
-   If test cases need to be introduced, use safe, inert examples in a
    controlled local branch/fork.

------------------------------------------------------------------------

# 4. Day 1 Work Plan --- In the Order We Will Follow

We will work incrementally. Complete and understand one stage before
moving to the next. Do not generate the entire application in one shot.

## Stage 1 --- Explore the baseline repository

Inspect the repository structure and understand the purpose of the
important files and folders.

Areas to inspect include:

-   Application source folders and entry points.
-   Routes, controllers, services, entities/models, views, and public
    assets.
-   `package.json` and `package-lock.json`.
-   Dockerfile and Compose configuration.
-   GitHub Actions or other CI/CD configuration.
-   Tests, examples, and exploit/demo folders.
-   Configuration files and scripts.

**Deliverable:** A repository inventory describing what exists, where it
is located, and why it may matter to software supply-chain analysis.

## Stage 2 --- Define the Guardian's Day 1 scope

Translate the hackathon requirements into a concrete checklist.
Distinguish between:

-   What the Guardian must discover.
-   What it must inspect.
-   What it must detect.
-   What evidence it must retain.
-   What it must report.

Classify capabilities as required for Day 1, useful if time permits, or
explicitly deferred. Do not expand into later-day features.

**Deliverable:** A concise Day 1 scope and acceptance checklist.

## Stage 3 --- Design repository ingestion

Design a reusable way to accept a repository, such as a Git URL or a
local repository path. The ingestion stage should prepare a safe,
traceable workspace and record repository metadata, including the source
and commit when available.

The ingestion module should not assume that every repository is a
Node.js project. It should detect repository characteristics and hand
the workspace to later discovery stages.

**Deliverable:** A repository-ingestion interface and a clear
description of its inputs, outputs, and safety boundaries.

## Stage 4 --- Discover and inventory components

Inspect the repository for supported manifests, lockfiles,
source/configuration files, container definitions, and CI/CD workflows.
Identify the ecosystems present and extract package/component
information using ecosystem-appropriate methods.

For the first baseline, npm/Node.js is the first adapter to validate.
Keep the discovery design extensible so additional ecosystem adapters
can be added later.

**Deliverable:** A normalized inventory of discovered repository
elements and software components, with file/source references.

## Stage 5 --- Generate or consume an SBOM

Produce or ingest an SBOM using CycloneDX or SPDX. Preserve component
identity and available metadata, such as name, version, package URL
(purl), supplier/origin, and dependency relationships where available.

Do not invent missing metadata. Mark unavailable fields as unknown or
omit them.

**Deliverable:** An SBOM artifact and a record of the tool/version and
input used to produce it.

## Stage 6 --- Build the dependency graph

Represent components as nodes and dependency relationships as edges.
Preserve whether a dependency is direct or transitive when that
information is available. Support tracing from a vulnerable transitive
component back to its parent chain and direct dependency.

The graph model should be ecosystem-neutral even if the first
implementation reads npm data.

**Deliverable:** A dependency graph and traceable dependency paths.

## Stage 7 --- Detect known vulnerabilities

Use suitable vulnerability intelligence/scanning tools to correlate
components and versions with known advisories. Normalize results into a
consistent finding format.

Capture, where available:

-   Advisory/CVE identifier.
-   Affected package and version.
-   Severity and its source.
-   Fixed version or remediation guidance.
-   Direct/transitive status.
-   Dependency path.
-   Scanner/advisory source and timestamp.

Do not fabricate CVSS scores, fixes, or vulnerability matches. Preserve
scanner output and provenance.

**Deliverable:** Structured vulnerability findings linked to components
and dependency paths.

## Stage 8 --- Detect suspicious supply-chain signals

Inspect available evidence for unexpected dependencies, suspicious
package names, unusual version changes, risky install scripts,
unexpected lockfile changes, untrusted images, and unsafe CI/CD
configuration.

For change-based detection, establish what the comparison baseline is
(for example, a trusted base commit or a supplied before/after diff). A
single repository snapshot cannot prove that a dependency was newly
introduced unless a comparison source exists.

Treat suspiciousness as a risk signal requiring evidence, not an
automatic declaration of maliciousness.

**Deliverable:** Structured anomaly/suspicious-activity findings with
evidence and confidence/reasoning.

## Stage 9 --- Add agentic orchestration

The system should have an orchestrator that coordinates specialized
agents. The agent design should resemble a mini security team.

Possible responsibilities (names and boundaries can be refined later):

-   **Discovery/Inventory Agent:** reviews the discovered inventory and
    identifies gaps or inconsistencies.
-   **Vulnerability Investigation Agent:** investigates scanner findings
    and affected dependency paths.
-   **Supply-Chain Anomaly Agent:** investigates suspicious package,
    lockfile, container, and CI/CD signals.
-   **Risk Assessment Agent:** correlates evidence and assesses impact
    and priority.
-   **Reporting Agent:** prepares clear evidence-backed explanations.

The orchestrator should assign work, provide relevant evidence, collect
results, resolve disagreements or request further checks, and produce a
consolidated assessment.

**Critical architecture distinction:** Deterministic tools perform
parsing, version resolution, SBOM generation, graph construction, and
vulnerability matching. Agents investigate and reason over the resulting
evidence. Do not make an LLM the source of truth for package versions,
CVE matching, or dependency edges.

A collection of agents that merely rewrites scanner output is not
enough. Agentic behavior should be visible through coordinated
investigation, evidence exchange, follow-up checks, and consolidated
decisions.

**Deliverable:** A working Day 1 orchestration flow with specialized
responsibilities and traceable agent inputs/outputs.

## Stage 10 --- Consolidate findings and report evidence

Create a common finding model so results from different scanners and
agents can be combined without losing their source. Report what was
found, affected components, dependency paths, evidence, severity/risk,
and recommended next investigative action.

Keep tool severity (such as a scanner's severity) distinct from the
Guardian's own risk assessment.

**Deliverable:** A consolidated Day 1 assessment/report.

## Stage 11 --- Present results in a dashboard or report interface

Show the repository identity and tested commit, component inventory,
SBOM, dependency graph, vulnerability findings, suspicious signals, and
evidence-backed agent assessment.

The interface should make it possible to move from a high-level finding
to its underlying component, path, and evidence.

**Deliverable:** A usable Day 1 presentation of the Guardian's results.
The interface can be simple initially; correctness and traceability come
first.

------------------------------------------------------------------------

# 5. Suggested High-Level System Flow

``` text
Repository URL / Local Repository
              |
              v
      Repository Ingestion
              |
              v
      Repository Identification
       (ecosystems and files)
              |
              v
   Component Discovery / Inventory
              |
        +-----+------+
        |            |
        v            v
   SBOM Creation   Container / CI
        |          Configuration
        v            |
 Dependency Graph    |
        |            |
        +------+-----+
               |
               v
      Security Scanning / Checks
       |         |          |
       v         v          v
   Vulnerability  Dependency  Supply-chain
     Checks       Changes     Anomaly Checks
       |         |          |
       +---------+----------+
                 |
                 v
       Normalize and Preserve Evidence
                 |
                 v
         Agent Orchestrator
       /          |            \
      v           v             v
 Vulnerability  Anomaly       Risk / Impact
 Investigation  Investigation  Assessment
       \          |            /
                 v
        Consolidated Findings
                 |
                 v
         Evidence-backed Report
                 |
                 v
             Dashboard
```

This is a conceptual Day 1 flow. The exact module boundaries and tool
choices should be finalized after repository exploration and scope
definition.

------------------------------------------------------------------------

# 6. Architecture Principles

1.  **Repository-agnostic:** Do not hardcode Goof-specific paths,
    packages, versions, or expected findings into the core system.
2.  **Adapter-based:** Use ecosystem-specific discovery adapters that
    normalize data into a common internal representation.
3.  **Evidence-first:** Every finding should point to the file, scanner
    output, advisory, graph path, or other evidence that supports it.
4.  **Deterministic core:** Use parsers and security tools for facts;
    use agents for investigation, correlation, and explanation.
5.  **Traceability:** Record repository URL/path, commit, tool
    name/version, scan time, and relevant configuration.
6.  **Extensible:** Start with npm because Goof is a Node.js repository,
    but avoid designing the entire system around npm.
7.  **Safe by default:** Treat repository contents and scripts as
    untrusted input.
8.  **Human-readable results:** Explain why a finding matters without
    hiding the technical evidence.
9.  **No fabricated certainty:** Distinguish confirmed vulnerabilities,
    suspicious signals, tool warnings, and agent hypotheses.
10. **Incremental delivery:** Build and test one stage at a time.

------------------------------------------------------------------------

# 7. Candidate Technology Options --- Not Yet Final Decisions

These are candidates to evaluate, not mandatory choices. Select tools
based on actual Day 1 requirements, compatibility, output quality, and
ease of integration. Avoid running multiple overlapping scanners without
a clear reason.

  -----------------------------------------------------------------------
  Area                    Candidate options       Purpose
  ----------------------- ----------------------- -----------------------
  Backend/API             Python, FastAPI         Coordinate analysis
                                                  modules and expose
                                                  results

  Agent orchestration     LangGraph or a simpler  Coordinate specialized
                          explicit orchestrator   investigations and
                                                  shared state

  Frontend                React + TypeScript      Display repository
                                                  analysis and findings

  Structured storage      PostgreSQL or a simpler Persist scans and
                          local store for the     normalized findings
                          prototype               

  Dependency graph        NetworkX initially      Represent and trace
                                                  dependency
                                                  relationships

  SBOM                    Syft; CycloneDX/SPDX    Generate or consume
                          tooling                 SBOMs

  Vulnerability scanning  OSV-Scanner, Grype, or  Identify known
                          another suitable        vulnerable components
                          scanner                 

  Container/config        Trivy or another        Inspect container
  scanning                suitable scanner        images and relevant
                                                  configurations

  Source control          Git                     Clone, identify
                                                  commits, and compare
                                                  repository states
  -----------------------------------------------------------------------

Do not install every candidate immediately. First decide what each tool
contributes and whether another selected tool already covers the same
requirement.

------------------------------------------------------------------------

# 8. Common Data Model --- Conceptual Starting Point

The implementation should normalize results from different ecosystems
and tools. The following are conceptual entities, not a finalized
database schema.

-   **Repository:** URL or local source, repository name, detected
    ecosystems, commit/hash, scan identifier.
-   **Repository Element:** file path, file type, role (manifest,
    lockfile, source, Docker, workflow, configuration, test, etc.).
-   **Component:** ecosystem, package name, version, purl when
    available, source/origin metadata when available.
-   **Dependency Relationship:** parent component, child component,
    direct/transitive classification, relationship source.
-   **SBOM Record:** format, tool, tool version, generation time,
    artifact location.
-   **Vulnerability Finding:** advisory ID, component, affected version,
    severity, fixed version if known, source, evidence.
-   **Anomaly Finding:** signal type, affected element/component,
    evidence, rationale, confidence, comparison baseline if applicable.
-   **Risk Assessment:** finding references, risk level, reasoning,
    contributing factors, uncertainty.
-   **Agent Investigation:** agent role, task, evidence received, tools
    invoked, findings returned, unresolved questions.
-   **Scan Run:** start/end time, configuration, tool versions, status,
    errors, repository commit.

Use stable identifiers and preserve links between these records. Do not
force fields to have values when the source does not provide them.

------------------------------------------------------------------------

# 9. Day 1 Acceptance Checklist

Day 1 is not complete merely because a dashboard exists. The system
should demonstrate the following on the Goof baseline:

-   [ ] Accept a repository source and identify the tested commit.
-   [ ] Inspect the repository without assuming it is always a Node.js
    project.
-   [ ] Discover relevant manifests and lockfiles.
-   [ ] Extract component names and versions.
-   [ ] Distinguish direct and transitive dependencies where supported.
-   [ ] Generate or consume a CycloneDX or SPDX SBOM.
-   [ ] Build a dependency graph and trace a dependency path.
-   [ ] Inspect at least one container image or CI/CD workflow.
-   [ ] Run vulnerability correlation/scanning and capture advisory IDs,
    severity, and fixes where available.
-   [ ] Demonstrate a vulnerable transitive dependency path if one is
    actually found by the scan.
-   [ ] Check relevant suspicious supply-chain signals and explain their
    evidence.
-   [ ] Coordinate multiple specialized investigations through an
    orchestrator.
-   [ ] Produce consolidated findings with affected component, path,
    evidence, and initial risk level.
-   [ ] Preserve enough metadata to reproduce or audit the scan.
-   [ ] Avoid hardcoding Goof-specific findings into the Guardian's core
    logic.

If a checklist item cannot be completed, document the limitation and
evidence rather than pretending it passed.

------------------------------------------------------------------------

# 10. Safety and Scope Boundaries

The hackathon brief excludes unauthorized testing of real production
systems and infrastructure. Work only on repositories and environments
that are authorized for this project.

For this project:

-   Do not scan or attack systems outside the authorized repository/test
    environment.
-   Do not publish malicious packages to public registries.
-   Do not expose real credentials, tokens, or secrets in logs or
    reports.
-   Do not execute untrusted install scripts or exploit demonstrations
    casually.
-   Do not run suspicious images without an isolated, controlled
    environment.
-   Prefer static inspection and safe scanner execution.
-   If builds are required, use a disposable isolated workspace and
    restrict unnecessary network access.
-   Do not automatically merge, deploy, or release changes.
-   Keep a human in control of security-sensitive actions.

The current task is Day 1 discovery, mapping, detection, and evidence.
Do not expand the implementation into automated remediation or later-day
stretch goals unless the hackathon team explicitly moves to them.

------------------------------------------------------------------------

# 11. Working Instructions for the Antigravity Agent

Use these instructions whenever assisting with this project.

## Role

Act as a senior software supply-chain security engineer and practical
implementation partner. Help build the Software Supply Chain Guardian
incrementally, with special focus on the current Day 1 requirements.

## Mandatory project context

-   The selected baseline is `https://github.com/snyk-labs/nodejs-goof`.
-   Goof is a test subject, not the product.
-   The Guardian must be reusable and repository-agnostic.
-   The current scope is Day 1 only: discover components, build the
    supply-chain view, detect vulnerabilities, detect suspicious
    changes, and present evidence.
-   The system must include agentic orchestration resembling a mini
    security team.
-   Deterministic tools establish technical facts; agents investigate
    and correlate evidence.
-   The user wants to understand and approve the plan stage by stage. Do
    not rush into a complete implementation.

## How to collaborate

1.  Before coding, inspect the existing workspace and explain what is
    already present.
2.  Work on the current stage only. Do not silently implement future
    stages.
3.  Give a concise plan before making substantial changes.
4.  Ask before making destructive changes, deleting files, replacing
    major architecture, or introducing costly/external services.
5.  Prefer small, testable changes over a large one-shot code
    generation.
6.  After each change, explain which files changed, why, and how to
    run/test it.
7.  Run relevant tests or validation commands when safe and available.
    Report actual outcomes.
8.  Do not claim that a scan, build, test, or integration succeeded
    unless it was actually run and succeeded.
9.  If repository details are unknown, inspect the files rather than
    guessing.
10. If a tool or dependency is proposed, explain why it is needed and
    what requirement it satisfies.
11. Keep the implementation modular and extensible across ecosystems.
12. Keep the user informed and explain technical decisions in clear,
    practical language.

## Coding and security rules

-   Never hardcode Goof's package names, versions, file paths,
    vulnerability counts, or expected findings as core Guardian logic.
-   Do not trust README claims as current scan results; verify the
    checked-out files and run tools.
-   Do not execute arbitrary repository scripts just because they exist.
-   Do not run exploit demonstrations against public or external
    systems.
-   Do not publish packages or images.
-   Do not expose secrets. Redact sensitive values from logs and
    reports.
-   Preserve scanner output and evidence provenance.
-   Clearly label uncertainty, unsupported ecosystems, incomplete scans,
    and tool errors.
-   Do not allow an LLM to invent dependency relationships, CVEs,
    severity, fixed versions, or package metadata.
-   Keep human approval for security-sensitive actions.

## Preferred response style

-   Start with the direct answer.
-   Use clear headings and concise explanations.
-   When the user asks for a short answer, keep it short.
-   Do not overwhelm the user with the entire roadmap during a small
    implementation question.
-   Explain one stage at a time and wait for the user's next question or
    approval before moving on.

------------------------------------------------------------------------

# 12. Current Project Status and Immediate Next Actions

## Decisions already made

-   Project: Software Supply Chain Guardian.
-   Baseline repository: Snyk Goof (`snyk-labs/nodejs-goof`).
-   Product principle: Guardian must be generalizable; Goof is only the
    baseline.
-   Current scope: Day 1 only.
-   Work style: understand, define, implement, and validate
    incrementally.
-   No implementation should be rushed before the repository and
    requirements are understood.

## Current stage

**Stage 1 --- Repository Exploration**, followed by **Stage 2 --- Define
the Guardian's Day 1 Scope**.

The repository README has been provided and reviewed. It describes Goof
as a deliberately vulnerable Node.js demo application and documents its
run instructions, dependency vulnerabilities, code-level vulnerability
examples, Docker scanning, and runtime alerts. These README details
still need to be checked against the exact repository checkout and
commit.

## Immediate next actions

1.  Inspect the repository root and record its folders/files.
2.  Inspect `package.json` and `package-lock.json` to understand npm
    dependencies.
3.  Inspect the source structure and relevant configuration.
4.  Inspect Docker and CI/CD files.
5.  Create a repository inventory.
6.  Convert the Day 1 brief into a scope/acceptance checklist.
7.  Only then finalize the ingestion and discovery design.

**Do not start by generating the entire application. Start by
understanding the repository and agreeing on the Day 1 scope.**

------------------------------------------------------------------------

# 13. Important Terminology

-   **Manifest:** A file declaring project dependencies and metadata,
    such as `package.json` or `pom.xml`.
-   **Lockfile:** A file recording resolved dependency versions and
    related installation information, such as `package-lock.json`.
-   **Direct dependency:** A dependency explicitly declared by the
    project.
-   **Transitive dependency:** A dependency brought in by another
    dependency.
-   **SBOM:** Software Bill of Materials; a structured inventory of
    software components in an application or artifact.
-   **Dependency graph:** A graph representing which components depend
    on which other components.
-   **CVE:** Common Vulnerabilities and Exposures identifier for a
    publicly catalogued vulnerability.
-   **PURL:** Package URL, a standardized way to identify a software
    package.
-   **Provenance:** Information about where a component or artifact came
    from and how it was produced.
-   **Reachability:** Whether vulnerable code can actually be reached or
    invoked in the application. Treat this as a possible deeper
    analysis, not a prerequisite to claiming a scanner finding.
-   **Orchestrator:** The coordinator that assigns tasks to agents,
    shares context/evidence, and consolidates results.
-   **Evidence:** Verifiable source material supporting a finding, such
    as a file/line, lockfile entry, scanner output, advisory, dependency
    path, or workflow configuration.

------------------------------------------------------------------------

**End of project context. Keep the work focused on Day 1 until the team
explicitly changes scope.**

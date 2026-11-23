"""
FastAPI Live Demo Server & AI Security Copilot for Software Supply Chain Guardian.

Provides real-time agent execution streaming via Server-Sent Events (SSE),
interactive AI Copilot Q&A powered by Groq 120B, and report export endpoints.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from guardian.ai import query_groq
from guardian.orchestrator import Orchestrator
from guardian.report_generator import generate_markdown_report

app = FastAPI(
    title="Software Supply Chain Guardian — Live Command Center",
    description="Agentic AI Supply Chain Security Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_RESULT_PATH = Path("reports/scan-result.json")
DASHBOARD_PATH = Path("reports/dashboard.html")
REPORT_MD_PATH = Path("reports/SECURITY-REPORT.md")


def _load_latest_scan() -> Optional[dict]:
    if SCAN_RESULT_PATH.exists():
        try:
            return json.loads(SCAN_RESULT_PATH.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the interactive Guardian Dashboard."""
    if DASHBOARD_PATH.exists():
        return HTMLResponse(content=DASHBOARD_PATH.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Guardian scan has not run yet. Run 'python -m guardian scan' or trigger via API.</h1>")


@app.get("/api/status")
async def get_status():
    """Return system readiness and scan status."""
    has_groq = bool(os.getenv("GROQ_API_KEY"))
    target_exists = Path("targets/goof").is_dir()
    scan_data = _load_latest_scan()

    return {
        "status": "ready",
        "groq_configured": has_groq,
        "target_available": target_exists,
        "has_scan_result": scan_data is not None,
        "components_count": len(scan_data.get("components", [])) if scan_data else 0,
        "findings_count": len(scan_data.get("findings", [])) if scan_data else 0,
    }


@app.get("/api/results")
async def get_results():
    """Return the full current ScanResult payload."""
    scan_data = _load_latest_scan()
    if not scan_data:
        raise HTTPException(status_code=404, detail="No scan result found. Please run a scan first.")
    return JSONResponse(content=scan_data)


@app.get("/api/report/markdown", response_class=PlainTextResponse)
async def get_markdown_report():
    """Return the raw Markdown security report."""
    if REPORT_MD_PATH.exists():
        return REPORT_MD_PATH.read_text(encoding="utf-8")
    scan_data = _load_latest_scan()
    if scan_data:
        # Generate on the fly
        from guardian.models import ScanResult
        sr = ScanResult.model_validate(scan_data)
        return generate_markdown_report(sr)
    raise HTTPException(status_code=404, detail="No scan result found.")


class ScanRequest(BaseModel):
    repo_path: str = "targets/goof"
    sbom_path: Optional[str] = "reports/goof.sbom.cdx.json"
    grype_path: Optional[str] = "reports/goof.grype.json"
    groq_key: Optional[str] = None


@app.post("/api/scan/live")
async def run_live_scan(req: ScanRequest = ScanRequest()):
    """
    Run the multi-agent pipeline and stream real-time events via Server-Sent Events (SSE).
    """
    repo = Path(req.repo_path)
    if not repo.is_dir():
        raise HTTPException(status_code=400, detail=f"Directory '{req.repo_path}' does not exist.")

    event_queue: queue.Queue = queue.Queue()

    def event_callback(phase: str, status: str, data: Any):
        event_queue.put({
            "event": "agent_update",
            "phase": phase,
            "status": status,
            "data": data,
        })

    def run_worker():
        try:
            event_queue.put({"event": "scan_start", "repo": req.repo_path})
            orchestrator = Orchestrator(groq_key=req.groq_key)
            result = orchestrator.run(
                repo_path=req.repo_path,
                sbom_path=req.sbom_path,
                grype_path=req.grype_path,
                output_path=str(SCAN_RESULT_PATH),
                groq_key=req.groq_key,
                callback=event_callback,
            )
            event_queue.put({
                "event": "scan_complete",
                "summary": {
                    "total_components": len(result.components),
                    "total_findings": len(result.findings),
                    "total_elements": len(result.elements),
                },
            })
        except Exception as e:
            event_queue.put({"event": "scan_error", "error": str(e)})
        finally:
            event_queue.put(None)  # Sentinel to end stream

    threading.Thread(target=run_worker, daemon=True).start()

    async def sse_generator():
        while True:
            # Yield control to event loop
            await asyncio.sleep(0.05)
            try:
                item = event_queue.get_nowait()
            except queue.Empty:
                continue

            if item is None:
                break

            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class ChatMessage(BaseModel):
    message: str


@app.post("/api/chat")
async def chat_copilot(msg: ChatMessage):
    """
    Interactive AI Security Copilot powered by Groq 120B.
    Answers developer and judge questions grounded in the actual scan facts.
    """
    scan_data = _load_latest_scan()
    context_str = ""
    if scan_data:
        findings = scan_data.get("findings", [])
        crit_direct = [f for f in findings if f.get("risk_level") == "critical"]
        high_trans = [f for f in findings if f.get("risk_level") == "high"]
        analyst = scan_data.get("agent_results", {}).get("analyst", {}).get("metadata", {})

        context_str = f"""
TARGET REPOSITORY CONTEXT:
- Repository: {scan_data.get('context', {}).get('repo_name', 'goof')}
- Total Components: {len(scan_data.get('components', []))}
- Total Deduplicated Vulnerabilities: {len(findings)}
- Critical Direct Vulnerabilities: {len(crit_direct)} (e.g., ejs@1.0.0, typeorm@0.2.24, mongoose@4.2.4)
- High Risk Transitive Vulnerabilities: {len(high_trans)} (e.g., handlebars@4.0.14 via direct parent hbs@4.0.4)
- Supply Chain Config Issues: unpinned "latest" dependencies (method-override, morgan), unpinned container base image (node:18.13.0), mutable GitHub Action tags (actions/checkout@v3).
- Direct Parent Fixes:
  * ejs: bump to 3.1.7
  * typeorm: bump to 0.3.0
  * mongoose: bump to 6.13.6
  * handlebars transitive: bump direct hbs to ^4.1.2
"""

    system_prompt = f"""You are the Software Supply Chain Guardian AI Copilot, an elite AppSec and software supply chain specialist assisting evaluators and developers.
You answer questions with technical precision, quoting exact CVEs, package versions, dependency graph paths, and actionable remediation commands.
Keep your answers concise, structured (using bolding and code blocks), and grounded in the security scan facts.
{context_str}
"""

    prompt = f"User Question: {msg.message}\n\nPlease provide an authoritative, technically grounded security answer."

    response = query_groq(prompt=prompt, system=system_prompt, max_tokens=600)
    return {"reply": response}

"""
app.py
-------
ConfigSentry Web Dashboard
FastAPI application that accepts config file uploads,
runs audit checks, and returns results in the browser.
"""

import sys
import os
import tempfile
import uuid
from pathlib import Path
from datetime import datetime
from typing import List  # kept for future use

from fastapi import FastAPI, File, UploadFile, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Add parent directory to path so we can import ConfigSentry modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from checks import run_all_checks
from scorer import calculate_score
from reporter import generate_report
from remediator import generate_remediation_script

# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────

app = FastAPI(
    title="ConfigSentry",
    description="Network Device Configuration Auditor",
    version="1.0.0"
)

BASE_DIR  = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.cache = {}  # Fix for newer Jinja2 versions

# Temp storage for generated reports (cleared on restart)
REPORTS_DIR = BASE_DIR / "tmp_reports"
REPORTS_DIR.mkdir(exist_ok=True)

SUPPORTED_DEVICE_TYPES = [
    ("cisco_ios",         "Cisco IOS (ISR, Catalyst)"),
    ("cisco_ios_xe",      "Cisco IOS-XE (Cat8k, CSR1000v)"),
    ("cisco_xr",          "Cisco IOS-XR (ASR, NCS)"),
    ("cisco_nxos",        "Cisco NX-OS (Nexus)"),
    ("cisco_asa",         "Cisco ASA Firewall"),
    ("fortinet",          "Fortinet FortiGate"),
    ("paloalto_panos",    "Palo Alto PAN-OS"),
    ("juniper_junos",     "Juniper JunOS"),
    ("arista_eos",        "Arista EOS"),
    ("huawei",            "Huawei VRP"),
    ("hp_procurve",       "HP ProCurve"),
    ("dell_os10",         "Dell OS10"),
    ("mikrotik_routeros", "MikroTik RouterOS"),
    ("ubiquiti_edge",     "Ubiquiti EdgeRouter"),
]

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Landing page with upload form."""
    context = {
        "request": request,
        "device_types": SUPPORTED_DEVICE_TYPES
    }
    return templates.TemplateResponse(request=request, name="index.html", context=context)


@app.post("/audit", response_class=HTMLResponse)
async def run_audit(
    request: Request,
    config_file: UploadFile = File(...),
    device_type: str = Form(...),
    device_name: str = Form("")
):
    """
    Accept a config file upload, run audit, return results page.
    """
    if not config_file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded.")

    content = await config_file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        raw_config = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read file. Please upload a plain text config file.")

    session_id   = str(uuid.uuid4())[:8]
    timestamp    = datetime.now().isoformat()
    display_name = device_name.strip() or Path(config_file.filename).stem

    findings   = run_all_checks(raw_config, device_type)
    score_data = calculate_score(findings)

    result = {
        "host":       config_file.filename,
        "hostname":   display_name,
        "mode":       "offline",
        "status":     "OK",
        "findings":   findings,
        "score":      score_data,
        "raw_config": raw_config,
        "timestamp":  timestamp,
        "fails":      [f for f in findings if f["severity"] == "FAIL"],
        "warnings":   [f for f in findings if f["severity"] == "WARNING"],
        "passes":     [f for f in findings if f["severity"] == "PASS"],
    }

    # Generate PDF report
    pdf_filename = f"audit_{session_id}.pdf"
    pdf_path     = REPORTS_DIR / pdf_filename
    generate_report([result], output_path=str(pdf_path), fmt="pdf")

    # Generate remediation script
    rem_filename = f"remediation_{session_id}.txt"
    rem_path     = REPORTS_DIR / rem_filename
    generate_remediation_script(result, device_type, str(rem_path))

    context = {
        "request":      request,
        "results":      [result],
        "device_type":  device_type,
        "timestamp":    timestamp[:19].replace("T", " "),
        "pdf_url":      f"/download/{pdf_filename}",
        "rem_files":    [{"name": display_name, "url": f"/download/{rem_filename}"}],
        "total_fails":    len(result["fails"]),
        "total_warnings": len(result["warnings"]),
        "total_passes":   len(result["passes"]),
        "worst_score":    score_data["score"],
        "worst_level":    score_data["risk_level"],
        "multi":          False,
        "device_types":   SUPPORTED_DEVICE_TYPES,
    }
    return templates.TemplateResponse(request=request, name="results.html", context=context)


@app.get("/download/{filename}")
async def download_file(filename: str):
    """Serve a generated report or remediation script for download."""
    # Security: only allow files from our tmp_reports directory
    safe_name = Path(filename).name
    file_path = REPORTS_DIR / safe_name

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found or expired.")

    media_type = "application/pdf" if safe_name.endswith(".pdf") else "text/plain"
    return FileResponse(
        path=str(file_path),
        filename=safe_name,
        media_type=media_type
    )


@app.get("/health")
async def health():
    """Health check endpoint for deployment platforms."""
    return {"status": "ok", "service": "ConfigSentry"}

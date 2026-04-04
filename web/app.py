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
import difflib
from pathlib import Path
from datetime import datetime
from typing import List

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
    config_files: List[UploadFile] = File(...),
    device_types: List[str] = Form(...),
    device_names: List[str] = Form(default=[]),
    custom_checks_file: UploadFile = File(None),
):
    """
    Accept one or more config file uploads (and optional custom checks YAML),
    run audit on each, return combined results page.
    """
    if not config_files or not config_files[0].filename:
        raise HTTPException(status_code=400, detail="No file uploaded.")

    # Normalise device_names list to match length of config_files
    names_list = list(device_names) if device_names else []
    while len(names_list) < len(config_files):
        names_list.append("")

    # Load custom checks once (shared across all uploaded files)
    custom_check_defs = []
    custom_check_count = 0
    if custom_checks_file and custom_checks_file.filename:
        try:
            from custom_checks import load_custom_checks_from_string, run_custom_checks
            yaml_content = (await custom_checks_file.read()).decode("utf-8", errors="replace")
            custom_check_defs = load_custom_checks_from_string(yaml_content) or []
            custom_check_count = len(custom_check_defs)
        except Exception:
            pass  # Custom checks are optional — silently skip on any error

    session_id = str(uuid.uuid4())[:8]
    timestamp  = datetime.now().isoformat()
    results    = []

    for idx, (upload, device_type, raw_name) in enumerate(
        zip(config_files, device_types, names_list)
    ):
        if not upload.filename:
            continue

        content = await upload.read()
        if not content:
            continue

        try:
            raw_config = content.decode("utf-8", errors="replace")
        except Exception:
            continue

        display_name = raw_name.strip() or Path(upload.filename).stem

        findings = run_all_checks(raw_config, device_type)

        if custom_check_defs:
            from custom_checks import run_custom_checks
            extra    = run_custom_checks(raw_config, device_type, custom_check_defs)
            findings.extend(extra)

        score_data = calculate_score(findings)

        results.append({
            "host":        upload.filename,
            "hostname":    display_name,
            "device_type": device_type,
            "mode":        "offline",
            "status":      "OK",
            "findings":    findings,
            "score":       score_data,
            "raw_config":  raw_config,
            "timestamp":   timestamp,
            "fails":       [f for f in findings if f["severity"] == "FAIL"],
            "warnings":    [f for f in findings if f["severity"] == "WARNING"],
            "passes":      [f for f in findings if f["severity"] == "PASS"],
        })

    if not results:
        raise HTTPException(status_code=400, detail="No valid config files could be processed.")

    multi = len(results) > 1

    # Generate combined PDF report
    pdf_filename = f"audit_{session_id}.pdf"
    pdf_path     = REPORTS_DIR / pdf_filename
    generate_report(results, output_path=str(pdf_path), fmt="pdf")

    # Generate per-device remediation scripts
    rem_files = []
    for result in results:
        rem_filename = f"remediation_{session_id}_{result['hostname']}.txt"
        rem_path     = REPORTS_DIR / rem_filename
        generate_remediation_script(result, result["device_type"], str(rem_path))
        rem_files.append({"name": result["hostname"], "url": f"/download/{rem_filename}"})

    # Summary stats
    total_fails    = sum(len(r["fails"])    for r in results)
    total_warnings = sum(len(r["warnings"]) for r in results)
    total_passes   = sum(len(r["passes"])   for r in results)
    worst          = max(results, key=lambda r: r["score"]["score"])

    context = {
        "request":            request,
        "results":            results,
        "device_type":        results[0]["device_type"] if not multi else "multiple",
        "timestamp":          timestamp[:19].replace("T", " "),
        "pdf_url":            f"/download/{pdf_filename}",
        "rem_files":          rem_files,
        "total_fails":        total_fails,
        "total_warnings":     total_warnings,
        "total_passes":       total_passes,
        "worst_score":        worst["score"]["score"],
        "worst_level":        worst["score"]["risk_level"],
        "multi":              multi,
        "device_types":       SUPPORTED_DEVICE_TYPES,
        "custom_check_count": custom_check_count,
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


@app.post("/diff", response_class=HTMLResponse)
async def run_diff(
    request: Request,
    config_before: UploadFile = File(...),
    config_after:  UploadFile = File(...),
    device_type:   str = Form(...),
    device_name:   str = Form(""),
):
    """
    Accept two versions of the same device config (before/after),
    run audit on both, and return a change-tracking diff report.
    """
    if not config_before.filename or not config_after.filename:
        raise HTTPException(status_code=400, detail="Both config files are required.")

    before_raw = (await config_before.read()).decode("utf-8", errors="replace")
    after_raw  = (await config_after.read()).decode("utf-8", errors="replace")

    if not before_raw.strip() or not after_raw.strip():
        raise HTTPException(status_code=400, detail="One or both config files appear to be empty.")

    display_name = device_name.strip() or Path(config_before.filename).stem
    timestamp    = datetime.now().isoformat()

    # ── Run checks on both versions ───────────────────────────────
    findings_before = run_all_checks(before_raw, device_type)
    findings_after  = run_all_checks(after_raw,  device_type)

    score_before = calculate_score(findings_before)
    score_after  = calculate_score(findings_after)

    # ── Build lookup maps by check_id ────────────────────────────
    before_map = {f["check_id"]: f for f in findings_before}
    after_map  = {f["check_id"]: f for f in findings_after}
    all_ids    = sorted(set(before_map) | set(after_map))

    NEW_RISKS    = []   # PASS/absent → FAIL/WARNING
    RESOLVED     = []   # FAIL/WARNING → PASS
    WORSENED     = []   # WARNING → FAIL
    IMPROVED     = []   # FAIL → WARNING
    UNCHANGED    = []   # same severity

    SEV_RANK = {"PASS": 0, "WARNING": 1, "FAIL": 2}

    for cid in all_ids:
        b = before_map.get(cid)
        a = after_map.get(cid)
        sev_b = b["severity"] if b else "PASS"
        sev_a = a["severity"] if a else "PASS"
        rank_b = SEV_RANK.get(sev_b, 0)
        rank_a = SEV_RANK.get(sev_a, 0)

        entry = {
            "check_id":    cid,
            "title":       (a or b)["title"],
            "detail_b":    b["detail"]       if b else "Check not present in before config.",
            "detail_a":    a["detail"]       if a else "Check not present in after config.",
            "remediation": (a or b).get("remediation", ""),
            "sev_before":  sev_b,
            "sev_after":   sev_a,
        }

        if rank_a > rank_b:
            if sev_b == "PASS":
                NEW_RISKS.append(entry)
            else:
                WORSENED.append(entry)
        elif rank_a < rank_b:
            if sev_a == "PASS":
                RESOLVED.append(entry)
            else:
                IMPROVED.append(entry)
        else:
            UNCHANGED.append(entry)

    # ── Line-level diff (unified, limited to 400 lines for performance) ──
    before_lines = before_raw.splitlines(keepends=True)
    after_lines  = after_raw.splitlines(keepends=True)
    udiff = list(difflib.unified_diff(
        before_lines, after_lines,
        fromfile=config_before.filename,
        tofile=config_after.filename,
        lineterm=""
    ))
    # Annotate each diff line for the template
    diff_lines = []
    for line in udiff[:600]:   # cap at 600 lines for browser performance
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            diff_lines.append({"type": "meta",    "text": line})
        elif line.startswith("+"):
            diff_lines.append({"type": "added",   "text": line})
        elif line.startswith("-"):
            diff_lines.append({"type": "removed", "text": line})
        else:
            diff_lines.append({"type": "context", "text": line})

    diff_truncated = len(udiff) > 600

    # ── Score delta ───────────────────────────────────────────────
    score_delta = score_after["score"] - score_before["score"]

    context = {
        "request":        request,
        "device_name":    display_name,
        "device_type":    device_type,
        "file_before":    config_before.filename,
        "file_after":     config_after.filename,
        "timestamp":      timestamp[:19].replace("T", " "),
        "score_before":   score_before,
        "score_after":    score_after,
        "score_delta":    score_delta,
        "new_risks":      NEW_RISKS,
        "resolved":       RESOLVED,
        "worsened":       WORSENED,
        "improved":       IMPROVED,
        "unchanged":      UNCHANGED,
        "diff_lines":     diff_lines,
        "diff_truncated": diff_truncated,
        "total_changed":  len(NEW_RISKS) + len(RESOLVED) + len(WORSENED) + len(IMPROVED),
    }
    return templates.TemplateResponse(request=request, name="diff.html", context=context)


@app.get("/health")
async def health():
    """Health check endpoint for deployment platforms."""
    return {"status": "ok", "service": "ConfigSentry"}

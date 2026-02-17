import re
import os
import time
import hashlib
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Any
from groq import Groq

from utils.repo_handler import clone_repo, cleanup_repo
from utils.file_scanner import scan_files
from agents.secrets_agent import detect_secrets
from agents.sql_agent import detect_sql_injection
from agents.auth_agent import detect_missing_auth
from agents.ai_explainer import enhance_findings_with_ai

# Load .env so GROQ_API_KEY is available
load_dotenv()

# Groq client for /generate-fix
_GROQ_API_KEY = os.getenv("GROQ_API_KEY")
_groq_client = Groq(api_key=_GROQ_API_KEY) if _GROQ_API_KEY else None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security-auditor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CLONE_FAIL_MSG = "Unable to scan this repository. Try another public repository."
CLONE_TIMEOUT_SECONDS = 120  # generous clone timeout

# Thread pool — 3 workers lets agents run in parallel
_executor = ThreadPoolExecutor(max_workers=3)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI Security Auditor",
    description="Analyze GitHub repositories for security vulnerabilities",
    version="1.0.0"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global exception handler — never leak stack traces
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": "Something went wrong. Please try again later."},
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    repo_url: str


class Finding(BaseModel):
    file: str
    line: int
    type: str
    severity: str
    explanation: str


class AuditReport(BaseModel):
    repo_url: str
    scan_time_seconds: float
    files_scanned: int
    summary: Dict[str, int]
    findings: Dict[str, List[Dict[str, Any]]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def generate_summary(findings: Dict[str, List]) -> Dict[str, int]:
    """Generate a summary of findings by severity."""
    summary = {
        'total_findings': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'secrets_detected': 0,
        'sql_injection': 0,
        'missing_auth': 0,
    }

    for category, items in findings.items():
        summary['total_findings'] += len(items)
        summary[category] = len(items)

        for item in items:
            severity = item.get('severity', 'MEDIUM').lower()
            if severity in summary:
                summary[severity] += 1

    return summary


def _run_agents_parallel(files):
    """
    Run all three detection agents in parallel and merge results.
    """
    from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed

    tasks = {
        'secrets_detected': detect_secrets,
        'sql_injection': detect_sql_injection,
        'missing_auth': detect_missing_auth,
    }
    findings = {}

    with _TPE(max_workers=3) as pool:
        futures = {pool.submit(fn, files): name for name, fn in tasks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                findings[name] = fut.result()
            except Exception as exc:
                logger.warning("Agent %s failed: %s", name, exc)
                findings[name] = []

    return findings


def _blocking_scan(repo_url: str):
    """
    Clone → scan → detect pipeline (blocking).

    GUARANTEE: If clone succeeds, this function NEVER raises.
    It always returns a valid result dict with partial results.

    Only raises if clone itself fails.
    """
    repo_path = None

    # ── STEP 1: Clone (this CAN raise) ──────────────────────────
    repo_path = clone_repo(repo_url)
    logger.info("CLONE SUCCESS: %s", repo_url)

    # ── STEP 2: Everything after clone is wrapped — NEVER fails ─
    try:
        # Scan files
        scan_result = scan_files(repo_path)
        files = scan_result["files"]
        total_found = scan_result["total_found"]
        was_truncated = scan_result["was_truncated"]

        logger.info("FILES FOUND: %d code files (loaded %d)", total_found, len(files))

        if not files:
            # Zero files is NOT a failure — return valid partial result
            return {
                "files": [],
                "findings": {"secrets_detected": [], "sql_injection": [], "missing_auth": []},
                "repo_path": repo_path,
                "total_found": total_found,
                "was_truncated": True,  # always flag as partial when 0 files scanned
                "scan_notice": "No supported source files (.py, .js, .ts) found in initial scan window.",
            }

        # Run security agents in parallel
        findings = _run_agents_parallel(files)

        # AI explanations — graceful degradation
        try:
            findings = enhance_findings_with_ai(findings)
        except Exception as ai_err:
            logger.warning("AI explanation failed, returning raw findings: %s", ai_err)

        # Build notice
        scan_notice = None
        if was_truncated:
            scan_notice = (
                f"Large repository detected. "
                f"Showing results from first {len(files)} of {total_found} files."
            )

        return {
            "files": files,
            "findings": findings,
            "repo_path": repo_path,
            "total_found": total_found,
            "was_truncated": was_truncated,
            "scan_notice": scan_notice,
        }

    except Exception as post_clone_err:
        # Post-clone failure — NEVER propagate, return safe partial result
        logger.exception("Post-clone processing failed, returning empty results: %s", post_clone_err)
        return {
            "files": [],
            "findings": {"secrets_detected": [], "sql_injection": [], "missing_auth": []},
            "repo_path": repo_path,
            "total_found": 0,
            "was_truncated": True,
            "scan_notice": "Scan completed with limited results due to repository complexity.",
        }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "running", "service": "AI Security Auditor"}


@app.post("/analyze")
async def analyze_repo(request: AnalyzeRequest):
    """
    Analyze a GitHub repository for security vulnerabilities.

    Scans for:
    - Hardcoded secrets (API keys, passwords, tokens)
    - SQL injection vulnerabilities
    - Missing authentication on endpoints
    """
    start_time = time.time()
    repo_path = None

    url = request.repo_url.strip()
    if not url:
        return JSONResponse(status_code=400, content={"error": "Please enter a repository URL."})

    # ── CLONE PHASE (only this can return failure) ──────────────
    try:
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(_executor, _blocking_scan, url),
                timeout=CLONE_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.warning("Scan timed out for %s", url)
            return JSONResponse(
                status_code=400,
                content={"error": CLONE_FAIL_MSG},
            )
    except Exception as e:
        # Clone failed — this is the ONLY place we return the failure message
        logger.exception("Clone failed for %s", url)
        return JSONResponse(
            status_code=400,
            content={"error": CLONE_FAIL_MSG},
        )

    # ── POST-CLONE: result is GUARANTEED to be a valid dict ────
    try:
        repo_path = result["repo_path"]
        files = result.get("files", [])
        findings = result.get("findings", {"secrets_detected": [], "sql_injection": [], "missing_auth": []})
        total_found = result.get("total_found", 0)
        was_truncated = result.get("was_truncated", False)
        scan_notice = result.get("scan_notice")

        summary = generate_summary(findings)
        scan_time = time.time() - start_time

        partial_scan = was_truncated or total_found > len(files)

        return {
            "repo_url": url,
            "scan_time_seconds": round(scan_time, 2),
            "files_scanned": len(files),
            "total_files": total_found,
            "partial_scan": partial_scan,
            "scan_notice": scan_notice,
            "summary": summary,
            "findings": findings,
        }
    finally:
        if repo_path:
            cleanup_repo(repo_path)


# ---------------------------------------------------------------------------
# Generate Secure Fix endpoint
# ---------------------------------------------------------------------------
class FixRequest(BaseModel):
    vulnerability_type: str
    code_snippet: str

# Simple in-memory cache  {hash -> fixed_code}
_fix_cache: Dict[str, str] = {}


@app.post("/generate-fix")
async def generate_fix(request: FixRequest):
    """Use Groq to generate a secure rewrite of vulnerable code."""
    vuln_type = request.vulnerability_type.strip()
    snippet = request.code_snippet.strip()

    if not snippet:
        return JSONResponse(status_code=400, content={"error": "No code snippet provided."})

    # Cache key
    cache_key = hashlib.sha256(f"{vuln_type}::{snippet}".encode()).hexdigest()
    if cache_key in _fix_cache:
        return {"fixed_code": _fix_cache[cache_key], "cached": True}

    if not _groq_client:
        return JSONResponse(
            status_code=200,
            content={"fixed_code": "AI fix unavailable. Showing manual fix suggestion.", "cached": False},
        )

    prompt = (
        f"Vulnerability type: {vuln_type}\n"
        f"Vulnerable code:\n```\n{snippet[:500]}\n```\n\n"
        "Rewrite this code securely. Return only the fixed code, no explanation."
    )

    try:
        response = _groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security engineer. Return only fixed code."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=500,
        )
        fixed_code = response.choices[0].message.content.strip()

        # Strip surrounding markdown fences if present
        if fixed_code.startswith("```"):
            lines = fixed_code.split("\n")
            lines = lines[1:]  # remove opening ```lang
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            fixed_code = "\n".join(lines)

        _fix_cache[cache_key] = fixed_code
        return {"fixed_code": fixed_code, "cached": False}

    except Exception as e:
        logger.exception("Groq generate-fix failed")
        return JSONResponse(
            status_code=200,
            content={"fixed_code": "AI fix unavailable. Showing manual fix suggestion.", "cached": False},
        )


# ---------------------------------------------------------------------------
# Fix All Issues (per file) endpoint
# ---------------------------------------------------------------------------
class VulnItem(BaseModel):
    type: str
    line: int = 0
    code_snippet: str = ""

class FixAllRequest(BaseModel):
    filename: str
    vulnerabilities: List[VulnItem]


@app.post("/fix-all")
async def fix_all(request: FixAllRequest):
    """Rewrite an entire file securely, fixing all listed vulnerabilities."""
    filename = request.filename.strip()
    vulns = request.vulnerabilities

    if not vulns:
        return JSONResponse(status_code=400, content={"error": "No vulnerabilities provided."})

    # Cache key based on filename + all vulns
    raw = filename + "::" + "||".join(f"{v.type}:{v.line}:{v.code_snippet}" for v in vulns)
    cache_key = hashlib.sha256(raw.encode()).hexdigest()
    if cache_key in _fix_cache:
        return {"fixed_file": _fix_cache[cache_key], "cached": True}

    if not _groq_client:
        return JSONResponse(
            status_code=200,
            content={"fixed_file": "AI fix unavailable. Showing manual fix suggestion.", "cached": False},
        )

    # Build vulnerability list for the prompt
    vuln_lines = []
    for v in vulns:
        snippet = v.code_snippet[:200] if v.code_snippet else "(no snippet)"
        vuln_lines.append(f"- Line {v.line}: {v.type} → {snippet}")

    prompt = (
        f"File: {filename}\n\n"
        f"Vulnerabilities found:\n" + "\n".join(vuln_lines) + "\n\n"
        "Rewrite this file securely. Fix all listed vulnerabilities. "
        "Return only the full corrected file, no explanation."
    )

    try:
        response = _groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security engineer. Return only the corrected file code."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=2000,
        )
        fixed = response.choices[0].message.content.strip()

        # Strip markdown fences
        if fixed.startswith("```"):
            lines = fixed.split("\n")
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            fixed = "\n".join(lines)

        _fix_cache[cache_key] = fixed
        return {"fixed_file": fixed, "cached": False}

    except Exception as e:
        logger.exception("Groq fix-all failed")
        return JSONResponse(
            status_code=200,
            content={"fixed_file": "AI fix unavailable. Showing manual fix suggestion.", "cached": False},
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

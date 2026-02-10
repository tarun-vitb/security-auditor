from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Any
import time

from utils.repo_handler import clone_repo, cleanup_repo
from utils.file_scanner import scan_files
from agents.secrets_agent import detect_secrets
from agents.sql_agent import detect_sql_injection
from agents.auth_agent import detect_missing_auth
from agents.ai_explainer import enhance_findings_with_ai


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


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "running", "service": "AI Security Auditor"}


@app.post("/analyze", response_model=AuditReport)
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
    
    try:
        # Validate URL
        if not request.repo_url.startswith(('https://github.com/', 'git@github.com:')):
            raise HTTPException(
                status_code=400,
                detail="Only GitHub repository URLs are supported"
            )
        
        # Clone the repository
        repo_path = clone_repo(request.repo_url)
        
        # Scan for relevant files
        files = scan_files(repo_path)
        
        if not files:
            raise HTTPException(
                status_code=400,
                detail="No .py, .js, or .ts files found in the repository"
            )
        
        # Run security agents
        findings = {
            'secrets_detected': detect_secrets(files),
            'sql_injection': detect_sql_injection(files),
            'missing_auth': detect_missing_auth(files),
        }
        
        # Enhance findings with AI explanations
        findings = enhance_findings_with_ai(findings)
        
        # Generate summary
        summary = generate_summary(findings)
        
        scan_time = time.time() - start_time
        
        return AuditReport(
            repo_url=request.repo_url,
            scan_time_seconds=round(scan_time, 2),
            files_scanned=len(files),
            summary=summary,
            findings=findings
        )
        
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
    finally:
        # Cleanup cloned repo
        if repo_path:
            cleanup_repo(repo_path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

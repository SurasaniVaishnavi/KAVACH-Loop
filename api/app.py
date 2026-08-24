import json
import subprocess
import sys
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_DIR = PROJECT_ROOT / "website"
SUMMARY_FILE = WEBSITE_DIR / "data/verification-summary.json"
REPORT_FILE = PROJECT_ROOT / "reports/patch_verification.json"
APPROVAL_FILE = PROJECT_ROOT / "approvals/patch_approval.json"
HARNESS_FILE = PROJECT_ROOT / "harness/verify_patch.py"

ASAN_TRIGGER = PROJECT_ROOT / "crash_inputs/asan_trigger.txt"
AFL_CRASH = PROJECT_ROOT / "crash_inputs/afl_crash.bin"

VERIFY_LOCK = threading.Lock()

app = FastAPI(
    title="KAVACH-Loop Restricted Verification API",
    description=(
        "Local defensive API for reading sanitized evidence and running "
        "one fixed verification workflow."
    ),
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail=f"Required evidence file is unavailable: {path.name}",
        ) from error
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=500,
            detail=f"Evidence file is invalid: {path.name}",
        ) from error


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    return response


@app.get("/api/health")
def health() -> dict:
    return {
        "project": "KAVACH-Loop",
        "service": "restricted-verification-api",
        "status": "healthy",
        "mode": "local-defensive-poc",
    }


@app.get("/api/status")
def status() -> dict:
    return load_json(SUMMARY_FILE)


@app.get("/api/evidence")
def evidence() -> dict:
    verification = load_json(REPORT_FILE)
    approval = load_json(APPROVAL_FILE)

    sanitized_checks = {}

    for name, result in verification.get("checks", {}).items():
        sanitized_checks[name] = {
            "passed": bool(result.get("passed")),
            "return_code": result.get("return_code"),
            "finding_count": result.get("finding_count"),
        }

    return {
        "project": verification.get("project", "KAVACH-Loop"),
        "harness_decision": verification.get(
            "harness_decision",
            "UNKNOWN",
        ),
        "human_approval_required": verification.get(
            "human_approval_required",
            True,
        ),
        "human_decision": approval.get("decision", "NOT RECORDED"),
        "checks": sanitized_checks,
    }


@app.post("/api/verify")
def run_verification() -> dict:
    if not VERIFY_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail="A verification run is already in progress.",
        )

    try:
        missing_inputs = [
            path.name
            for path in (ASAN_TRIGGER, AFL_CRASH)
            if not path.is_file()
        ]

        if missing_inputs:
            raise HTTPException(
                status_code=503,
                detail={
                    "message": "Required local regression input is unavailable.",
                    "missing": missing_inputs,
                },
            )

        try:
            result = subprocess.run(
                [sys.executable, str(HARNESS_FILE)],
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=90,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise HTTPException(
                status_code=504,
                detail="Verification exceeded the 90-second limit.",
            ) from error

        report = load_json(REPORT_FILE)

        allowed_prefixes = (
            "compilation:",
            "normal_input:",
            "asan_crash_replay:",
            "afl_crash_replay:",
            "semgrep:",
            "HARNESS DECISION:",
            "Human approval required:",
        )

        summary = [
            line
            for line in result.stdout.splitlines()
            if line.startswith(allowed_prefixes)
        ]

        return {
            "completed": True,
            "exit_code": result.returncode,
            "harness_decision": report.get(
                "harness_decision",
                "UNKNOWN",
            ),
            "summary": summary,
            "human_approval_required": True,
            "automatic_merge": False,
            "automatic_deployment": False,
        }
    finally:
        VERIFY_LOCK.release()


app.mount(
    "/assets",
    StaticFiles(directory=WEBSITE_DIR / "assets"),
    name="assets",
)

app.mount(
    "/data",
    StaticFiles(directory=WEBSITE_DIR / "data"),
    name="data",
)


@app.get("/")
def dashboard():
    return FileResponse(WEBSITE_DIR / "index.html")
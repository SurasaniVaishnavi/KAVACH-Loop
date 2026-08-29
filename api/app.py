import json
import re
import secrets
import subprocess
import sys
import threading
import asyncio
from datetime import datetime, timezone
from typing import Literal
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from agents.evidence_analyst import (
    EvidenceAnalystError,
    analyze_evidence,
)



PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_DIR = PROJECT_ROOT / "website"
SUMMARY_FILE = WEBSITE_DIR / "data/verification-summary.json"
REPORT_FILE = PROJECT_ROOT / "reports/patch_verification.json"
APPROVAL_FILE = PROJECT_ROOT / "approvals/patch_approval.json"
HARNESS_FILE = PROJECT_ROOT / "harness/verify_patch.py"
C_ANALYZER_FILE = PROJECT_ROOT / "harness/analyze_c_file.py"
RUNTIME_JOBS = PROJECT_ROOT / "runtime_jobs"
INTAKE_REPORTS = PROJECT_ROOT / "reports" / "intake"
HUMAN_REVIEW_REPORTS = PROJECT_ROOT / "reports" / "human_reviews"


ASAN_TRIGGER = PROJECT_ROOT / "crash_inputs/asan_trigger.txt"
AFL_CRASH = PROJECT_ROOT / "crash_inputs/afl_crash.bin"

MAX_C_SOURCE_BYTES = 64 * 1024
JOB_ID_PATTERN = re.compile(r"^[0-9a-f]{12}-[0-9a-f]{8}$")

VERIFY_LOCK = threading.Lock()
EVIDENCE_AGENT_LOCK = asyncio.Lock()
MAX_AGENT_REQUEST_BYTES = 32 * 1024
INTAKE_LOCK = threading.Lock()
HUMAN_REVIEW_LOCK = threading.Lock()

class HumanReviewRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    job_id: str = Field(
        min_length=21,
        max_length=21,
        pattern=r"^[0-9a-f]{12}-[0-9a-f]{8}$",
    )
    source_sha256: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    human_decision: Literal[
        "CONFIRMED_FINDING",
        "REJECTED_CONCLUSION",
    ]
    reviewer_note: str = Field(
        min_length=10,
        max_length=500,
    )

app = FastAPI(
    title="KAVACH-Loop Restricted Verification API",
    description=(
        "Local defensive API for sanitized evidence, one fixed regression "
        "workflow and controlled standalone C-source intake."
    ),
    version="3.0.0",
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
            "passed": result.get("passed"),
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


@app.post("/api/analyze/c")
async def analyze_c_upload(
    source: UploadFile = File(...),
) -> dict:
    if not INTAKE_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail="A controlled intake analysis is already running.",
        )

    runtime_file = None

    try:
        original_name = source.filename or ""

        if (
            not original_name
            or "/" in original_name
            or "\\" in original_name
            or Path(original_name).name != original_name
        ):
            raise HTTPException(
                status_code=400,
                detail="A simple source filename is required.",
            )

        if Path(original_name).suffix.lower() != ".c":
            raise HTTPException(
                status_code=400,
                detail="Only standalone .c source files are accepted.",
            )

        source_bytes = await source.read(MAX_C_SOURCE_BYTES + 1)

        if not source_bytes:
            raise HTTPException(
                status_code=400,
                detail="Empty source files are not accepted.",
            )

        if len(source_bytes) > MAX_C_SOURCE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Source exceeds the 64 KiB limit.",
            )

        if b"\x00" in source_bytes:
            raise HTTPException(
                status_code=400,
                detail="Binary data is not accepted.",
            )

        try:
            source_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HTTPException(
                status_code=400,
                detail="Source must be valid UTF-8 or ASCII text.",
            ) from error

        if not C_ANALYZER_FILE.is_file():
            raise HTTPException(
                status_code=503,
                detail="Controlled C analyzer is unavailable.",
            )

        RUNTIME_JOBS.mkdir(exist_ok=True)

        runtime_file = RUNTIME_JOBS / f"upload-{uuid4().hex}.c"

        with runtime_file.open("xb") as file_handle:
            file_handle.write(source_bytes)

        runtime_file.chmod(0o600)

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(C_ANALYZER_FILE),
                    str(runtime_file),
                ],
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise HTTPException(
                status_code=504,
                detail="Controlled analysis exceeded 60 seconds.",
            ) from error

        if result.returncode == 2:
            raise HTTPException(
                status_code=400,
                detail="Submitted source failed intake validation.",
            )

        if result.returncode not in (0, 1):
            raise HTTPException(
                status_code=500,
                detail="Controlled analyzer did not complete normally.",
            )

        job_id = ""

        for line in result.stdout.splitlines():
            if line.startswith("Job ID:"):
                job_id = line.removeprefix("Job ID:").strip()
                break

        if not JOB_ID_PATTERN.fullmatch(job_id):
            raise HTTPException(
                status_code=500,
                detail="Analyzer returned an invalid job identifier.",
            )

        report_file = INTAKE_REPORTS / f"{job_id}.json"
        report = load_json(report_file)
        report_source = report.get("source")

        if not isinstance(report_source, dict):
            raise HTTPException(
                status_code=500,
                detail="Analyzer source metadata is invalid.",
            )

        report_source["original_name"] = original_name

        report_file.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        compilation = report.get(
            "checks",
            {},
        ).get("syntax_compilation", {})
        compilation_diagnostic = compilation.get("stderr", "")

        if not isinstance(compilation_diagnostic, str):
            compilation_diagnostic = ""

        compilation_diagnostic = compilation_diagnostic[:2000]

        semgrep = report.get(
            "checks",
            {},
        ).get("semgrep", {})

        return {
            "completed": True,
            "job_id": job_id,
            "source": {
                "original_name": original_name,
                "size_bytes": report.get(
                    "source",
                    {},
                ).get("size_bytes"),
                "sha256": report.get(
                    "source",
                    {},
                ).get("sha256"),
            },
            "checks": {
                "syntax_compilation": {
                    "passed": compilation.get("passed"),
                    "return_code": compilation.get("return_code"),
                    "diagnostic": compilation_diagnostic,
                },
                "semgrep": {
                    "completed": semgrep.get("completed"),
                    "return_code": semgrep.get("return_code"),
                    "finding_count": semgrep.get("finding_count"),
                    "findings": semgrep.get("findings", []),
                },
            },
            "analysis_decision": report.get(
                "analysis_decision",
                "UNKNOWN",
            ),
            "review_priority": report.get(
                "review_priority",
                "UNASSESSED",
            ),
            "source_executed": False,
            "automatic_patch": False,
            "automatic_merge": False,
            "automatic_deployment": False,
            "human_review_required": True,
        }
    finally:
        await source.close()

        if runtime_file is not None:
            runtime_file.unlink(missing_ok=True)

        INTAKE_LOCK.release()
@app.post("/api/review/finding")
def record_human_finding_review(
    review: HumanReviewRequest,
) -> dict:
    if not HUMAN_REVIEW_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=409,
            detail="Another human review is being recorded.",
        )

    try:
        intake_report_file = (
            INTAKE_REPORTS / f"{review.job_id}.json"
        )
        intake_report = load_json(intake_report_file)

        source = intake_report.get("source", {})

        if not isinstance(source, dict):
            raise HTTPException(
                status_code=409,
                detail="The saved intake source metadata is invalid.",
            )

        saved_sha256 = source.get("sha256", "")

        if (
            not isinstance(saved_sha256, str)
            or not secrets.compare_digest(
                saved_sha256,
                review.source_sha256,
            )
        ):
            raise HTTPException(
                status_code=409,
                detail="The review does not match the saved intake report.",
            )

        automated_decision = intake_report.get(
            "analysis_decision",
            "UNKNOWN",
        )
        review_priority = intake_report.get(
            "review_priority",
            "UNASSESSED",
        )

        allowed_decisions = {
            "REVIEW_REQUIRED",
            "NO_SUPPORTED_FINDINGS",
            "COMPILATION_FAILED",
            "ANALYSIS_ERROR",
        }
        allowed_priorities = {
            "HIGH",
            "MEDIUM",
            "LOW",
            "NONE_IDENTIFIED",
            "UNASSESSED",
        }

        if automated_decision not in allowed_decisions:
            raise HTTPException(
                status_code=409,
                detail="The saved automated decision is invalid.",
            )

        if review_priority not in allowed_priorities:
            review_priority = "UNASSESSED"

        if (
            review.human_decision == "CONFIRMED_FINDING"
            and automated_decision != "REVIEW_REQUIRED"
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "A finding can be confirmed only when the "
                    "deterministic decision is REVIEW_REQUIRED."
                ),
            )

        if any(
            ord(character) < 32
            and character not in "\n\t"
            for character in review.reviewer_note
        ):
            raise HTTPException(
                status_code=400,
                detail="The reviewer note contains invalid characters.",
            )

        review_id = (
            f"{review.job_id}-{uuid4().hex[:8]}"
        )

        review_record = {
            "project": "KAVACH-Loop",
            "record_type": "local_human_finding_review",
            "review_id": review_id,
            "recorded_at_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "source": {
                "original_name": source.get(
                    "original_name",
                    "authorized-source.c",
                ),
                "sha256": saved_sha256,
            },
            "intake_job_id": review.job_id,
            "automated_decision": automated_decision,
            "review_priority": review_priority,
            "human_decision": review.human_decision,
            "reviewer_note": review.reviewer_note,
            "human_review_recorded": True,
            "identity_verified": False,
            "local_demo_only": True,
            "source_executed": False,
            "patch_generated": False,
            "patch_approved": False,
            "automatic_merge": False,
            "automatic_deployment": False,
        }

        HUMAN_REVIEW_REPORTS.mkdir(
            parents=True,
            exist_ok=True,
        )
        review_file = (
            HUMAN_REVIEW_REPORTS / f"{review_id}.json"
        )
        review_file.write_text(
            json.dumps(review_record, indent=2),
            encoding="utf-8",
        )

        return review_record
    finally:
        HUMAN_REVIEW_LOCK.release()


@app.get("/api/agent/status")
async def evidence_analyst_status() -> dict:
    busy = EVIDENCE_AGENT_LOCK.locked()

    return {
        "agent": "KAVACH-Loop Evidence Analyst",
        "provider": "local-ollama",
        "status": "busy" if busy else "ready",
        "busy": busy,
        "accepts_raw_source": False,
        "evidence_only": True,
        "human_review_required": True,
        "automatic_patch": False,
        "automatic_merge": False,
        "automatic_deployment": False,
    }
@app.post("/api/agent/analyze-evidence")
async def run_evidence_analyst(request: Request) -> dict:
    if EVIDENCE_AGENT_LOCK.locked():
        raise HTTPException(
            status_code=409,
            detail="The Evidence Analyst is already processing a report.",
        )

    await EVIDENCE_AGENT_LOCK.acquire()

    try:
        request_body = await request.body()

        if not request_body:
            raise HTTPException(
                status_code=400,
                detail="A sanitized evidence report is required.",
            )

        if len(request_body) > MAX_AGENT_REQUEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail="The evidence report exceeds the 32 KiB limit.",
            )

        try:
            report = json.loads(request_body)
        except json.JSONDecodeError as error:
            raise HTTPException(
                status_code=400,
                detail="The evidence report is not valid JSON.",
            ) from error

        if not isinstance(report, dict):
            raise HTTPException(
                status_code=400,
                detail="The evidence report must be a JSON object.",
            )

        if not isinstance(report.get("source"), dict):
            raise HTTPException(
                status_code=400,
                detail="Source metadata is missing from the evidence.",
            )

        if not isinstance(report.get("checks"), dict):
            raise HTTPException(
                status_code=400,
                detail="Deterministic checks are missing from the evidence.",
            )

        if not isinstance(report.get("analysis_decision"), str):
            raise HTTPException(
                status_code=400,
                detail="The deterministic decision is missing.",
            )

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(
                    analyze_evidence,
                    report,
                ),
                timeout=250,
            )
        except EvidenceAnalystError as error:
            raise HTTPException(
                status_code=503,
                detail=str(error),
            ) from error
        except TimeoutError as error:
            raise HTTPException(
                status_code=504,
                detail="The local Evidence Analyst exceeded the 250-second limit.",
            ) from error
    finally:
        EVIDENCE_AGENT_LOCK.release()
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
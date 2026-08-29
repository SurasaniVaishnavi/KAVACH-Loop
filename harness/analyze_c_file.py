import argparse
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTROLLED_ROOT = (PROJECT_ROOT / "controlled_inputs" / "c").resolve()
RUNTIME_ROOT = PROJECT_ROOT / "runtime_jobs"
REPORT_ROOT = PROJECT_ROOT / "reports" / "intake"
SEMGREP_RULESET = PROJECT_ROOT / "semgrep_rules"

MAX_SOURCE_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 30


class IntakeError(Exception):
    pass


def is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_source(source: Path) -> tuple[Path, bytes]:
    if source.is_symlink():
        raise IntakeError("Symbolic links are not accepted")

    try:
        resolved = source.resolve(strict=True)
    except FileNotFoundError as error:
        raise IntakeError("Source file does not exist") from error

    if not resolved.is_file():
        raise IntakeError("Submitted path is not a regular file")

    allowed_source_roots = (
        CONTROLLED_ROOT,
        RUNTIME_ROOT.resolve(),
    )

    if not any(
        is_inside(resolved, root)
        for root in allowed_source_roots
    ):
        raise IntakeError(
            "Source must be inside an approved intake workspace"
        )

    if resolved.suffix.lower() != ".c":
        raise IntakeError("Only .c source files are accepted")

    size = resolved.stat().st_size

    if size == 0:
        raise IntakeError("Empty source files are not accepted")

    if size > MAX_SOURCE_BYTES:
        raise IntakeError("Source exceeds the 64 KiB limit")

    source_bytes = resolved.read_bytes()

    if b"\x00" in source_bytes:
        raise IntakeError("Binary data is not accepted")

    try:
        source_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IntakeError("Source must be valid UTF-8 or ASCII text") from error

    return resolved, source_bytes


def run_command(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["SEMGREP_ENABLE_VERSION_CHECK"] = "0"

    return subprocess.run(
        arguments,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
        env=environment,
    )


def clean_output(text: str, job_directory: Path) -> str:
    return (
        text.replace(str(job_directory), "<JOB>")
        .replace(str(PROJECT_ROOT), "<PROJECT_ROOT>")
        .strip()
    )


def analyze_source(source: Path) -> dict:
    resolved, source_bytes = validate_source(source)

    for required_tool in ("clang", "semgrep"):
        if shutil.which(required_tool) is None:
            raise IntakeError(
                f"Required local tool is unavailable: {required_tool}"
            )

    if not SEMGREP_RULESET.is_dir():
        raise IntakeError("Approved Semgrep ruleset is unavailable")

    RUNTIME_ROOT.mkdir(exist_ok=True)
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)

    digest = sha256(source_bytes).hexdigest()
    job_id = f"{digest[:12]}-{uuid4().hex[:8]}"

    with tempfile.TemporaryDirectory(
        prefix=f"{job_id}-",
        dir=RUNTIME_ROOT,
    ) as temporary_directory:
        job_directory = Path(temporary_directory)
        job_source = job_directory / "submission.c"
        job_source.write_bytes(source_bytes)

        compilation = run_command([
            "clang",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-fsyntax-only",
            str(job_source),
        ])

        semgrep = run_command([
            "semgrep",
            "scan",
            "--config",
            str(SEMGREP_RULESET),
            "--json",
            str(job_source),
        ])

        semgrep_results = []
        semgrep_json_valid = False

        try:
            semgrep_data = json.loads(semgrep.stdout)
            semgrep_results = semgrep_data.get("results", [])
            semgrep_json_valid = True
        except json.JSONDecodeError:
            semgrep_data = {}

        compilation_passed = compilation.returncode == 0
        semgrep_completed = (
            semgrep.returncode == 0
            and semgrep_json_valid
        )
        finding_count = len(semgrep_results)

        if not semgrep_completed:
            decision = "ANALYSIS_ERROR"
        elif not compilation_passed:
            decision = "COMPILATION_FAILED"
        elif finding_count > 0:
            decision = "REVIEW_REQUIRED"
        else:
            decision = "NO_SUPPORTED_FINDINGS"

        findings = []

        for result in semgrep_results:
            findings.append({
                "check_id": result.get("check_id"),
                "line": result.get("start", {}).get("line"),
                "message": result.get("extra", {}).get("message", "").strip(),
                "severity": result.get("extra", {}).get("severity"),
            })
        if not semgrep_completed or not compilation_passed:
            review_priority = "UNASSESSED"
        else:
            severities = {
                str(finding.get("severity", "")).upper()
                for finding in findings
            }

            if "ERROR" in severities:
                review_priority = "HIGH"
            elif "WARNING" in severities:
                review_priority = "MEDIUM"
            elif "INFO" in severities:
                review_priority = "LOW"
            elif finding_count == 0:
                review_priority = "NONE_IDENTIFIED"
            else:
                review_priority = "UNASSESSED"

        report = {
            "project": "KAVACH-Loop",
            "profile": "controlled_standalone_c",
            "job_id": job_id,
            "generated_at_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "source": {
                "original_name": resolved.name,
                "size_bytes": len(source_bytes),
                "sha256": digest,
            },
            "checks": {
                "syntax_compilation": {
                    "passed": compilation_passed,
                    "return_code": compilation.returncode,
                    "stderr": clean_output(
                        compilation.stderr,
                        job_directory,
                    ),
                },
                "semgrep": {
                    "completed": semgrep_completed,
                    "return_code": semgrep.returncode,
                    "finding_count": finding_count,
                    "findings": findings,
                    "stderr": clean_output(
                        semgrep.stderr,
                        job_directory,
                    ),
                },
            },
            "analysis_decision": decision,
            "review_priority": review_priority,
            "source_executed": False,
            "automatic_patch": False,
            "automatic_merge": False,
            "automatic_deployment": False,
            "human_review_required": True,
        }

    report_file = REPORT_ROOT / f"{job_id}.json"
    report_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"Job ID: {job_id}")
    print(
        "Syntax compilation:",
        "PASS" if compilation_passed else "FAIL",
    )
    print(f"Semgrep findings: {finding_count}")
    print(f"ANALYSIS DECISION: {decision}")
    print("Source executed: False")
    print("Human review required: True")
    print(f"Report saved: {report_file}")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze one authorized standalone C source file."
    )
    parser.add_argument(
        "source",
        type=Path,
                help="C file located inside an approved intake workspace",
    )
    arguments = parser.parse_args()

    try:
        report = analyze_source(arguments.source)
    except IntakeError as error:
        print(f"INTAKE REJECTED: {error}")
        raise SystemExit(2) from error
    except subprocess.TimeoutExpired as error:
        print("ANALYSIS ERROR: A tool exceeded the 30-second limit")
        raise SystemExit(3) from error

    if report["analysis_decision"] == "ANALYSIS_ERROR":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
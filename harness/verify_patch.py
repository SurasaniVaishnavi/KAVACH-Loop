import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PATCHED_SOURCE = PROJECT_ROOT / "patch_candidates/target_patched.c"
PATCHED_BINARY = PROJECT_ROOT / "build/target_patched_asan"
ASAN_TRIGGER = PROJECT_ROOT / "crash_inputs/asan_trigger.txt"
AFL_CRASH = PROJECT_ROOT / "crash_inputs/afl_crash.bin"
SEMGREP_RULE = PROJECT_ROOT / "semgrep_rules/unsafe_strcpy.yml"
REPORT_FILE = PROJECT_ROOT / "reports/patch_verification.json"


def run_command(command, input_data=None):
    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )


def contains_asan_error(result):
    combined = result.stdout + result.stderr
    return b"ERROR: AddressSanitizer" in combined


def main():
    checks = {}

    compile_result = run_command([
        "clang",
        "-g",
        "-O1",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        str(PATCHED_SOURCE),
        "-o",
        str(PATCHED_BINARY),
    ])

    checks["compilation"] = {
        "passed": compile_result.returncode == 0,
        "return_code": compile_result.returncode,
        "stderr": compile_result.stderr.decode(errors="replace"),
    }

    if compile_result.returncode != 0:
        final_status = "FAIL"
    else:
        normal_result = run_command(
            [str(PATCHED_BINARY)],
            input_data=b"Vaishnavi",
        )

        checks["normal_input"] = {
            "passed": (
                normal_result.returncode == 0
                and normal_result.stdout == b"Hello, Vaishnavi\n"
                and not contains_asan_error(normal_result)
            ),
            "return_code": normal_result.returncode,
            "stdout": normal_result.stdout.decode(errors="replace"),
            "stderr": normal_result.stderr.decode(errors="replace"),
        }

        asan_result = run_command(
            [str(PATCHED_BINARY)],
            input_data=ASAN_TRIGGER.read_bytes(),
        )

        checks["asan_crash_replay"] = {
            "passed": (
                asan_result.returncode == 1
                and b"Error: input is too long" in asan_result.stderr
                and not contains_asan_error(asan_result)
            ),
            "return_code": asan_result.returncode,
            "asan_error_present": contains_asan_error(asan_result),
            "stderr": asan_result.stderr.decode(errors="replace"),
        }

        afl_result = run_command(
            [str(PATCHED_BINARY)],
            input_data=AFL_CRASH.read_bytes(),
        )

        checks["afl_crash_replay"] = {
            "passed": (
                afl_result.returncode == 1
                and b"Error: input is too long" in afl_result.stderr
                and not contains_asan_error(afl_result)
            ),
            "return_code": afl_result.returncode,
            "asan_error_present": contains_asan_error(afl_result),
            "stderr": afl_result.stderr.decode(errors="replace"),
        }

        semgrep_result = run_command([
            "semgrep",
            "scan",
            "--config",
            str(SEMGREP_RULE),
            str(PATCHED_SOURCE),
            "--json",
        ])

        try:
            semgrep_data = json.loads(semgrep_result.stdout)
            finding_count = len(semgrep_data.get("results", []))
        except json.JSONDecodeError:
            finding_count = None

        checks["semgrep"] = {
            "passed": (
                semgrep_result.returncode == 0
                and finding_count == 0
            ),
            "return_code": semgrep_result.returncode,
            "finding_count": finding_count,
            "stderr": semgrep_result.stderr.decode(errors="replace"),
        }

        final_status = (
            "PASS"
            if all(check["passed"] for check in checks.values())
            else "FAIL"
        )

    report = {
        "project": "KAVACH-Loop",
        "stage": "candidate_verification",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "candidate": "patch_candidates/target_patched.c",
        "checks": checks,
        "harness_decision": final_status,
        "human_approval_required": True,
    }

    REPORT_FILE.parent.mkdir(exist_ok=True)
    REPORT_FILE.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    for name, result in checks.items():
        status = "PASS" if result["passed"] else "FAIL"
        print(f"{name}: {status}")

    print(f"HARNESS DECISION: {final_status}")
    print("Human approval required: True")
    print(f"Report saved: {REPORT_FILE}")

    raise SystemExit(0 if final_status == "PASS" else 1)


if __name__ == "__main__":
    main()
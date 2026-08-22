import json
import re
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
CRASH_DIR = PROJECT_ROOT / "crash_inputs"
REPORT_DIR = PROJECT_ROOT / "reports"


def read_text(path):
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main():
    REPORT_DIR.mkdir(exist_ok=True)

    asan_report = read_text(EVIDENCE_DIR / "asan_report_before.txt")
    afl_asan_report = read_text(
        EVIDENCE_DIR / "afl_asan_report_before.txt"
    )
    afl_stats = read_text(
        EVIDENCE_DIR / "afl_fuzzer_stats_before.txt"
    )

    semgrep_file = EVIDENCE_DIR / "semgrep_before.json"
    semgrep_results = []

    if semgrep_file.exists():
        semgrep_data = json.loads(
            semgrep_file.read_text(encoding="utf-8")
        )
        semgrep_results = semgrep_data.get("results", [])

    def stat_value(name):
        match = re.search(
            rf"^{re.escape(name)}\s*:\s*(.+)$",
            afl_stats,
            re.MULTILINE,
        )
        return match.group(1).strip() if match else None

    report = {
        "project": "KAVACH-Loop",
        "stage": "before_repair",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": "vulnerable_samples/target.c",
        "vulnerability": {
            "type": "stack-buffer-overflow",
            "unsafe_function": "strcpy",
            "cwe": "CWE-120",
        },
        "asan": {
            "detected": (
                "ERROR: AddressSanitizer: stack-buffer-overflow"
                in asan_report
            ),
            "report": "evidence/asan_report_before.txt",
            "reproducer": "crash_inputs/asan_trigger.txt",
        },
        "semgrep": {
            "finding_count": len(semgrep_results),
            "rule_ids": [
                result.get("check_id") for result in semgrep_results
            ],
            "report": "evidence/semgrep_before.json",
        },
        "afl": {
            "crash_replay_detected": (
                "ERROR: AddressSanitizer: stack-buffer-overflow"
                in afl_asan_report
            ),
            "execs_done": stat_value("execs_done"),
            "saved_crashes": stat_value("saved_crashes"),
            "saved_hangs": stat_value("saved_hangs"),
            "reproducer": "crash_inputs/afl_crash.bin",
            "asan_replay_report":
                "evidence/afl_asan_report_before.txt",
            "statistics":
                "evidence/afl_fuzzer_stats_before.txt",
        },
    }

    checks_passed = (
        report["asan"]["detected"]
        and report["semgrep"]["finding_count"] >= 1
        and report["afl"]["crash_replay_detected"]
    )

    report["evidence_complete"] = checks_passed

    output_file = REPORT_DIR / "evidence_bundle_before.json"
    output_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"ASan overflow detected: {report['asan']['detected']}")
    print(f"Semgrep findings: {report['semgrep']['finding_count']}")
    print(
        "AFL crash replay detected: "
        f"{report['afl']['crash_replay_detected']}"
    )
    print(f"AFL executions: {report['afl']['execs_done']}")
    print(f"AFL saved crashes: {report['afl']['saved_crashes']}")
    print(f"Evidence complete: {report['evidence_complete']}")
    print(f"Report saved: {output_file}")


if __name__ == "__main__":
    main()
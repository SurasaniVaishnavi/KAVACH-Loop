#!/usr/bin/env bash
set -u

cd "$(dirname "$0")/.." || exit 1

echo "======================================"
echo "       KAVACH-Loop Defensive PoC"
echo "======================================"

echo
echo "[1] Vulnerable sample"
echo "File: vulnerable_samples/target.c"
echo "Unsafe strcpy occurrences:"
grep -n "strcpy" vulnerable_samples/target.c || true

echo
echo "[2] Approved secure version"
echo "File: approved_patches/target_approved.c"
if grep -n "strcpy" approved_patches/target_approved.c; then
    echo "WARNING: strcpy was found"
else
    echo "PASS: unsafe strcpy is absent"
fi

echo
echo "[3] Normal-input test"
printf 'hello\n' | ./build/target_approved
normal_status=${PIPESTATUS[1]}
echo "Exit code: $normal_status"

echo
echo "[4] Oversized-input safety test"
python3 -c 'print("A" * 100)' | ./build/target_approved
long_status=${PIPESTATUS[1]}
echo "Exit code: $long_status"

echo
echo "[5] Evidence integrity check"
sha256sum -c evidence/final_manifest.sha256

echo
echo "[6] Recorded decisions"
python3 - <<'PY'
import json

with open("reports/patch_verification.json", encoding="utf-8") as file:
    verification = json.load(file)

with open("approvals/patch_approval.json", encoding="utf-8") as file:
    approval = json.load(file)

print("Harness decision:", verification["harness_decision"])
print("Human approval:", approval["decision"])
print(
    "Human approval required:",
    verification["human_approval_required"],
)
PY

echo
echo "Demo complete: no files were modified or deployed."
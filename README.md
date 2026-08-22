# KAVACH-Loop

KAVACH-Loop is an evidence-guided, human-approved vulnerability-remediation prototype developed for an authorized defensive cybersecurity college project.

The current proof of concept demonstrates a controlled repair workflow for a deliberately vulnerable local C program. Automated tools produce verification evidence, but they do not approve, merge or deploy the patch.

## Core workflow

1. Detect unsafe code.
2. reproduce the issue using controlled local testing.
3. Create a minimal patch candidate.
4. Verify compilation, normal behaviour and security regressions.
5. Require human review and approval.
6. Store regression memory and integrity-protected evidence.

## Current PoC scenario

The demonstration uses an intentionally vulnerable C sample containing unsafe `strcpy()` usage.

The approved version:

- Rejects oversized input safely.
- Preserves expected normal-input behaviour.
- Produces no AddressSanitizer crash during regression replay.
- Passes the recorded AFL++ crash replay.
- Contains no unsafe `strcpy()` finding in the configured static check.

## Verification tools

- Semgrep — static detection
- AddressSanitizer — memory-safety verification
- AFL++ — defensive fuzz testing
- GCC — compilation and warnings
- Python — verification harness and evidence reporting
- SHA-256 — evidence-integrity verification
- HTML, CSS and JavaScript — read-only demonstration dashboard

## Trust model

KAVACH-Loop separates generation from verification:

- A patch candidate does not approve itself.
- The verification harness determines automated pass or fail.
- A passing harness result still requires human review.
- No patch is automatically merged or deployed.
- Regression evidence is preserved for future candidates.

## Run the terminal demonstration

From the project directory:

```bash
./demo/run_demo.sh
```

## Run the dashboard locally

```bash
python3 -m http.server 8000 --directory website
```

Then open:

```text
http://localhost:8000
```

## Current scope

This repository contains a small proof of concept, not the complete proposed production system. It currently validates one controlled C memory-safety scenario.

Future work may include:

- Multiple vulnerability classes
- AI-assisted patch-candidate generation
- Confidence-based candidate gating
- Stronger isolated execution
- Expanded regression memory
- Role-based human approval
- Air-gapped deployment support
- A complete evidence and audit dashboard

## Safety boundary

This is an authorized defensive prototype using locally created files and test data. The deliberately vulnerable sample exists only for controlled before-and-after demonstration.

KAVACH-Loop is not proposed for unsupervised deployment on live operational or classified systems.
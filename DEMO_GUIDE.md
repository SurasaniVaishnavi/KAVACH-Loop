# KAVACH-Loop PoC Demo

KAVACH-Loop is an evidence-guided, human-approved vulnerability-remediation prototype.

## Demonstrated workflow

1. Identify unsafe code in a deliberately vulnerable local C sample.
2. Reproduce and record the vulnerability using defensive testing tools.
3. Create a minimal patch candidate.
4. Verify compilation, normal behaviour and security regressions.
5. Require human review before approval.
6. Preserve regression memory and integrity-checked evidence.

## Run the demonstration

From the project directory:

```bash
./demo/run_demo.sh
```

## Expected result

- Vulnerable sample contains unsafe `strcpy()`.
- Approved source does not contain unsafe `strcpy()`.
- Normal input exits with code `0`.
- Oversized input is rejected with code `1`.
- Evidence integrity checks report `OK`.
- Harness decision is `PASS`.
- Human decision is `APPROVED`.

## Safety boundary

This is an authorized defensive college prototype using only locally created test files. The deliberately vulnerable sample is retained solely for controlled before-and-after demonstration. No patch is deployed or merged automatically.
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

## Version 2 containerized demonstration

Start the restricted API container:

```bash
docker compose up -d
```

Open the interactive dashboard:

```text
http://127.0.0.1:8001
```

Click **Run verification** and confirm:

- Harness decision: `PASS`
- Compilation: `PASS`
- Normal-input test: `PASS`
- ASan crash replay: `PASS`
- AFL++ crash replay: `PASS`
- Semgrep: `PASS`
- Automatic merge: disabled
- Automatic deployment: disabled
- Human approval remains required

Explain to the judges that the browser does not submit commands or external targets. It can only request execution of the predefined defensive verification harness inside the restricted local container.

After the demonstration, stop the container:

```bash
docker compose down
```
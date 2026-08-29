# KAVACH-Loop Demo Guide

KAVACH-Loop is an evidence-guided defensive security prototype developed for Terrier Cyber Quest 2026.

The demonstration contains two controlled paths:

- **Path A:** authorized standalone C-file analysis, restricted local AI explanation and human finding review
- **Path B:** isolated verification of the existing baseline candidate patch

## Safety statement

Use only the locally created fixtures in `controlled_inputs/c/` or another file that you are explicitly authorized to analyze.

The platform does not:

- Execute uploaded C programs
- Send the complete uploaded source to the model
- Generate a patch for uploaded files
- Approve a patch automatically
- Merge code
- Deploy changes
- Accept external scan targets

## Start the platform

From the repository root:

```bash
docker compose up --detach --build
```

For a fresh Ollama volume:

```bash
docker compose exec kavach-ollama \
  ollama pull qwen3.5:0.8b
```

Check both services:

```bash
docker compose ps
```

Open:

```text
http://127.0.0.1:8001
```

## Path A — Authorized file analysis

### Demonstrate CWE-120 detection

Upload:

```text
controlled_inputs/c/unsafe_strcpy_demo.c
```

Select **Analyze C file**.

Expected:

- Syntax compilation: `PASS`
- Supported Semgrep findings: `1`
- Decision: `REVIEW_REQUIRED`
- Review priority: `HIGH`
- Source executed: `false`

### Demonstrate CWE-134 detection

Upload:

```text
controlled_inputs/c/unsafe_format_string.c
```

Select **Analyze another C file**.

Expected:

- Syntax compilation: `PASS`
- Supported Semgrep findings: `1`
- Rule: `kavach-uncontrolled-printf-format`
- Decision: `REVIEW_REQUIRED`
- Review priority: `HIGH`

This second result demonstrates that the controlled intake is not limited to the original unsafe-`strcpy` example.

### Run the Evidence Analyst

Select **Explain latest evidence**.

Expected:

- Provider: local Ollama
- Model: `qwen3.5:0.8b`
- Deterministic decision remains `REVIEW_REQUIRED`
- Review priority remains `HIGH`
- Structured summary, root cause and evidence
- Recommended human action
- Explicit limitations and safety guardrail

The model receives sanitized evidence rather than the complete source file. It cannot change the deterministic decision or priority.

### Download sanitized evidence

Select **Download sanitized report**.

Open the JSON briefly and confirm that it contains:

- Source metadata
- Sanitized compiler and Semgrep evidence
- Deterministic decision
- Review priority
- Advisory AI explanation
- Safety-control fields

The complete C source should not appear in the report.

### Record a human finding decision

Enter a reviewer note of 10–500 characters.

Example:

```text
Confirmed after reviewing the deterministic CWE-134 evidence. The finding requires manual remediation review.
```

Select **Confirm finding**.

Expected:

- Human decision: `CONFIRMED_FINDING`
- Review priority: `HIGH`
- Identity verified: `false`
- Local demo only: `true`
- Patch generated: `false`
- Patch approved: `false`
- Automatic merge: disabled
- Automatic deployment: disabled

Select **Download review record** to obtain the source-hash-bound local review record.

The **Reject automated conclusion** control can record human disagreement. It does not modify the deterministic analysis result.

## Safe-file control

Upload:

```text
controlled_inputs/c/safe_format_string.c
```

Expected:

- Decision: `NO_SUPPORTED_FINDINGS`
- Review priority: `NONE_IDENTIFIED`
- The interface does not claim that the file is completely secure
- **Confirm finding** remains disabled

## Invalid and adversarial controls

The repository includes:

```text
controlled_inputs/c/invalid_syntax.c
controlled_inputs/c/adversarial_test.c
```

Expected for both:

- Decision: `COMPILATION_FAILED`
- Review priority: `UNASSESSED`
- Source is not executed
- Untrusted prompt-like compiler text does not control the final agent response
- Human review remains required

## Path B — Isolated baseline verification

Select **Run verification**.

Expected:

- Compilation: `PASS`
- Normal input: `PASS`
- ASan crash replay: `PASS`
- AFL++ crash replay: `PASS`
- Semgrep: `PASS`
- Harness decision: `PASS`
- Human approval required: `True`
- Automatic merge: disabled
- Automatic deployment: disabled

Path B verifies only the predefined baseline candidate and regression inputs. It does not analyze the uploaded Path A file.

## Container restrictions to mention

The API container uses:

- Non-root user `10001:10001`
- Read-only root filesystem
- All Linux capabilities dropped
- `no-new-privileges`
- CPU, memory and PID limits
- Temporary `tmpfs` workspaces
- API binding only to `127.0.0.1:8001`

Ollama has no host-published port and is accessible only through the private Docker network.

## Recorded demonstration

The compressed demonstration is available at:

```text
docs/demo/kavach-loop-tcq-2026-demo.mp4
```

Full-resolution screenshots are available in:

```text
docs/images/
```

## Stop the platform

```bash
docker compose down
```

The Ollama model remains stored in the Docker volume after the services stop.
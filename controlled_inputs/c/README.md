# Controlled C Input Profile

This directory contains only intentionally selected, authorized C source files used to test KAVACH-Loop.

## Initial supported scope

- One standalone `.c` source file per analysis job.
- Maximum source size: 64 KiB.
- UTF-8 or ASCII text source only.
- Compilation with Clang using strict warnings.
- Static analysis using approved local Semgrep rules.
- No automatic merge or deployment.
- Human review remains mandatory.

## Initial restrictions

- No executables, archives, object files or binary data.
- No user-supplied shell commands or compiler flags.
- No network, database, hardware or external-service access.
- No Makefile, CMake or multi-file project support.
- Submitted programs are not executed during the first intake stage.
- Dynamic testing will be added only with additional sandbox controls.

Only files created by or explicitly authorized by the project owner may be analyzed.
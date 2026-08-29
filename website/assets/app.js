"use strict";

document.addEventListener("DOMContentLoaded", async () => {
    const runButton = document.querySelector("#run-verification");
    const resultPanel = document.querySelector("#verification-result");
    const intakeForm = document.querySelector("#c-intake-form");
    const fileInput = document.querySelector("#c-source-file");
    const analyzeButton = document.querySelector("#analyze-c-file");
    const intakeResult = document.querySelector("#c-intake-result");
    const agentButton = document.querySelector(
        "#run-evidence-agent"
    );
    const agentResult = document.querySelector(
        "#evidence-agent-result"
    );
    const downloadAgentButton = document.querySelector(
        "#download-agent-report"
    );
    const agentReport = document.querySelector(
        "#evidence-agent-report"
    );

    const agentReportFields = {
        decision: document.querySelector(
            "#agent-report-decision"
        ),
        priority: document.querySelector(
            "#agent-report-priority"
        ),
        confidence: document.querySelector(
            "#agent-report-confidence"
        ),
        model: document.querySelector(
            "#agent-report-model"
        ),
        elapsed: document.querySelector(
            "#agent-report-elapsed"
        ),
        summary: document.querySelector(
            "#agent-report-summary"
        ),
        rootCause: document.querySelector(
            "#agent-report-root-cause"
        ),
        evidence: document.querySelector(
            "#agent-report-evidence"
        ),
        action: document.querySelector(
            "#agent-report-action"
        ),
        limitations: document.querySelector(
            "#agent-report-limitations"
        )
    };

    const humanReviewGate = document.querySelector(
        "#human-review-gate"
    );
    const humanReviewNote = document.querySelector(
        "#human-review-note"
    );
    const confirmFindingButton = document.querySelector(
        "#confirm-finding"
    );
    const rejectConclusionButton = document.querySelector(
        "#reject-conclusion"
    );
    const downloadReviewButton = document.querySelector(
        "#download-review-record"
    );
    const humanReviewResult = document.querySelector(
        "#human-review-result"
    );


    let latestIntakeEvidence = null;
    let latestAgentReport = null;
    let latestHumanReviewRecord = null;

    const internalLinks = document.querySelectorAll('a[href^="#"]');

    internalLinks.forEach((link) => {
        link.addEventListener("click", (event) => {
            const targetId = link.getAttribute("href");

            if (!targetId || targetId === "#") {
                return;
            }

            const target = document.querySelector(targetId);

            if (target) {
                event.preventDefault();
                target.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });
            }
        });
    });
    function replaceReportList(listElement, items) {
        if (!listElement) {
            return;
        }

        listElement.replaceChildren();

        const safeItems =
            Array.isArray(items) && items.length > 0
                ? items
                : ["Not provided"];

        safeItems.forEach((item) => {
            const listItem = document.createElement("li");
            listItem.textContent = String(item);
            listElement.appendChild(listItem);
        });
    }

    function renderAgentReport(data, elapsedSeconds) {
        if (!agentReport) {
            return;
        }

        const analysis =
            data && typeof data.analysis === "object"
                ? data.analysis
                : {};

        if (agentReportFields.decision) {
            agentReportFields.decision.textContent =
                data.deterministic_decision || "UNKNOWN";
        }
        if (agentReportFields.priority) {
            agentReportFields.priority.textContent =
                data.review_priority || "UNASSESSED";
        }

        if (agentReportFields.confidence) {
            agentReportFields.confidence.textContent =
                analysis.confidence || "NOT AVAILABLE";
        }

        if (agentReportFields.model) {
            agentReportFields.model.textContent =
                data.model || "NOT AVAILABLE";
        }

        if (agentReportFields.elapsed) {
            agentReportFields.elapsed.textContent =
                `${elapsedSeconds} seconds`;
        }

        if (agentReportFields.summary) {
            agentReportFields.summary.textContent =
                analysis.summary || "No summary was returned.";
        }

        if (agentReportFields.rootCause) {
            agentReportFields.rootCause.textContent =
                analysis.root_cause ||
                "No root cause was established.";
        }

        if (agentReportFields.action) {
            agentReportFields.action.textContent =
                analysis.recommended_next_action ||
                "Human review remains required.";
        }

        replaceReportList(
            agentReportFields.evidence,
            analysis.key_evidence
        );

        replaceReportList(
            agentReportFields.limitations,
            analysis.limitations
        );

        agentReport.hidden = false;

        if (agentResult) {
            agentResult.hidden = true;
        }
    }
    function displayEvidence(evidence) {
        const summaryValues = document.querySelectorAll(
            ".summary-card strong"
        );

        const workflowMode =
    typeof evidence.workflow_mode === "string"
        ? evidence.workflow_mode
            .replace(" autonomy", "")
            .toUpperCase()
        : "SUPERVISED";

        const summaryData = [
            evidence.harness_decision,
            evidence.human_decision,
            evidence.checks.evidence_integrity,
            workflowMode
        ];

        summaryValues.forEach((element, index) => {
            if (summaryData[index]) {
                element.textContent = summaryData[index];
            }
        });

        const checkValues = document.querySelectorAll(
            ".evidence-panel .check-row strong"
        );

        const checkData = [
            evidence.checks.compilation,
            evidence.checks.normal_input,
            evidence.checks.asan_crash_replay,
            evidence.checks.afl_crash_replay,
            evidence.checks.unsafe_strcpy_check,
            evidence.human_decision,
            evidence.checks.evidence_integrity
        ];

        checkValues.forEach((element, index) => {
            if (checkData[index]) {
                element.textContent = checkData[index];
            }
        });
    }

    async function loadEvidence() {
        try {
            const apiResponse = await fetch("/api/status", {
                headers: {
                    Accept: "application/json"
                }
            });

            if (!apiResponse.ok) {
                throw new Error("Live API is unavailable.");
            }

            return {
                evidence: await apiResponse.json(),
                liveApiAvailable: true
            };
        }catch {
            const fallbackResponse = await fetch(
                "data/verification-summary.json"
            );

            if (!fallbackResponse.ok) {
                throw new Error("Verification summary is unavailable.");
            }

            return {
                evidence: await fallbackResponse.json(),
                liveApiAvailable: false
            };
        }
    }

    function disableLiveControls(message) {
        if (runButton) {
            runButton.disabled = true;
        }

        if (resultPanel) {
            resultPanel.textContent = message;
        }

        if (fileInput) {
            fileInput.disabled = true;
        }

        if (analyzeButton) {
            analyzeButton.disabled = true;
        }

        if (intakeResult) {
            intakeResult.textContent = message;
        }
    }

    let liveApiAvailable = false;

    try {
        const loaded = await loadEvidence();

        liveApiAvailable = loaded.liveApiAvailable;
        displayEvidence(loaded.evidence);

        document.body.dataset.evidenceStatus = "loaded";

        if (!liveApiAvailable) {
            disableLiveControls(
                "Live analysis is available only in local Docker mode. " +
                "The public dashboard displays sanitized saved evidence."
            );
        }
    } catch (error) {
        document.body.dataset.evidenceStatus = "unavailable";

        disableLiveControls(error.message);

        if (resultPanel) {
            resultPanel.className = "verification-result failure";
        }

        if (intakeResult) {
            intakeResult.className = "verification-result failure";
        }
    }

    if (runButton && resultPanel) {
        runButton.addEventListener("click", async () => {
            if (!liveApiAvailable) {
                return;
            }

            runButton.disabled = true;
            runButton.textContent = "Verification running…";

            resultPanel.className = "verification-result running";
            resultPanel.textContent =
                "Running the fixed harness inside the restricted container…";

            try {
                const response = await fetch("/api/verify", {
                    method: "POST",
                    headers: {
                        Accept: "application/json"
                    }
                });

                const data = await response.json();

                if (!response.ok) {
                    const detail =
                        typeof data.detail === "string"
                            ? data.detail
                            : JSON.stringify(data.detail);

                    throw new Error(
                        detail || "Verification request failed."
                    );
                }

                const summary = Array.isArray(data.summary)
                    ? data.summary.join("\n")
                    : "No check summary was returned.";

                resultPanel.textContent =
                    `Harness decision: ${data.harness_decision}\n` +
                    `${summary}\n` +
                    "Automatic merge: disabled\n" +
                    "Automatic deployment: disabled\n" +
                    "Human approval remains required.";

                resultPanel.className =
                    data.harness_decision === "PASS"
                        ? "verification-result success"
                        : "verification-result failure";
            } catch (error) {
                resultPanel.className = "verification-result failure";
                resultPanel.textContent =
                    `Verification could not complete: ${error.message}`;
            } finally {
                window.clearInterval(elapsedTimer);
                runButton.disabled = false;
                runButton.textContent = "Run verification again";
            }
        });
    }

    if (intakeForm && fileInput && analyzeButton && intakeResult) {
        intakeForm.addEventListener("submit", async (event) => {
            event.preventDefault();

            if (!liveApiAvailable) {
                return;
            }

            const selectedFile = fileInput.files[0];

            if (!selectedFile) {
                intakeResult.className = "verification-result failure";
                intakeResult.textContent =
                    "Select one authorized C source file.";
                return;
            }

            if (!selectedFile.name.toLowerCase().endsWith(".c")) {
                intakeResult.className = "verification-result failure";
                intakeResult.textContent =
                    "Only .c source files are accepted.";
                return;
            }

            if (selectedFile.size === 0) {
                intakeResult.className = "verification-result failure";
                intakeResult.textContent =
                    "Empty source files are not accepted.";
                return;
            }

            if (selectedFile.size > 64 * 1024) {
                intakeResult.className = "verification-result failure";
                intakeResult.textContent =
                    "The source exceeds the 64 KiB limit.";
                return;
            }

            const formData = new FormData();
            formData.append(
                "source",
                selectedFile,
                selectedFile.name
            );
            latestIntakeEvidence = null;
            latestAgentReport = null;
            latestHumanReviewRecord = null;

            if (humanReviewGate) {
                humanReviewGate.hidden = true;
            }

            if (humanReviewNote) {
                humanReviewNote.value = "";
            }

            if (downloadReviewButton) {
                downloadReviewButton.disabled = true;
            }
            if (agentReport) {
                agentReport.hidden = true;
            }

            if (agentResult) {
                agentResult.hidden = false;
            }

            if (downloadAgentButton) {
                downloadAgentButton.disabled = true;
            }

            if (agentButton && agentResult) {
                agentButton.disabled = true;
                agentButton.textContent = "Explain latest evidence";
                agentResult.className = "verification-result";
                agentResult.textContent =
                    "Waiting for deterministic analysis to complete.";
            }
            fileInput.disabled = true;
            analyzeButton.disabled = true;
            analyzeButton.textContent = "Analyzing…";

            intakeResult.className = "verification-result running";
            intakeResult.textContent =
                "Validating, syntax-checking and scanning the C source…";

            try {
                const response = await fetch("/api/analyze/c", {
                    method: "POST",
                    headers: {
                        Accept: "application/json"
                    },
                    body: formData
                });

                const data = await response.json();

                if (!response.ok) {
                    const detail =
                        typeof data.detail === "string"
                            ? data.detail
                            : JSON.stringify(data.detail);

                    throw new Error(
                        detail || "Controlled analysis request failed."
                    );
                }
                latestIntakeEvidence = data;

                if (agentButton && agentResult) {
                    agentButton.disabled = false;
                    agentResult.className = "verification-result";
                    agentResult.textContent =
                        "Deterministic evidence is ready. " +
                        "AI explanation remains optional and advisory.";
                }


                const syntaxCheck =
                data.checks.syntax_compilation;

            const compilationPassed =
                syntaxCheck.passed === true;

            const compilationDiagnostic =
                typeof syntaxCheck.diagnostic === "string"
                    ? syntaxCheck.diagnostic.trim()
                    : "";

            const findingCount =
                data.checks.semgrep.finding_count;
                const findings =
                Array.isArray(data.checks.semgrep.findings)
                    ? data.checks.semgrep.findings
                    : [];

            const findingDetails = findings
                .map((finding, index) => {
                    const ruleId =
                        finding.rule_id ||
                        finding.check_id ||
                        "approved-rule";

                    const severity =
                        finding.severity || "UNKNOWN";

                    const line =
                        finding.line ||
                        finding.start_line ||
                        "unknown";

                    const message =
                        finding.message ||
                        "Security review is required.";

                    return (
                        `${index + 1}. [${severity}] ${ruleId}\n` +
                        `   Line: ${line}\n` +
                        `   ${message}`
                    );
                })
                .join("\n");

            const findingSection =
                findingDetails
                    ? `Finding details:\n${findingDetails}\n`
                    : "";

            const diagnosticSection =
                compilationDiagnostic
                    ? `Compiler diagnostic:\n${compilationDiagnostic}\n`
                    : "";

            intakeResult.textContent =
                `File: ${data.source.original_name}\n` +
                `Size: ${data.source.size_bytes} bytes\n` +
                `Syntax compilation: ${
                    compilationPassed ? "PASS" : "FAIL"
                }\n` +
                diagnosticSection +
                `Supported Semgrep findings: ${findingCount}\n` +
                findingSection +
                `Analysis decision: ${data.analysis_decision}\n` +
                `Review priority: ${
                    data.review_priority || "UNASSESSED"
                }\n` +
                "Source executed: false\n" +
                "Automatic patch: disabled\n" +
                "Automatic merge: disabled\n" +
                "Automatic deployment: disabled\n" +
                "Human review remains required.";
                if (
                    data.analysis_decision ===
                    "NO_SUPPORTED_FINDINGS"
                ) {
                    intakeResult.className =
                        "verification-result success";
                } else if (
                    data.analysis_decision ===
                    "REVIEW_REQUIRED"
                ) {
                    intakeResult.className =
                        "verification-result review";
                } else {
                    intakeResult.className =
                        "verification-result failure";
                }
            } catch (error) {
                intakeResult.className =
                    "verification-result failure";
                intakeResult.textContent =
                    `Controlled analysis could not complete: ${
                        error.message
                    }`;
            } finally {
                fileInput.disabled = false;
                analyzeButton.disabled = false;
                analyzeButton.textContent =
                    "Analyze another C file";
            }
        });
    }
    if (agentButton && agentResult) {
        agentButton.addEventListener("click", async () => {
            if (!liveApiAvailable || !latestIntakeEvidence) {
                agentResult.className =
                    "verification-result failure";
                agentResult.textContent =
                    "Run deterministic C analysis before requesting " +
                    "an AI explanation.";
                return;
            }

            agentButton.disabled = true;
            agentButton.textContent = "Evidence Analyst running…";

            agentResult.className = "verification-result running";
            agentResult.hidden = false;

            if (agentReport) {
                agentReport.hidden = true;
            }

            const startedAt = performance.now();

            const updateRunningStatus = () => {
                const elapsedSeconds = Math.floor(
                    (performance.now() - startedAt) / 1000
                );

                agentResult.textContent =
                    "The local model is explaining sanitized evidence.\n" +
                    "The raw source file is not being sent.\n" +
                    `Elapsed time: ${elapsedSeconds} seconds`;
            };

            updateRunningStatus();

            const elapsedTimer = window.setInterval(
                updateRunningStatus,
                1000
            );

            try {
                const response = await fetch(
                    "/api/agent/analyze-evidence",
                    {
                        method: "POST",
                        headers: {
                            Accept: "application/json",
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify(
                            latestIntakeEvidence
                        )
                    }
                );

                const responseText = await response.text();
                let data;

                try {
                    data = JSON.parse(responseText);
                } catch {
                    const message =
                        response.ok
                            ? "The Evidence Analyst returned invalid JSON."
                            : (
                                `The server returned HTTP ${
                                    response.status
                                }. Check the local API logs.`
                            );

                    throw new Error(message);
                }

                if (!response.ok) {
                    const detail =
                        typeof data.detail === "string"
                            ? data.detail
                            : JSON.stringify(data.detail);

                    throw new Error(
                        detail ||
                        "The Evidence Analyst request failed."
                    );
                }

                const analysis = data.analysis || {};
                const completedElapsed = (
                    (performance.now() - startedAt) / 1000
                ).toFixed(1);

                const keyEvidence =
                    Array.isArray(analysis.key_evidence)
                        ? analysis.key_evidence
                            .map((item) => `- ${item}`)
                            .join("\n")
                        : "- Not provided";

                const limitations =
                    Array.isArray(analysis.limitations)
                        ? analysis.limitations
                            .map((item) => `- ${item}`)
                            .join("\n")
                        : "- Not provided";

                agentResult.textContent =
                    `Agent: ${data.agent}\n` +
                    `Model: ${data.model}\n` +
                    `Elapsed time: ${completedElapsed} seconds\n` +
                    `Deterministic decision: ${
                        data.deterministic_decision
                    }\n` +
                    `Confidence: ${analysis.confidence}\n\n` +
                    `Summary:\n${analysis.summary}\n\n` +
                    `Root cause:\n${analysis.root_cause}\n\n` +
                    `Key evidence:\n${keyEvidence}\n\n` +
                    `Recommended next action:\n${
                        analysis.recommended_next_action
                    }\n\n` +
                    `Limitations:\n${limitations}\n\n` +
                    "Raw source file received by model: false\n" +
                    "Compiler excerpt may be included: true\n" +
                    "Automatic patch: disabled\n" +
                    "Automatic merge: disabled\n" +
                    "Automatic deployment: disabled\n" +
                    "Human review remains required.";

                agentResult.className =
                    "verification-result review";
                    renderAgentReport(data, completedElapsed);
                    latestHumanReviewRecord = null;

                    if (humanReviewGate) {
                        humanReviewGate.hidden = false;
                    }

                    if (humanReviewNote) {
                        humanReviewNote.value = "";
                    }

                    if (confirmFindingButton) {
                        confirmFindingButton.disabled =
                            data.deterministic_decision !==
                            "REVIEW_REQUIRED";
                    }

                    if (rejectConclusionButton) {
                        rejectConclusionButton.disabled = false;
                    }

                    if (downloadReviewButton) {
                        downloadReviewButton.disabled = true;
                    }

                    if (humanReviewResult) {
                        humanReviewResult.className =
                            "verification-result";
                        humanReviewResult.textContent =
                            "No human decision has been recorded.";
                    }
                    latestAgentReport = data;

                    if (downloadAgentButton) {
                        downloadAgentButton.disabled = false;
                    }
            } catch (error) {
                const failedElapsed = (
                    (performance.now() - startedAt) / 1000
                ).toFixed(1);
                if (humanReviewGate) {
                    humanReviewGate.hidden = true;
                }
                if (agentReport) {
                    agentReport.hidden = true;
                }

                agentResult.hidden = false;

                agentResult.className =
                    "verification-result failure";

                agentResult.textContent =
                    `Evidence Analyst could not complete: ${
                        error.message
                    }\nElapsed time: ${failedElapsed} seconds`;
            } finally {
                    window.clearInterval(elapsedTimer);
                    agentButton.disabled = false;
                    agentButton.textContent =
                        "Explain latest evidence again";
            }
        });
    }
    if (downloadAgentButton) {
        downloadAgentButton.addEventListener("click", () => {
            if (!latestAgentReport || !latestIntakeEvidence) {
                return;
            }

            const originalName =
                latestIntakeEvidence.source?.original_name ||
                "authorized-source.c";

            const safeBaseName = originalName
                .replace(/\.c$/i, "")
                .replace(/[^a-zA-Z0-9._-]/g, "_");

            const reportText = JSON.stringify(
                latestAgentReport,
                null,
                2
            );

            const reportBlob = new Blob(
                [reportText],
                {
                    type: "application/json"
                }
            );

            const reportUrl = URL.createObjectURL(reportBlob);
            const downloadLink = document.createElement("a");

            downloadLink.href = reportUrl;
            downloadLink.download =
                `kavach-evidence-${safeBaseName}.json`;

            document.body.appendChild(downloadLink);
            downloadLink.click();
            downloadLink.remove();
            URL.revokeObjectURL(reportUrl);
        });
    }
    async function submitHumanReview(humanDecision) {
        if (!latestIntakeEvidence || !humanReviewNote) {
            return;
        }

        const reviewerNote = humanReviewNote.value.trim();

        if (reviewerNote.length < 10 || reviewerNote.length > 500) {
            humanReviewResult.className =
                "verification-result failure";
            humanReviewResult.textContent =
                "Enter a reviewer note between 10 and 500 characters.";
            return;
        }

        confirmFindingButton.disabled = true;
        rejectConclusionButton.disabled = true;

        humanReviewResult.className = "verification-result running";
        humanReviewResult.textContent =
            "Recording the local human finding-review decision…";

        try {
            const response = await fetch("/api/review/finding", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    job_id: latestIntakeEvidence.job_id,
                    source_sha256:
                        latestIntakeEvidence.source.sha256,
                    human_decision: humanDecision,
                    reviewer_note: reviewerNote
                })
            });

            const responseText = await response.text();
            let data;

            try {
                data = JSON.parse(responseText);
            } catch {
                throw new Error(
                    `The server returned HTTP ${response.status} ` +
                    "without a valid JSON response."
                );
            }

            if (!response.ok) {
                const detail =
                    typeof data.detail === "string"
                        ? data.detail
                        : JSON.stringify(data.detail);

                throw new Error(
                    detail || "The human-review request failed."
                );
            }

            latestHumanReviewRecord = data;
            downloadReviewButton.disabled = false;

            humanReviewResult.className =
                humanDecision === "CONFIRMED_FINDING"
                    ? "verification-result review"
                    : "verification-result success";

            humanReviewResult.textContent =
                `Human decision: ${data.human_decision}\n` +
                `Review priority: ${data.review_priority}\n` +
                `Recorded at: ${data.recorded_at_utc}\n` +
                `Reviewer note: ${data.reviewer_note}\n\n` +
                "Identity verified: false\n" +
                "Local demo only: true\n" +
                "Patch generated: false\n" +
                "Patch approved: false\n" +
                "Automatic merge: disabled\n" +
                "Automatic deployment: disabled";
        } catch (error) {
            humanReviewResult.className =
                "verification-result failure";
            humanReviewResult.textContent =
                `Human decision could not be recorded: ${error.message}`;

            confirmFindingButton.disabled =
                latestIntakeEvidence.analysis_decision !==
                "REVIEW_REQUIRED";
            rejectConclusionButton.disabled = false;
        }
    }
    if (confirmFindingButton) {
        confirmFindingButton.addEventListener("click", () => {
            submitHumanReview("CONFIRMED_FINDING");
        });
    }

    if (rejectConclusionButton) {
        rejectConclusionButton.addEventListener("click", () => {
            submitHumanReview("REJECTED_CONCLUSION");
        });
    }
    if (downloadReviewButton) {
        downloadReviewButton.addEventListener("click", () => {
            if (!latestHumanReviewRecord) {
                return;
            }

            const reportBlob = new Blob(
                [
                    JSON.stringify(
                        latestHumanReviewRecord,
                        null,
                        2
                    )
                ],
                {
                    type: "application/json"
                }
            );

            const downloadUrl = URL.createObjectURL(reportBlob);
            const downloadLink = document.createElement("a");
            const jobId =
                latestHumanReviewRecord.intake_job_id ||
                "local-review";

            downloadLink.href = downloadUrl;
            downloadLink.download =
                `kavach-human-review-${jobId}.json`;

            document.body.appendChild(downloadLink);
            downloadLink.click();
            downloadLink.remove();

            URL.revokeObjectURL(downloadUrl);
        });
    }
});
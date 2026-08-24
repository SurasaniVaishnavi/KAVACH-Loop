"use strict";

document.addEventListener("DOMContentLoaded", async () => {
    const runButton = document.querySelector("#run-verification");
    const resultPanel = document.querySelector("#verification-result");

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

    function displayEvidence(evidence) {
        const summaryValues = document.querySelectorAll(
            ".summary-card strong"
        );

        const workflowMode =
            typeof evidence.workflow_mode === "string"
                ? evidence.workflow_mode.replace(" autonomy", "")
                : "Supervised";

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
        } catch {
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

    let liveApiAvailable = false;

    try {
        const loaded = await loadEvidence();

        liveApiAvailable = loaded.liveApiAvailable;
        displayEvidence(loaded.evidence);

        document.body.dataset.evidenceStatus = "loaded";

        if (!liveApiAvailable && runButton && resultPanel) {
            runButton.disabled = true;
            resultPanel.textContent =
                "Live verification is available only in local Docker mode. " +
                "The public dashboard displays the sanitized saved evidence.";
        }
    } catch (error) {
        document.body.dataset.evidenceStatus = "unavailable";

        if (runButton) {
            runButton.disabled = true;
        }

        if (resultPanel) {
            resultPanel.className = "verification-result failure";
            resultPanel.textContent = error.message;
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

                    throw new Error(detail || "Verification request failed.");
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
                runButton.disabled = false;
                runButton.textContent = "Run verification again";
            }
        });
    }
});
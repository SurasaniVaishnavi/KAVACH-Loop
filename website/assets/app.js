"use strict";

document.addEventListener("DOMContentLoaded", async () => {
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

    try {
        const response = await fetch("data/verification-summary.json");

        if (!response.ok) {
            throw new Error(`Evidence request failed: ${response.status}`);
        }

        const evidence = await response.json();

        const summaryValues = document.querySelectorAll(
            ".summary-card strong"
        );

        const summaryData = [
            evidence.harness_decision,
            evidence.human_decision,
            evidence.checks.evidence_integrity,
            evidence.workflow_mode.replace(" autonomy", "")
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

        document.body.dataset.evidenceStatus = "loaded";

        console.info(
            "KAVACH-Loop sanitized verification evidence loaded."
        );
    } catch (error) {
        document.body.dataset.evidenceStatus = "unavailable";

        console.error(
            "The dashboard could not load its verification summary.",
            error
        );
    }
});
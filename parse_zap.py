import csv
import json
import os
import sys


SEVERITY = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_risk(risk):
    """
    Convert ZAP risk values into standard severity names.
    """

    risk = str(risk).upper().strip()

    mapping = {
        "INFORMATIONAL": "INFO",
        "INFORMATION": "INFO",
        "INFO": "INFO",
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }

    return mapping.get(risk, "INFO")


def get_alert_url(alert):
    """
    Get the first affected URL from a ZAP alert.
    """

    instances = alert.get("instances", [])

    if instances:
        return instances[0].get("uri", "")

    return ""


def load_zap_report(report_file):
    """
    Load ZAP JSON report.
    """

    try:
        with open(
            report_file,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except FileNotFoundError:
        print(
            f"ERROR: ZAP report not found: {report_file}"
        )
        sys.exit(2)

    except json.JSONDecodeError as error:
        print(
            f"ERROR: Invalid ZAP JSON: {error}"
        )
        sys.exit(2)


def extract_findings(data):
    """
    Extract findings from ZAP JSON.
    """

    findings = []

    for site in data.get("site", []):

        site_name = site.get("name", "")

        for alert in site.get("alerts", []):

            risk = normalize_risk(
                alert.get("riskdesc", "")
            )

            instances = alert.get("instances", [])

            # Some ZAP reports may not contain instances.
            if not instances:
                instances = [{}]

            for instance in instances:

                url = instance.get(
                    "uri",
                    ""
                )

                findings.append(
                    {
                        "site": site_name,
                        "risk": risk,
                        "alert_name": alert.get(
                            "name",
                            ""
                        ),
                        "confidence": alert.get(
                            "confidence",
                            ""
                        ),
                        "url": url,
                        "description": alert.get(
                            "desc",
                            ""
                        ),
                        "solution": alert.get(
                            "solution",
                            ""
                        ),
                        "reference": alert.get(
                            "reference",
                            ""
                        ),
                    }
                )

    return findings


def calculate_counts(findings):
    """
    Calculate vulnerability counts by severity.
    """

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:

        risk = finding["risk"]

        if risk in counts:
            counts[risk] += 1

    return counts


def get_blocking_findings(findings, threshold):
    """
    Return findings that meet or exceed the configured threshold.
    """

    threshold_value = SEVERITY[threshold]

    return [
        finding
        for finding in findings
        if SEVERITY[finding["risk"]] >= threshold_value
    ]


def get_finding_status(finding, threshold):
    """
    Determine CSV status for an individual finding.
    """

    finding_value = SEVERITY[finding["risk"]]
    threshold_value = SEVERITY[threshold]

    if finding_value >= threshold_value:
        return "FAIL"

    if finding["risk"] == "MEDIUM":
        return "WARN"

    return "PASS"


def write_csv(
    csv_file,
    findings,
    threshold
):
    """
    Generate CSV report.
    """

    os.makedirs(
        os.path.dirname(csv_file) or ".",
        exist_ok=True
    )

    fieldnames = [
        "site",
        "risk",
        "alert_name",
        "confidence",
        "url",
        "description",
        "solution",
        "reference",
        "status",
    ]

    with open(
        csv_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for finding in findings:

            row = dict(finding)

            row["status"] = get_finding_status(
                finding,
                threshold
            )

            writer.writerow(row)


def print_summary(
    counts,
    threshold,
    blocking_findings
):
    """
    Print DAST summary.
    """

    print("")
    print("======================================")
    print("          DAST SCAN SUMMARY")
    print("======================================")

    print(
        f"CRITICAL : {counts['CRITICAL']}"
    )

    print(
        f"HIGH     : {counts['HIGH']}"
    )

    print(
        f"MEDIUM   : {counts['MEDIUM']}"
    )

    print(
        f"LOW      : {counts['LOW']}"
    )

    print(
        f"INFO     : {counts['INFO']}"
    )

    print("--------------------------------------")

    print(
        f"Threshold          : {threshold}"
    )

    print(
        f"Blocking findings  : "
        f"{len(blocking_findings)}"
    )

    print("======================================")
    print("")


def handle_validation_failure(
    blocking_findings
):
    """
    Apply BuildPiper validation failure action.

    WARN:
        Print warning and continue pipeline.

    FAIL:
        Fail pipeline.

    Any other value:
        Configuration error.
    """

    action = os.getenv(
        "VALIDATION_FAILURE_ACTION",
        "FAIL"
    ).upper().strip()

    if action == "WARN":

        print(
            "⚠️ DAST threshold breached"
        )

        print(
            f"Blocking findings: "
            f"{len(blocking_findings)}"
        )

        print(
            "VALIDATION_FAILURE_ACTION=WARN"
        )

        print(
            "Pipeline will continue."
        )

        return 0

    elif action == "FAIL":

        print(
            "❌ DAST threshold breached"
        )

        print(
            f"Blocking findings: "
            f"{len(blocking_findings)}"
        )

        print(
            "VALIDATION_FAILURE_ACTION=FAIL"
        )

        print(
            "Pipeline will stop."
        )

        return 1

    else:

        print(
            "ERROR: Invalid "
            "VALIDATION_FAILURE_ACTION"
        )

        print(
            f"Received: {action}"
        )

        print(
            "Supported values: "
            "WARN, FAIL"
        )

        return 2


def main():

    # --------------------------------------------------
    # Arguments
    # --------------------------------------------------

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python3 parse_zap.py "
            "<zap-json> [csv-file]"
        )

        sys.exit(2)

    report_file = sys.argv[1]

    csv_file = (
        sys.argv[2]
        if len(sys.argv) >= 3
        else "/reports/dast-results.csv"
    )

    # --------------------------------------------------
    # Environment configuration
    # --------------------------------------------------

    threshold = os.getenv(
        "DAST_THRESHOLD",
        "HIGH"
    ).upper().strip()

    # --------------------------------------------------
    # Validate threshold
    # --------------------------------------------------

    if threshold not in SEVERITY:

        print(
            f"ERROR: Invalid DAST_THRESHOLD: "
            f"{threshold}"
        )

        print(
            "Supported values: "
            "CRITICAL, HIGH, MEDIUM, LOW, INFO"
        )

        sys.exit(2)

    # --------------------------------------------------
    # Load ZAP JSON
    # --------------------------------------------------

    print(
        f"Reading ZAP report: {report_file}"
    )

    data = load_zap_report(
        report_file
    )

    # --------------------------------------------------
    # Extract findings
    # --------------------------------------------------

    findings = extract_findings(
        data
    )

    # --------------------------------------------------
    # Calculate counts
    # --------------------------------------------------

    counts = calculate_counts(
        findings
    )

    # --------------------------------------------------
    # Determine blocking findings
    # --------------------------------------------------

    blocking_findings = (
        get_blocking_findings(
            findings,
            threshold
        )
    )

    # --------------------------------------------------
    # Generate CSV
    # --------------------------------------------------

    write_csv(
        csv_file,
        findings,
        threshold
    )

    print(
        f"CSV report generated: {csv_file}"
    )

    # --------------------------------------------------
    # Print summary
    # --------------------------------------------------

    print_summary(
        counts,
        threshold,
        blocking_findings
    )

    # --------------------------------------------------
    # Validation / Pipeline decision
    # --------------------------------------------------

    if blocking_findings:

        exit_code = (
            handle_validation_failure(
                blocking_findings
            )
        )

        sys.exit(exit_code)

    # --------------------------------------------------
    # No threshold breach
    # --------------------------------------------------

    print(
        "✅ DAST RESULT: PASSED"
    )

    print(
        "No findings met or exceeded "
        f"the {threshold} threshold."
    )

    sys.exit(0)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import csv
import html
import json
import os
import re
import sys
from datetime import datetime, timezone

SEVERITY = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

RISK_CODES = {
    "-1": "INFO",
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL",
}


def clean(value):
    value = html.unescape(str(value or ""))
    value = re.sub(r"<[^>]*>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def normalize_risk(alert):
    risk = str(
        alert.get("riskdesc") or alert.get("risk") or ""
    ).upper().strip()

    risk = risk.split("(", 1)[0].strip()

    if risk in SEVERITY:
        return risk

    code = str(alert.get("riskcode", "")).strip()
    return RISK_CODES.get(code, "INFO")


def load_report(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read ZAP JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("ZAP JSON root must be an object")

    if not isinstance(data.get("site", []), list):
        raise ValueError("ZAP JSON site field must be a list")

    return data


def extract_findings(data, target_url):
    findings = []
    alert_groups = 0

    for site in data.get("site", []) or []:
        if not isinstance(site, dict):
            continue

        for alert in site.get("alerts", []) or []:
            if not isinstance(alert, dict):
                continue

            alert_groups += 1
            severity = normalize_risk(alert)
            instances = alert.get("instances") or [{}]

            for instance in instances:
                if not isinstance(instance, dict):
                    instance = {}

                url = (
                    instance.get("uri")
                    or alert.get("url")
                    or site.get("name")
                    or target_url
                )

                reference = clean(alert.get("reference"))
                match = re.search(r"https?://[^\s<>\"']+", reference)
                documentation = match.group(0).rstrip(".,)") if match else reference

                details = []
                if instance.get("method"):
                    details.append("Method: " + clean(instance["method"]))
                if instance.get("param"):
                    details.append("Param: " + clean(instance["param"]))
                if instance.get("evidence"):
                    details.append(
                        "Evidence: " + clean(instance["evidence"])[:150]
                    )

                description = clean(alert.get("desc"))
                if details:
                    description = " | ".join(
                        x for x in [description, " | ".join(details)] if x
                    )

                findings.append({
                    "severity": severity,
                    "plugin_id": str(alert.get("pluginid", "")),
                    "title": clean(
                        alert.get("alert")
                        or alert.get("name")
                        or "Unnamed ZAP alert"
                    ),
                    "url": str(url),
                    "description": description,
                    "solution": clean(alert.get("solution")),
                    "documentation": documentation,
                })

    return findings, alert_groups


def finding_status(severity, threshold):
    if SEVERITY[severity] >= SEVERITY[threshold]:
        return "Failed"

    if severity in ("MEDIUM", "LOW"):
        return "Warning"

    return "Info"


def write_csv(path, findings, threshold):
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)

    headers = [
        "S.No",
        "Tool",
        "Category",
        "Status",
        "Severity",
        "Check ID",
        "Title / Message",
        "File",
        "Line",
        "Cause / Description",
        "Recommendation / Fix",
        "Documentation",
    ]

    rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }
    findings.sort(key=lambda item: rank[item["severity"]])

    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(headers)

        for number, item in enumerate(findings, 1):
            writer.writerow([
                number,
                "OWASP ZAP",
                "DAST",
                finding_status(item["severity"], threshold),
                item["severity"],
                item["plugin_id"],
                item["title"],
                "",  # File: DAST findings are URL-based
                "",  # Line: DAST findings are URL-based
                item["description"],
                item["solution"],
                item["documentation"],
            ])


def build_summary(findings, alert_groups, threshold, policy, csv_path):
    counts = {severity: 0 for severity in SEVERITY}

    for item in findings:
        counts[item["severity"]] += 1

    threshold_findings = sum(
        1 for item in findings
        if SEVERITY[item["severity"]] >= SEVERITY[threshold]
    )

    if threshold_findings and policy == "FAIL":
        result = "FAIL"
    elif threshold_findings:
        result = "WARN"
    else:
        result = "PASS"

    return {
        "scan": {
            "alerts_count": alert_groups,
            "findings_count": len(findings),
            "severity_counts": counts,
            "threshold": threshold,
            "threshold_findings": threshold_findings,
            "validation_failure_action": policy,
            "finding_status": result,
        },
        "reports": {
            "csv": csv_path,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: parse_zap.py <zap.json> <output.csv> <summary.json>",
            file=sys.stderr,
        )
        return 2

    report_path, csv_path, summary_path = sys.argv[1:4]

    threshold = os.getenv("FAIL_ON", "HIGH").upper().strip()
    if threshold == "INFORMATIONAL":
        threshold = "INFO"

    policy = os.getenv(
        "VALIDATION_FAILURE_ACTION", "WARN"
    ).upper().strip()

    if policy == "WARNING":
        policy = "WARN"

    if threshold not in SEVERITY:
        print(f"Invalid FAIL_ON value: {threshold}", file=sys.stderr)
        return 2

    if policy not in ("WARN", "FAIL"):
        print(
            "VALIDATION_FAILURE_ACTION must be WARN or FAIL",
            file=sys.stderr,
        )
        return 2

    try:
        data = load_report(report_path)
        findings, alert_groups = extract_findings(
            data, os.getenv("TARGET_URL", "")
        )

        write_csv(csv_path, findings, threshold)

        summary = build_summary(
            findings, alert_groups, threshold, policy, csv_path
        )

        os.makedirs(
            os.path.dirname(os.path.abspath(summary_path)),
            exist_ok=True,
        )

        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    except (ValueError, OSError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    scan = summary["scan"]

    print("\n========== OWASP ZAP DAST SUMMARY ==========")
    print(f"Alert groups       : {scan['alerts_count']}")
    print(f"Finding instances  : {scan['findings_count']}")

    for severity, count in scan["severity_counts"].items():
        print(f"{severity:12}: {count}")

    print(f"Threshold          : {threshold}")
    print(f"Threshold findings : {scan['threshold_findings']}")
    print(f"Policy             : {policy}")
    print(f"Result             : {scan['finding_status']}")
    print(f"CSV                : {csv_path}")
    print(f"Summary            : {summary_path}")
    print("============================================")

    if scan["threshold_findings"] and policy == "FAIL":
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

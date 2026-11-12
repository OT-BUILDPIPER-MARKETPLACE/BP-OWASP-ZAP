#!/bin/bash
set -o pipefail

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh

if [ "${DEBUG:-false}" = "true" ]; then
    set -x
fi

WORKSPACE="${WORKSPACE:-/bp/workspace}"
CODEBASE_DIR="${CODEBASE_DIR:-}"
TARGET_URL="${TARGET_URL:-}"
SCAN_TYPE="${SCAN_TYPE:-baseline}"
FAIL_ON="${FAIL_ON:-HIGH}"
VALIDATION_FAILURE_ACTION="${VALIDATION_FAILURE_ACTION:-WARN}"
REPORT_DIR="${REPORT_DIR:-/zap/wrk}"
ACTIVITY_SUB_TASK_CODE="${ACTIVITY_SUB_TASK_CODE:-}"
GLOBAL_TASK_ID="${GLOBAL_TASK_ID:-}"

PARSER="/home/buildpiper/parse_zap.py"
REPORT_NAME="owasp_zap_dast_report.csv"
SUMMARY_NAME="OWASP_ZAP_DAST_Summary.json"

CODEBASE_LOCATION="${WORKSPACE}/${CODEBASE_DIR}"
REPORTS_DIR="${CODEBASE_LOCATION}/reports"
EXEC_DIR="/bp/execution_dir/${GLOBAL_TASK_ID}"

finish_step() {
    local status="$1"
    local message="$2"

    if [ "$status" -eq 0 ]; then
        logInfoMessage "$message"
    else
        logErrorMessage "$message"
    fi

    saveTaskStatus "$status" "$ACTIVITY_SUB_TASK_CODE"
    exit "$status"
}

# ------------------------------------------------------------
# Validate configuration
# ------------------------------------------------------------

[ -n "$TARGET_URL" ] ||
    finish_step 1 "TARGET_URL is required"

case "$TARGET_URL" in
    http://*|https://*) ;;
    *) finish_step 1 "TARGET_URL must start with http:// or https://" ;;
esac

case "$SCAN_TYPE" in
    baseline|full) ;;
    *) finish_step 1 "SCAN_TYPE must be baseline or full" ;;
esac

case "$FAIL_ON" in
    INFO|LOW|MEDIUM|HIGH|CRITICAL) ;;
    *) finish_step 1 "FAIL_ON must be INFO, LOW, MEDIUM, HIGH or CRITICAL" ;;
esac

case "$VALIDATION_FAILURE_ACTION" in
    WARNING) VALIDATION_FAILURE_ACTION="WARN" ;;
    WARN|FAIL) ;;
    *) finish_step 1 "VALIDATION_FAILURE_ACTION must be WARN or FAIL" ;;
esac

[ "$REPORT_DIR" = "/zap/wrk" ] ||
    finish_step 1 "REPORT_DIR must be /zap/wrk"

[ -f "$PARSER" ] ||
    finish_step 1 "Parser not found: $PARSER"

[ -n "$GLOBAL_TASK_ID" ] ||
    finish_step 1 "GLOBAL_TASK_ID is required"

[ -n "$ACTIVITY_SUB_TASK_CODE" ] ||
    finish_step 1 "ACTIVITY_SUB_TASK_CODE is required"

if [ -n "$CODEBASE_DIR" ] && [ ! -d "$CODEBASE_LOCATION" ]; then
    finish_step 1 "Codebase directory not found: $CODEBASE_LOCATION"
fi

mkdir -p "$REPORT_DIR" "$REPORTS_DIR" "$EXEC_DIR" ||
    finish_step 1 "Unable to create report directories"

[ -w "$REPORT_DIR" ] ||
    finish_step 1 "Report directory is not writable"

rm -f \
    "$REPORT_DIR/zap.json" \
    "$REPORT_DIR/zap.html" \
    "$REPORT_DIR/zap.md" \
    "$REPORTS_DIR/$REPORT_NAME" \
    "$REPORTS_DIR/$SUMMARY_NAME" \
    "$EXEC_DIR/$REPORT_NAME" \owsp
    "$EXEC_DIR/$SUMMARY_NAME" \
    "$EXEC_DIR/${ACTIVITY_SUB_TASK_CODE}_output.json"

logInfoMessage "======================================"
logInfoMessage "OWASP ZAP DAST scan starting"
logInfoMessage "Target: $TARGET_URL"
logInfoMessage "Scan type: $SCAN_TYPE"
logInfoMessage "Threshold: $FAIL_ON"
logInfoMessage "Policy: $VALIDATION_FAILURE_ACTION"
logInfoMessage "CSV filename: $REPORT_NAME"
logInfoMessage "======================================"

# ------------------------------------------------------------
# Run ZAP. Reports use relative filenames inside /zap/wrk.
# ------------------------------------------------------------

cd "$REPORT_DIR" ||
    finish_step 1 "Cannot enter $REPORT_DIR"

ZAP_ARGS=(
    -t "$TARGET_URL"
    -J zap.json
    -r zap.html
    -w zap.md
    -I
    -z "-config connection.proxyChain.enabled=true -config connection.proxyChain.hostName=185.46.212.90 -config connection.proxyChain.port=443"
)

if [ "$SCAN_TYPE" = "baseline" ]; then
    zap-baseline.py "${ZAP_ARGS[@]}"
    ZAP_RC=$?
else
    zap-full-scan.py "${ZAP_ARGS[@]}"
    ZAP_RC=$?
fi

logInfoMessage "ZAP scanner exit code: $ZAP_RC"

# Do not skip report parsing when ZAP produced valid JSON but
# returned a non-zero finding/scanner status.
if [ ! -s "$REPORT_DIR/zap.json" ]; then
    finish_step 1 "ZAP JSON report missing or empty; scanner exit=$ZAP_RC"
fi

# ------------------------------------------------------------
# Parse directly into the configured workspace report filename.
# Parser also generates the summary JSON.
# ------------------------------------------------------------

FAIL_ON="$FAIL_ON" \
VALIDATION_FAILURE_ACTION="$VALIDATION_FAILURE_ACTION" \
TARGET_URL="$TARGET_URL" \
python3 "$PARSER" \
    "$REPORT_DIR/zap.json" \
    "$REPORTS_DIR/$REPORT_NAME" \
    "$REPORTS_DIR/$SUMMARY_NAME"

PARSER_RC=$?
logInfoMessage "ZAP parser exit code: $PARSER_RC"

# Copy available reports to the execution directory for the UI.
for f in "$REPORT_NAME" "$SUMMARY_NAME" zap.json zap.html zap.md; do
    if [ -f "$REPORTS_DIR/$f" ]; then
        cp -f "$REPORTS_DIR/$f" "$EXEC_DIR/$f" ||
            logErrorMessage "Could not copy $f to execution directory"
    elif [ -f "$REPORT_DIR/$f" ]; then
        cp -f "$REPORT_DIR/$f" "$EXEC_DIR/$f" ||
            logErrorMessage "Could not copy $f to execution directory"
    fi
done

# Preserve the raw ZAP outputs under workspace/reports too.
for f in zap.json zap.html zap.md; do
    [ ! -f "$REPORT_DIR/$f" ] ||
        cp -f "$REPORT_DIR/$f" "$REPORTS_DIR/$f"
done

# BuildPiper step output metadata.
# This retains the existing build/reports structure from your script.
python3 - "$EXEC_DIR/${ACTIVITY_SUB_TASK_CODE}_output.json" \
    "$REPORTS_DIR/$REPORT_NAME" \
    "$REPORTS_DIR/zap.json" \
    "$REPORTS_DIR/zap.html" \
    "$REPORTS_DIR/$SUMMARY_NAME" \
    "$PARSER_RC" <<'PY'
import json
import os
import sys

output, csv_path, json_path, html_path, summary_path, parser_rc = sys.argv[1:]
summary = {}

try:
    with open(summary_path, encoding="utf-8") as f:
        summary = json.load(f)
except (OSError, ValueError):
    pass

scan = summary.get("scan", {})
status = scan.get("finding_status", "ERROR")
payload = {
    "build": {
        "status": parser_rc == "0",
        "message": "OWASP ZAP DAST scan completed",
        "finding_status": status.lower(),
        "blocking": False,
        "alerts": scan.get("severity_counts", {}),
        "threshold": scan.get("threshold"),
        "threshold_findings": scan.get("threshold_findings"),
    },
    "reports": {
        "csv": csv_path,
        "json": json_path,
        "html": html_path,
        "summary": summary_path,
    },
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
PY

[ -s "$REPORTS_DIR/$REPORT_NAME" ] ||
    finish_step 1 "Configured CSV report was not generated"

[ -s "$EXEC_DIR/${ACTIVITY_SUB_TASK_CODE}_output.json" ] ||
    finish_step 1 "BuildPiper output JSON was not generated"

chmod 0777 \
    "$REPORTS_DIR/$REPORT_NAME" \
    "$EXEC_DIR/$REPORT_NAME" \
    "$EXEC_DIR/${ACTIVITY_SUB_TASK_CODE}_output.json" \
    2>/dev/null || true

# Scanner execution failures still fail the step.
if [ "$ZAP_RC" -ne 0 ]; then
    finish_step 1 "ZAP scanner exited with code $ZAP_RC"
fi

if [ "$PARSER_RC" -ne 0 ]; then
    finish_step "$PARSER_RC" "ZAP severity validation failed"
fi

logInfoMessage "CSV report: $REPORTS_DIR/$REPORT_NAME"
logInfoMessage "Execution report: $EXEC_DIR/$REPORT_NAME"
finish_step 0 "OWASP ZAP DAST scan completed successfully"

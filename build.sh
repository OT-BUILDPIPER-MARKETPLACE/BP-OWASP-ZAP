#!/bin/bash
source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh

if [ "$DEBUG" = true ]; then
  set -x
fi


TASK_STATUS=0

CODEBASE_LOCATION="${WORKSPACE}"/"${CODEBASE_DIR}"
logInfoMessage "I'll do processing at [$CODEBASE_LOCATION]"
sleep  $SLEEP_DURATION
cd  "${CODEBASE_LOCATION}"

TASK_STATUS=0
if [ -z "${TARGET_URL}" ]; then
    logErrorMessage "TARGET_URL is required"
    TASK_STATUS=1
fi
if [ -z "${FAIL_ON}" ]; then
    logErrorMessage "FAIL_ON is required"
    TASK_STATUS=1
fi
if [ -z "${SCAN_TYPE}" ]; then
    logErrorMessage "SCAN_TYPE is required"
    TASK_STATUS=1
fi
if [ -d "reports" ]; then
    true
else
    mkdir -p reports
fi

logInfoMessage "======================================"
logInfoMessage "        BuildPiper DAST Plugin"
logInfoMessage "======================================"
logInfoMessage "Target     : ${TARGET_URL}"
logInfoMessage "Scan type  : ${SCAN_TYPE}"
logInfoMessage "Fail on    : ${FAIL_ON}"
logInfoMessage "======================================"

case "${SCAN_TYPE}" in

  baseline)
    logInfoMessage "Running ZAP baseline scan..."
    zap-baseline.py \
      -t "${TARGET_URL}" \
      -J "${REPORT_DIR}/zap.json" \
      -r "${REPORT_DIR}/zap.html" \
      -w "${REPORT_DIR}/zap.md" \
      -I
    ;;

  full)
  logInfoMessage "Running full scan..."
    zap-full-scan.py \
      -t "${TARGET_URL}" \
      -J "${REPORT_DIR}/zap.json" \
      -r "${REPORT_DIR}/zap.html" \
      -w "${REPORT_DIR}/zap.md" \
      -I
    ;;

  *)
    logErrorMessage " Unsupported SCAN_TYPE=${SCAN_TYPE}"
    exit 1
    ;;
esac

logInfoMessage ""
logInfoMessage "Parsing ZAP report..."

python3 parse_zap.py \
    "${REPORT_DIR}/zap.json" \
    "${FAIL_ON}" \
    "${REPORT_DIR}/zap.csv"

TASK_STATUS=$?

logInfoMessage "DAST exit code: ${TASK_STATUS}"

saveTaskStatus ${TASK_STATUS} ${ACTIVITY_SUB_TASK_CODE}
# OWASP ZAP DAST

## Overview

This BuildPiper step integrates OWASP ZAP for Dynamic Application Security Testing (DAST).

It scans a running application to identify potential security vulnerabilities and generates security reports.

## Scan Types

| Scan Type | Description |
|---|---|
| `baseline` | Performs crawling and passive security analysis. Faster and suitable for regular CI/CD pipelines. |
| `full` | Performs crawling, passive analysis, and active security testing. Takes more time and may generate additional application traffic. |

**Recommendation:**
- Use `baseline` for regular pipeline executions.
- Use `full` periodically in controlled QA/staging environments.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `TARGET_URL` | Application URL to scan | Required |
| `SCAN_TYPE` | Scan mode: `baseline` or `full` | `baseline` |
| `FAIL_ON` | Minimum severity threshold for blocking findings | `HIGH` |
| `VALIDATION_FAILURE_ACTION` | `FAIL` to fail or `WARN` to continue with a warning | `FAIL` |
| `REPORT_DIR` | Directory for generating reports | `/zap/wrk` |
| `SLEEP_DURATION` | Delay before starting the scan | `5s` |
| `WORKSPACE` | BuildPiper workspace directory | `/bp/workspace` |
| `CODEBASE_DIR` | Optional codebase directory | Empty |

## Severity Levels

| Severity | Description |
|---|---|
| `INFO` | Informational findings |
| `LOW` | Low-risk findings |
| `MEDIUM` | Medium-risk findings |
| `HIGH` | High-risk findings |
| `CRITICAL` | Critical security findings |

### FAIL_ON Configuration

`FAIL_ON` defines which severity levels can block the pipeline.

| Value | Blocking Findings |
|---|---|
| `INFO` | INFO and above |
| `LOW` | LOW and above |
| `MEDIUM` | MEDIUM and above |
| `HIGH` | HIGH and CRITICAL |
| `CRITICAL` | CRITICAL only |

### VALIDATION_FAILURE_ACTION

- `FAIL`: Fails the step when blocking findings are detected.
- `WARN`: Displays a warning without failing the step due to vulnerability-threshold violations.

## Example Configuration

```bash
TARGET_URL=https://example.com/health
SCAN_TYPE=baseline
FAIL_ON=HIGH
VALIDATION_FAILURE_ACTION=FAIL
REPORT_DIR=/zap/wrk
SLEEP_DURATION=5s
```

## Reports

The step generates the following reports:

| Report | Filename | Description |
|---|---|---|
| HTML | `zap.html` | Detailed security report |
| JSON | `zap.json` | Structured scan results |
| Markdown | `zap.md` | Readable scan summary |

Reports are generated inside the configured `REPORT_DIR`.

## Execution Flow

1. Read configuration.
2. Validate scan inputs.
3. Execute the selected ZAP scan.
4. Generate security reports.
5. Analyze vulnerability findings.
6. Compare findings against `FAIL_ON`.
7. Apply `VALIDATION_FAILURE_ACTION`.
8. Display final scan status.

## Important Notes

- The target application must be running and reachable.
- Full Scan performs active security testing and should be used only with proper authorization.
- `FAIL_ON` controls the severity threshold, not the scan type.
- `WARN` prevents pipeline failure due to threshold violations; it does not guarantee that scan execution errors will be ignored.
- Configure workspace or volume mounting if reports need to persist after container execution.

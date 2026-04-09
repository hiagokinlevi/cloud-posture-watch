# Posture Methodology

This document describes how `cloud-posture-watch` derives findings, calculates risk scores, and produces reports.

## Data collection

Each provider module (under `providers/`) makes read-only API calls to retrieve configuration attributes for supported resource types. No write operations are performed. Credentials are consumed from the standard SDK credential chains (AWS profile, Azure DefaultAzureCredential, GCP ADC) and are never stored or logged.

## Analysis pipeline

```
Provider collector  -->  Analyzer(s)  -->  Findings  -->  Report
```

1. **Provider collector** returns a list of typed dataclass instances, one per resource.
2. **Analyzers** consume the collector output and apply rule logic:
   - `exposure_analyzer` — checks risk flags for access control violations
   - `logging_analyzer` — checks logging-related attributes
   - `drift_analyzer` — loads a baseline YAML and compares expected vs. actual values
3. **Findings** are converted to Pydantic `PostureFinding` models.
4. **Report generator** serialises findings to Markdown (and optionally JSON).

## Baseline profiles

Baseline files are YAML documents under `baselines/<provider>/`. Each profile (minimal, standard, strict) defines the expected state for each supported control.

The drift analyzer compares the collected state against the baseline using a control map defined in `analyzers/drift_analyzer.py`. Each control entry specifies:
- The posture attribute to check
- The expected value
- The importance level (required / recommended / informational)

## Risk scoring

The risk score is a simple weighted sum:

| Severity | Weight |
|----------|--------|
| CRITICAL | 10     |
| HIGH     | 5      |
| MEDIUM   | 2      |
| LOW      | 1      |
| INFO     | 0      |

The raw score is capped at 100. A score of 0 indicates no findings. A score above 50 indicates significant remediation work is needed.

## Limitations

- **Read-only**: The tool cannot confirm whether a configuration issue is actively being exploited.
- **Point-in-time**: Each run captures a snapshot; resources may change between assessments.
- **Coverage**: Only the services and attributes listed in the supported services table are checked. Other services require additional collector modules.
- **False positives**: Some checks (e.g., versioning_recommended) may trigger on intentionally configured environments. Use the baseline YAML to tune expectations.

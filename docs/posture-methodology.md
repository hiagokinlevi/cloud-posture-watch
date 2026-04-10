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
   - `network_exposure` — checks AWS security groups, Azure NSGs, and GCP firewall rules for public network exposure
   - `logging_analyzer` — checks logging-related attributes
   - `flow_logs_analyzer` — checks AWS VPC Flow Logs coverage, delivery destinations, and telemetry fidelity
   - `aws_iam_analyzer` — checks offline AWS IAM evidence for root MFA status, active access key age, and broadly permissive policy statements
   - `aws_rds_analyzer` — checks offline AWS RDS instance and cluster evidence for storage encryption, public accessibility, and public DB subnet group placement
   - `azure_rbac_analyzer` — checks offline Azure RBAC assignments for broad Owner/Contributor scope, guest privileged access, service principal Owner grants, User Access Administrator delegation risk, and wildcard custom roles
   - `gcp_iam_analyzer` — checks offline GCP IAM policy evidence for primitive roles, public principals, external sensitive-role users, default service accounts, broad IAM-admin roles, and stale service account keys
   - `iam_comparison_analyzer` — normalizes AWS, Azure, and GCP offline IAM analyzer results into one cross-cloud Markdown and JSON comparison report
   - `drift_analyzer` — loads a baseline YAML and compares expected vs. actual values
3. **Findings** are converted to Pydantic `PostureFinding` models.
4. **Report generator** serialises findings to Markdown (and optionally JSON).
5. **JSON schema contract** tags posture JSON reports with `$schema` and `schema_version`, and `k1n-posture json-schema` prints the stable v1 contract for downstream validators.
6. **Webhook notification** can summarize an approved JSON posture report for Slack or Teams. Payloads include provider, run ID, severity counts, and the top findings. The webhook URL is supplied only at send time and is never printed in success output.
7. **Watch mode** compares the latest posture JSON report to the prior snapshot, tracks newly introduced versus resolved findings, persists the latest snapshot for the next run, and can alert only when new findings meet a configured severity threshold.

## Baseline profiles

Baseline files are YAML documents under `baselines/<provider>/`. Each profile (minimal, standard, strict) defines the expected state for each supported control.

The drift analyzer compares the collected state against the baseline using a control map defined in `analyzers/drift_analyzer.py`. Each control entry specifies:
- The posture attribute to check
- The expected value
- The importance level (required / recommended / informational)

## Risk scoring

The risk score uses the shared `schemas.risk` model so CLI summaries and all report formats agree on the same numeric severity ratings:

| Severity | Weight |
|----------|--------|
| CRITICAL | 10     |
| HIGH     | 5      |
| MEDIUM   | 2      |
| LOW      | 1      |
| INFO     | 0      |

The raw score is capped at 100. A score of 0 maps to `clear`, 1-19 maps to `low`, 20-49 maps to `moderate`, and 50-100 maps to `high`. JSON exports include `risk_score`, `risk_level`, and the severity weights so downstream dashboards can preserve the same interpretation.

## JSON schema stability

The v1 posture-report JSON contract is exposed with `k1n-posture json-schema`. Generated JSON reports include `$schema`, `schema_version`, `run_id`, `provider`, `assessed_at`, `baseline_name`, `total_resources`, `risk_score`, `risk_level`, `risk_model`, `finding_counts`, `findings`, and `drift_items`. New non-breaking fields may be added, but the v1 required fields remain stable for downstream tooling.

## Limitations

- **Read-only**: The tool cannot confirm whether a configuration issue is actively being exploited.
- **Point-in-time**: Each run captures a snapshot; resources may change between assessments.
- **Coverage**: Only the services and attributes listed in the supported services table are checked. Other services require additional collector modules.
- **False positives**: Some checks (e.g., versioning_recommended) may trigger on intentionally configured environments. Use the baseline YAML to tune expectations.
- **Offline IAM evidence**: AWS IAM checks depend on exported account-summary, credential-report, and policy JSON. Missing root MFA evidence is reported as a medium-confidence finding rather than proof that MFA is disabled.
- **Offline RDS evidence**: AWS RDS checks depend on exported DB instance and optional DB cluster JSON. Public subnet-group detection only works when subnet details are present in the export.
- **Azure RBAC exports**: Azure RBAC checks depend on exported role assignments and optional custom role definitions. External-principal checks only compare user principal domains when `--trusted-domain` is supplied.
- **GCP IAM exports**: GCP IAM checks depend on exported policy `bindings` and optional service account key metadata. External-member checks only flag user domains when `--org-domain` is supplied.
- **Cross-cloud IAM comparison**: The comparison report does not infer new risk beyond the provider-specific analyzers. It groups supplied offline findings by common identity themes and uses the highest provider risk score as the comparison score.
- **Webhook notifications**: Slack and Teams notifications are derived from saved JSON posture reports, not live cloud state. Use `--dry-run` to review payload contents before posting to an external incoming webhook.
- **Watch mode**: Scheduled watch runs compare saved JSON posture reports rather than re-querying cloud APIs on their own. The first run seeds state without alerting unless `--alert-on-first-run` is explicitly enabled.

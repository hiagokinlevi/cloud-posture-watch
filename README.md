# cloud-posture-watch

**Cloud security posture assessment for AWS, Azure, and GCP — exposure analysis, logging gaps, and configuration drift detection.**

`cloud-posture-watch` is a multi-cloud CLI tool that audits the security posture of your cloud environments. It collects configuration state from AWS, Azure, and GCP using read-only APIs, compares that state against opinionated security baselines, and produces structured reports covering public exposure, logging coverage, encryption posture, VPC network telemetry, and configuration drift.

---

## Features

- **Multi-cloud support** — AWS, Azure, and GCP in a single tool
- **Exposure analysis** — identifies publicly accessible storage, compute, and network resources
- **Logging gap detection** — checks whether audit trails, access logs, and flow logs are enabled
- **VPC Flow Logs coverage** — flags AWS VPCs with missing flow logs, missing delivery destinations, missing rejected-traffic capture, or coarse aggregation windows
- **Offline AWS IAM review** — scans exported IAM evidence for root MFA gaps, stale active user keys, and permissive policies
- **Offline AWS RDS review** — scans exported RDS instance and cluster evidence for missing storage encryption and public database exposure
- **Offline AWS secrets correlation** — compares Secrets Manager or Parameter Store inventory against approved hardcoded credential findings to spot unmanaged literals and plaintext credential parameters
- **Offline Azure SQL review** — scans exported logical server and database evidence for disabled TDE, public network access, and broad firewall rules
- **Offline GCP Cloud SQL review** — scans exported Cloud SQL instance evidence for public IPv4 exposure, weak authorized networks, and missing SSL/TLS enforcement
- **Offline Azure RBAC review** — scans role assignment exports for broad Owner/Contributor access, guest privileged assignments, service principal Owner grants, and wildcard custom roles
- **Offline GCP IAM review** — scans exported IAM policies for primitive roles, public principals, external sensitive-role users, default service accounts, and stale service account keys
- **Cross-cloud IAM comparison** — combines offline AWS, Azure, and GCP identity findings into one Markdown and JSON review artifact
- **Offline Azure NSG review** — scans exported `az network nsg list` JSON for public admin, database, and broad inbound rules
- **Offline GCP firewall review** — scans exported `gcloud compute firewall-rules list` JSON for public admin, database, web, and broad inbound rules
- **Encryption posture** — validates encryption at rest and in transit across storage and database services
- **Configuration drift detection** — compares live state against YAML baselines and highlights deviations
- **Risk scoring** — applies a shared numeric 0-100 severity model across CLI summaries, Markdown, JSON, and HTML reports
- **Stable JSON contract** — publishes a v1 posture-report schema for downstream dashboards and CI tooling
- **Markdown reports** — human-readable output with findings, scores, and remediation recommendations
- **Watch mode for scheduled runs** — compares the latest JSON report to the prior snapshot and alerts only on newly introduced findings
- **GitHub Action support** — composite Marketplace-ready action validates CLI inputs, installs the tool, and exposes generated report paths as workflow outputs
- **Slack and Teams webhooks** — sends posture-report summaries to incoming webhooks or prints dry-run payloads for approval
- **Extensible baselines** — minimal / standard / strict profiles, all customizable

---

## Quickstart

### Prerequisites

- Python 3.11+
- Read-only credentials for the cloud account(s) you want to assess
- `pip install cloud-posture-watch` (or install from source, see below)

### Install from source

```bash
git clone https://github.com/hiagokinlevi/cloud-posture-watch.git
cd cloud-posture-watch
python -m venv --system-site-packages .venv
./.venv/bin/python -m pip install -e . --no-deps --no-build-isolation
```

### Configure

```bash
cp .env.example .env
# Edit .env and set PROVIDER plus the credentials for your target cloud
```

### Run an assessment

```bash
# AWS — uses the active AWS profile
k1n-posture assess --provider aws --profile standard

# Azure
k1n-posture assess --provider azure --profile standard

# GCP
k1n-posture assess --provider gcp --profile strict

# Check for drift against a baseline
k1n-posture drift --provider aws --baseline baselines/aws/standard.yaml

# Generate a report from saved state
k1n-posture report --input ./output/last_run.json --format markdown

# Offline Azure NSG exposure review
az network nsg list -o json > nsgs.json
k1n-posture scan-azure-nsgs --input nsgs.json --fail-on high

# Offline AWS IAM posture review
k1n-posture scan-aws-iam --input aws-iam-posture.json --fail-on high

# Offline AWS RDS encryption and public exposure review
aws rds describe-db-instances --output json > aws-rds-instances.json
k1n-posture scan-aws-rds --input aws-rds-instances.json --fail-on high

# Offline AWS managed-secret correlation review
# Combine approved Secrets Manager / SSM inventory with hardcoded credential evidence
k1n-posture scan-aws-secrets --input aws-secrets-posture.json --fail-on high

# Offline Azure RBAC posture review
az role assignment list --all -o json > azure-rbac.json
k1n-posture scan-azure-rbac --input azure-rbac.json --trusted-domain example.com --fail-on high

# Offline Azure SQL encryption and firewall review
az sql server list -o json > azure-sql-servers.json
az sql db list --server prod-sql --resource-group rg-prod -o json > azure-sql-databases.json
# Merge the approved exports into one file shaped as {"servers": [...], "databases": [...]}
k1n-posture scan-azure-sql --input azure-sql-export.json --fail-on high

# Offline GCP Cloud SQL public IP and TLS review
gcloud sql instances list --format=json > cloud-sql-instances.json
k1n-posture scan-gcp-cloud-sql --input cloud-sql-instances.json --fail-on high

# Offline GCP IAM posture review
k1n-posture scan-gcp-iam --input gcp-iam-policies.json --org-domain example.com --fail-on high

# Cross-cloud offline IAM comparison
k1n-posture scan-iam-comparison \
  --aws-input aws-iam-posture.json \
  --azure-input azure-rbac.json \
  --gcp-input gcp-iam-policies.json \
  --trusted-domain example.com \
  --org-domain example.com \
  --fail-on high

# Offline GCP firewall exposure review
gcloud compute firewall-rules list --format=json > firewalls.json
k1n-posture scan-gcp-firewalls --input firewalls.json --fail-on high

# Send a report summary to Slack or Teams
k1n-posture notify-webhook \
  --input ./output/posture_aws_latest.json \
  --target slack \
  --webhook-url "$POSTURE_WEBHOOK_URL"

# Review the payload without sending it
k1n-posture notify-webhook \
  --input ./output/posture_aws_latest.json \
  --target teams \
  --dry-run

# Print the stable posture-report JSON schema
k1n-posture json-schema

# Compare the latest report to the previous snapshot and dry-run a Slack alert
k1n-posture watch-report \
  --input ./output/posture_aws_latest.json \
  --state-file ./output/aws-watch-state.json \
  --alert-on high \
  --target slack \
  --dry-run
```

---

## Architecture

```
cloud-posture-watch/
├── providers/          # Cloud-specific data collectors (read-only API calls)
│   ├── aws/
│   ├── azure/
│   └── gcp/
├── analyzers/          # Cross-cloud analysis logic (exposure, logging, drift)
├── baselines/          # YAML baseline profiles per provider
├── schemas/            # Pydantic models for all data structures
├── reports/            # Report generation
├── cli/                # Click CLI entry point
└── docs/               # Extended documentation
```

Each **provider** module collects raw configuration state and returns typed dataclasses. The **analyzers** consume provider output and apply policy logic. The **reports** module serialises findings into human-readable output.

---

## Supported services

| Provider | Service          | Checks                                              |
|----------|------------------|-----------------------------------------------------|
| AWS      | S3               | Public access block, encryption, logging, versioning |
| AWS      | CloudTrail       | Enabled, multi-region, log validation               |
| AWS      | Security Groups  | World-open SSH/RDP, public admin/database exposure  |
| AWS      | VPC Flow Logs    | Missing telemetry, delivery destination gaps, reject-traffic gaps, coarse aggregation |
| AWS      | IAM              | Offline export review for root MFA, stale active user access keys, and permissive policies |
| AWS      | RDS              | Offline export review for storage encryption, public accessibility, and public DB subnet group risk |
| AWS      | Secrets / SSM    | Offline inventory correlation for managed secret adoption, unmanaged hardcoded credentials, and plaintext credential parameters |
| Azure    | SQL Database     | Offline export review for TDE disablement, public network access, Azure-services firewall access, and broad public firewall ranges |
| Azure    | RBAC             | Offline export review for broad Owner/Contributor scope, guest privileged assignments, service principal Owner grants, and wildcard custom roles |
| Azure    | Storage Accounts | HTTPS-only, public blob access, encryption          |
| Azure    | NSGs             | Offline export review for world-open admin, database, web, and broad inbound rules |
| GCP      | Cloud SQL        | Offline export review for public IPv4 exposure, SSL/TLS enforcement, and broad authorized networks |
| GCP      | Cloud Storage    | Uniform bucket-level access, public ACLs            |
| GCP      | IAM              | Offline export review for primitive roles, public IAM members, external sensitive-role users, and service account key age |
| GCP      | Firewall Rules   | Offline export review for world-open admin, database, web, and broad inbound rules |
| GCP      | Cloud Logging    | Audit log configuration                             |

---

## Required permissions

All collectors use **read-only** permissions. No write operations are performed.

### AWS (minimum IAM policy)

```json
{
  "Effect": "Allow",
  "Action": [
    "s3:ListAllMyBuckets",
    "s3:GetBucketAcl",
    "s3:GetBucketEncryption",
    "s3:GetBucketLogging",
    "s3:GetBucketVersioning",
    "s3:GetBucketPublicAccessBlock",
    "cloudtrail:DescribeTrails",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeFlowLogs",
    "ec2:DescribeVpcs",
    "iam:GetAccountSummary",
    "iam:GenerateCredentialReport",
    "iam:GetCredentialReport",
    "iam:ListPolicies",
    "iam:GetPolicyVersion"
  ],
  "Resource": "*"
}
```

Offline AWS IAM review can use an approved JSON evidence bundle instead of live credentials. Include `account_summary.SummaryMap.AccountMFAEnabled`, credential-report user rows with `access_key_*_active` and `access_key_*_age_days`, and policy documents under `policies[].document`.

Offline AWS RDS review can use an approved JSON export from `aws rds describe-db-instances --output json`, plus optional `aws rds describe-db-clusters --output json` content when Aurora clusters are in scope. The analyzer accepts common wrapped response shapes and flags missing `StorageEncrypted`, `PubliclyAccessible`, and DB subnet groups that include public subnets.

Offline AWS secrets correlation can use an approved JSON bundle with `secrets`, `parameters`, and optional `hardcoded_credentials` arrays. Secrets can come from `aws secretsmanager list-secrets --output json`, parameters can come from `aws ssm describe-parameters --output json`, and hardcoded credential evidence can come from a separate approved code or config review. The analyzer correlates credential-like identifiers such as `DB_PASSWORD` or `API_TOKEN` with managed secret names, flags hardcoded literals that appear to duplicate an AWS-managed secret, flags hardcoded credentials that still lack a managed-secret counterpart, and reports credential-bearing SSM parameters stored as plaintext `String` values.

### Azure

Requires the built-in **Reader** role on the target subscription.

Offline Azure RBAC review can use an approved JSON export instead of live credentials. Export role assignments with `az role assignment list --all -o json`; when reviewing wildcard custom roles, wrap the export as `{"assignments": [...], "role_definitions": [...]}` and include role definitions from `az role definition list --custom-role-only true -o json`.

Offline Azure SQL review can use approved JSON evidence instead of live credentials. Supply one JSON file with `servers` and `databases` arrays, for example by combining `az sql server list -o json`, per-server firewall rule exports, and `az sql db list --server <name> --resource-group <rg> -o json` results into a single approved bundle. The analyzer checks `publicNetworkAccess`, firewall rule ranges, and Transparent Data Encryption status when present.

### GCP

Requires the **roles/viewer** IAM role on the target project.

Offline GCP Cloud SQL review can use an approved JSON export from `gcloud sql instances list --format=json` instead of live credentials. The analyzer checks `settings.ipConfiguration.ipv4Enabled`, public `ipAddresses`, `authorizedNetworks`, and SSL/TLS controls such as `requireSsl` or `sslMode`.

Offline GCP IAM review can use approved JSON evidence instead of live credentials. Use IAM policy exports with `bindings` records and include optional `service_account_keys` metadata with `service_account`, `key_id`, and `created_at_days_ago` when key-age review is needed.

Live firewall collection uses read-only Compute API access such as `compute.firewalls.list`; offline review only needs a JSON export from an account allowed to list firewall rules.

---

## Baseline profiles

| Profile    | Description                                                   |
|------------|---------------------------------------------------------------|
| `minimal`  | Catches only critical misconfigurations (public buckets, etc.) |
| `standard` | Recommended for most production environments                  |
| `strict`   | High-assurance environments; fails on warnings too            |

Baselines are YAML files in `baselines/<provider>/`. Fork and customise them freely.

---

## Output

Reports are written to `./output/` (configurable via `OUTPUT_DIR`). Each run produces:

- `posture_<provider>_<timestamp>.md` — Markdown narrative report
- `posture_<provider>_<timestamp>.json` — Machine-readable findings (for CI integration)

The shared risk model weights findings as CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, and INFO=0, then caps the total score at 100. JSON exports include both `risk_score` and `risk_level` so downstream dashboards and CI gates can preserve the same posture interpretation as the human-readable reports.

JSON posture exports include `$schema` and `schema_version` fields. `k1n-posture json-schema` prints the v1 contract for downstream validators and dashboards, including required report metadata, finding counts, finding records, drift records, and the risk-model fields.

Webhook notifications use saved JSON posture reports as input. `k1n-posture notify-webhook --target slack|teams` builds a provider summary, severity counts, and the top findings, then posts it to an HTTPS incoming webhook. Use `--dry-run` during change review to print the exact payload without sending data or exposing a webhook secret in command output.

Watch mode is designed for scheduled runners that already refresh posture JSON artifacts. `k1n-posture watch-report --input latest.json --state-file .watch/aws.json --alert-on high --target slack|teams` compares the latest report to the previous snapshot, summarizes new, resolved, and persistent findings, updates the state file, and only emits an alert when newly introduced findings meet the configured severity threshold. By default the first run seeds state without alerting to avoid noisy bootstrap notifications; add `--alert-on-first-run` when an initial alert is desired.

The repository now includes a composite GitHub Action in [`action.yml`](action.yml). It installs `cloud-posture-watch`, validates the requested `k1n-posture` subcommand without invoking a shell, runs inside the workflow workspace, and publishes the newest Markdown, JSON, and HTML report paths as step outputs for downstream upload or notification steps.

---

## Running in CI

```yaml
name: posture

on:
  workflow_dispatch:
  push:
    branches: [main]

jobs:
  assess:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Run AWS posture assessment
        id: posture
        uses: hiagokinlevi/cloud-posture-watch@main
        with:
          command: assess
          provider: aws
          args: --profile standard --fail-on high
          output-dir: ./output
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.POSTURE_AWS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.POSTURE_AWS_SECRET }}
          AWS_REGION: us-east-1

      - name: Upload Markdown report
        if: ${{ steps.posture.outputs.report-markdown != '' }}
        uses: actions/upload-artifact@v4
        with:
          name: posture-report
          path: ${{ steps.posture.outputs.report-markdown }}
```

Use `command: watch-report` with `args: --input ./output/posture_aws_latest.json --state-file .watch/aws-watch-state.json --alert-on high --target slack --webhook-url ${{ secrets.POSTURE_SLACK_WEBHOOK }}` when you want scheduled delta alerts instead of a fresh live assessment. Keep `--provider` and `--output-dir` in the dedicated action inputs so the action can validate and publish the resolved paths consistently.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are welcome.

## Security

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy.

## License

MIT — see [LICENSE](LICENSE).

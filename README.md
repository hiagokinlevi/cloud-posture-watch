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
- **Offline GCP IAM review** — scans exported IAM policies for primitive roles, public principals, external sensitive-role users, default service accounts, and stale service account keys
- **Offline Azure NSG review** — scans exported `az network nsg list` JSON for public admin, database, and broad inbound rules
- **Offline GCP firewall review** — scans exported `gcloud compute firewall-rules list` JSON for public admin, database, web, and broad inbound rules
- **Encryption posture** — validates encryption at rest and in transit across storage and database services
- **Configuration drift detection** — compares live state against YAML baselines and highlights deviations
- **Risk scoring** — applies a shared numeric 0-100 severity model across CLI summaries, Markdown, JSON, and HTML reports
- **Markdown reports** — human-readable output with findings, scores, and remediation recommendations
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

# Offline GCP IAM posture review
k1n-posture scan-gcp-iam --input gcp-iam-policies.json --org-domain example.com --fail-on high

# Offline GCP firewall exposure review
gcloud compute firewall-rules list --format=json > firewalls.json
k1n-posture scan-gcp-firewalls --input firewalls.json --fail-on high
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
| Azure    | Storage Accounts | HTTPS-only, public blob access, encryption          |
| Azure    | NSGs             | Offline export review for world-open admin, database, web, and broad inbound rules |
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

### Azure

Requires the built-in **Reader** role on the target subscription.

### GCP

Requires the **roles/viewer** IAM role on the target project.

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

---

## Running in CI

```yaml
# Example GitHub Actions step
- name: Cloud posture check
  run: k1n-posture assess --provider aws --profile standard --fail-on high
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.POSTURE_AWS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.POSTURE_AWS_SECRET }}
    AWS_REGION: us-east-1
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are welcome.

## Security

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy.

## License

MIT — see [LICENSE](LICENSE).

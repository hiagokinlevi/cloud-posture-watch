# cloud-posture-watch

**Cloud security posture assessment for AWS, Azure, and GCP — exposure analysis, logging gaps, and configuration drift detection.**

`cloud-posture-watch` is a multi-cloud CLI tool that audits the security posture of your cloud environments. It collects configuration state from AWS, Azure, and GCP using read-only APIs, compares that state against opinionated security baselines, and produces structured reports covering public exposure, logging coverage, encryption posture, VPC network telemetry, and configuration drift.

---

## Features

- **Multi-cloud support** — AWS, Azure, and GCP in a single tool
- **Exposure analysis** — identifies publicly accessible storage, compute, and network resources
- **Logging gap detection** — checks whether audit trails, access logs, and flow logs are enabled
- **VPC Flow Logs coverage** — flags AWS VPCs with missing flow logs, missing delivery destinations, missing rejected-traffic capture, or coarse aggregation windows
- **Offline AWS CloudTrail review** — scans exported trail configs for disabled logging, missing validation, missing global events, absent CloudWatch forwarding, and management-event gaps
- **Offline AWS IAM review** — scans exported IAM evidence for root MFA gaps, stale active user keys, and permissive policies
- **Offline AWS RDS review** — scans exported RDS instance and cluster evidence for missing storage encryption and public database exposure
- **Offline AWS secrets correlation** — compares Secrets Manager or Parameter Store inventory against approved hardcoded credential findings to spot unmanaged literals and plaintext credential parameters
- **Offline Azure SQL review** — scans exported logical server and database evidence for disabled TDE, public network access, and broad firewall rules
- **Offline GCP Cloud SQL review** — scans exported Cloud SQL instance evidence for public IPv4 exposure, weak authorized networks, and missing SSL/TLS enforcement
- **Offline Azure RBAC review** — scans role assignment exports for broad Owner/Contributor access, guest privileged assignments, service principal Owner grants, and wildcard custom roles
- **Offline GCP IAM review** — scans exported IAM policies for primitive roles, public principals, external sensitive-role users, default service accounts, and stale service account keys
- **Cross-cloud IAM comparison** — combines offline AWS, Azure, and GCP identity findings into one Markdown and JSON review artifact

## CLI options

- `--max-findings <int>` — cap findings emitted in JSON/Markdown/SARIF outputs after severity-first deterministic sorting; summary includes truncation context (for example, `displayed 200 of 612 findings`).

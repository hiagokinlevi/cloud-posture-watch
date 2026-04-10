# Overview

`cloud-posture-watch` is a command-line tool for assessing the security posture of cloud environments across AWS, Azure, and GCP.

## What is cloud security posture management (CSPM)?

Cloud Security Posture Management refers to the practice of continuously assessing cloud infrastructure configurations against security best practices, regulatory requirements, and organisational policies. Where traditional security tools focus on active threats, CSPM focuses on configuration risk: the misconfigured storage bucket that is publicly accessible, the database that lacks encryption, the audit log that was never enabled.

For Azure network reviews, `k1n-posture scan-azure-nsgs --input nsgs.json` accepts an offline `az network nsg list -o json` export and applies the NSG exposure analyzer without requiring live credentials. This is useful in restricted environments where a read-only export is easier to approve than direct API access.

For GCP network reviews, `k1n-posture scan-gcp-firewalls --input firewalls.json` accepts an offline `gcloud compute firewall-rules list --format=json` export and applies the same cross-cloud exposure checks to firewall rules without requiring live credentials.

For AWS identity reviews, `k1n-posture scan-aws-iam --input aws-iam-posture.json` accepts an offline JSON bundle with IAM account-summary, credential-report, and policy-document evidence. It flags missing root MFA evidence, stale active IAM user access keys, and wildcard administrative policies without making live API calls.

For AWS database reviews, `k1n-posture scan-aws-rds --input aws-rds-instances.json` accepts offline RDS instance exports from `aws rds describe-db-instances --output json`, plus common wrapped response shapes and optional cluster exports. It flags unencrypted database storage, publicly accessible RDS instances, and DB subnet groups that include public subnets without making live API calls.

For AWS secrets reviews, `k1n-posture scan-aws-secrets --input aws-secrets-posture.json` accepts an approved JSON bundle with Secrets Manager inventory, SSM Parameter Store inventory, and optional hardcoded credential findings from source or configuration review. It correlates managed secret names with identifiers such as `DB_PASSWORD` or `API_TOKEN`, flags hardcoded credentials that still appear in code despite managed-secret coverage, flags hardcoded credentials that have no managed AWS counterpart yet, and reports credential-like SSM parameters still stored as plaintext `String` values.

For Azure identity reviews, `k1n-posture scan-azure-rbac --input azure-rbac.json --trusted-domain example.com` accepts offline role assignment exports from `az role assignment list --all -o json`. It flags broad Owner or Contributor assignments, guest or external privileged principals, service-principal Owner grants, User Access Administrator delegation gaps, and wildcard custom roles without making live API calls.

For GCP database reviews, `k1n-posture scan-gcp-cloud-sql --input cloud-sql-instances.json` accepts offline exports from `gcloud sql instances list --format=json`. It flags public IPv4 exposure, broad `authorizedNetworks`, and missing SSL/TLS enforcement controls without making live API calls.

For GCP identity reviews, `k1n-posture scan-gcp-iam --input gcp-iam-policies.json --org-domain example.com` accepts offline IAM policy exports with optional service account key metadata. It flags primitive Owner/Editor/Viewer grants, public principals, external users in sensitive roles, default service accounts, broad IAM-admin roles, and stale service account keys without making live API calls.

For cross-cloud identity reviews, `k1n-posture scan-iam-comparison --aws-input aws-iam-posture.json --azure-input azure-rbac.json --gcp-input gcp-iam-policies.json` reuses the offline IAM analyzers and writes one Markdown plus JSON comparison artifact. It groups findings by provider and by recurring identity themes: credential hygiene, privileged standing access, external or public access, and custom or wildcard permissions.

For notification workflows, `k1n-posture notify-webhook --input posture.json --target slack|teams` reads a saved JSON posture report and sends a compact severity summary plus top findings to an incoming Slack or Microsoft Teams webhook. Use `--dry-run` to inspect the payload without making a network request.

For scheduled monitoring workflows, `k1n-posture watch-report --input posture.json --state-file .watch/aws.json --alert-on high --target slack|teams` compares the latest posture report to the previous snapshot, highlights newly introduced versus resolved findings, and emits an alert only when the new findings meet the configured severity threshold.

## What this tool does

1. **Collects** configuration state from cloud APIs using read-only credentials.
2. **Analyzes** that state against rules covering exposure, logging, encryption, network access, and IAM posture.
3. **Compares** live state against YAML baseline profiles to detect configuration drift.
4. **Reports** findings in Markdown with severity ratings, risk scores, and remediation guidance.
5. **Watches** scheduled JSON posture artifacts for newly introduced findings.
6. **Notifies** Slack or Teams channels from approved JSON posture artifacts when an operator supplies an HTTPS incoming webhook.

## What this tool does not do

- It does not perform active exploitation or penetration testing.
- It does not modify any cloud resources.
- It does not store credentials or send data to external services.
- It does not send webhook notifications unless `notify-webhook` is invoked without `--dry-run` and an HTTPS webhook URL is supplied.
- It does not schedule itself; use cron, GitHub Actions, or another runner to refresh reports and invoke `watch-report`.
- Offline Azure SQL review accepts approved server and database exports so teams can validate TDE and firewall posture before enabling public connectivity exceptions.
- It does not replace a comprehensive security review or threat model.

## Supported providers

| Provider | Auth mechanism                          |
|----------|-----------------------------------------|
| AWS      | AWS SDK default credential chain (profile, env vars, IAM role) |
| Azure    | DefaultAzureCredential or service principal via env vars |
| GCP      | Application Default Credentials or service account key file |

## Next steps

- [Cloud security model](cloud-security-model.md) — the conceptual framework behind the checks
- [Posture methodology](posture-methodology.md) — how findings are derived and scored
- [First AWS assessment tutorial](../training/tutorials/first-aws-assessment.md)

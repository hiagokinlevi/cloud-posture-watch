# Overview

`cloud-posture-watch` is a command-line tool for assessing the security posture of cloud environments across AWS, Azure, and GCP.

## What is cloud security posture management (CSPM)?

Cloud Security Posture Management refers to the practice of continuously assessing cloud infrastructure configurations against security best practices, regulatory requirements, and organisational policies. Where traditional security tools focus on active threats, CSPM focuses on configuration risk: the misconfigured storage bucket that is publicly accessible, the database that lacks encryption, the audit log that was never enabled.

For Azure network reviews, `k1n-posture scan-azure-nsgs --input nsgs.json` accepts an offline `az network nsg list -o json` export and applies the NSG exposure analyzer without requiring live credentials. This is useful in restricted environments where a read-only export is easier to approve than direct API access.

## What this tool does

1. **Collects** configuration state from cloud APIs using read-only credentials.
2. **Analyzes** that state against rules covering exposure, logging, encryption, and network access.
3. **Compares** live state against YAML baseline profiles to detect configuration drift.
4. **Reports** findings in Markdown with severity ratings, risk scores, and remediation guidance.

## What this tool does not do

- It does not perform active exploitation or penetration testing.
- It does not modify any cloud resources.
- It does not store credentials or send data to external services.
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

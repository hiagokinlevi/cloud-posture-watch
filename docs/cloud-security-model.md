# Cloud Security Model

This document describes the security model used by `cloud-posture-watch` to classify and prioritize findings.

## The shared responsibility model

All three major cloud providers operate under a shared responsibility model: the provider secures the underlying infrastructure (physical hardware, hypervisor, network backbone), while the customer is responsible for securing what they deploy on top of it.

Common customer responsibilities that this tool checks:

- **Data protection** — encryption at rest and in transit, backup, versioning
- **Access control** — preventing public exposure, enforcing least privilege
- **Logging and monitoring** — ensuring audit trails exist for incident response
- **Network segmentation** — firewall rules, security groups, private endpoints

## Risk domains

The tool organizes findings into four primary risk domains:

### 1. Exposure

A resource is "exposed" when it can be accessed by unintended parties, including the public internet. Exposure findings carry the highest severity because they directly represent a data breach risk.

Examples:
- S3 bucket with public access block disabled
- GCS bucket with an `allUsers` IAM binding
- Azure Storage Account with `allowBlobPublicAccess: true`
- GCP firewall rule allowing SSH, RDP, database, or broad port access from `0.0.0.0/0` or `::/0`

### 2. Logging gaps

Logging gaps mean that activity on a resource is not being recorded. Without logs, detecting unauthorized access, investigating incidents, and meeting compliance requirements become impossible.

Examples:
- S3 server access logging disabled
- CloudTrail not enabled in all regions
- GCS access logging not configured

### 3. Encryption posture

Encryption findings indicate that data is stored or transmitted without cryptographic protection. While cloud providers increasingly encrypt by default, the absence of explicit configuration is a risk.

Examples:
- S3 bucket without default encryption
- Azure Storage Account without a customer-managed key (strict profile)
- GCP Cloud SQL without SSL enforcement

### 4. Configuration drift

Drift findings indicate that a resource's configuration has deviated from an approved baseline. Drift may be intentional (in which case the baseline should be updated) or accidental (indicating a change control failure).

## Severity model

| Severity | Meaning                                                         |
|----------|-----------------------------------------------------------------|
| CRITICAL | Confirmed exposure or data risk; immediate action required       |
| HIGH     | Strong indicator of risk; remediate within the current sprint    |
| MEDIUM   | Control gap; remediate in the near term                         |
| LOW      | Improvement opportunity; address in the next planning cycle     |
| INFO     | Informational; no immediate action required                     |

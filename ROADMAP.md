# Roadmap

This document outlines the planned development direction for `cloud-posture-watch`. Items are not strictly ordered and may shift based on community feedback.

---

## v0.1 — Foundation (current)

- [x] Project structure and CLI scaffold
- [x] AWS S3 storage posture collector
- [x] Azure Storage Account collector
- [x] GCP Cloud Storage collector
- [x] Exposure, logging, and drift analyzers
- [x] Markdown report generation
- [x] YAML baseline profiles (minimal / standard / strict) for all three providers

---

## v0.2 — Compute and network coverage

- [x] AWS EC2 security group collector (SSH/RDP world-open detection)
- [x] AWS VPC flow logs coverage and destination checks
- [x] Azure NSG offline export scanner
- [x] GCP Firewall rules collector and offline export scanner
- [x] Risk scoring model with numeric severity ratings

---

## v0.3 — Identity and access

- [x] AWS IAM: root account MFA, access key age, overly permissive policies
- [x] Azure RBAC: guest accounts, overly broad role assignments
- [x] GCP IAM: service account key age, primitive role usage
- [x] Cross-cloud IAM comparison report

---

## v0.4 — Continuous monitoring mode

- [x] Watch mode: compare scheduled posture-report snapshots and alert on new findings
- [x] Webhook output for Slack / Teams notifications
- [x] JSON output schema stable for downstream tooling integration
- [x] GitHub Actions marketplace action

---

## v0.5 — Database and secrets posture

- [x] AWS RDS encryption and public accessibility check
- [x] Azure SQL encryption and firewall rules
- [x] GCP Cloud SQL public IP and SSL enforcement
- [x] AWS Secrets Manager / Parameter Store vs. hardcoded credential heuristic

---

## Future / Under consideration

- [x] Cloud SOAR routing layer with provider playbooks, approval po

## Automated Completions
- [x] CLI `--max-findings` Flag to Cap Output Volume (cycle 57)

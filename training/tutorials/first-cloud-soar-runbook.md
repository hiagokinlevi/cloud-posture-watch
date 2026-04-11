# First Cloud SOAR Runbook

This tutorial introduces the SOAR layer inside `cloud-posture-watch`.

## What You Will Learn

- how a finding maps to a playbook
- how approval requirements are represented
- how to distinguish preparation actions from live response actions

## Suggested Exercise

1. Start with a synthetic event from `samples/events/`.
2. Run `k1n-posture resolve-soar --input <event.json> --format json`.
3. Review the selected playbook under `soar/playbooks/`.
4. Compare the chosen actions to `soar/configs/default_approval.yaml`.
5. Confirm which actions are preparation-only and which require approval.

## Recommended Practice Inputs

- `samples/events/aws_compromised_access_key_event.json`
- `samples/events/aws_public_bucket_event.json`
- `samples/events/azure_suspicious_service_principal_event.json`
- `samples/events/gcp_public_storage_bucket_event.json`

## Why This Matters

Cloud security teams often have findings but no shared response pattern. The SOAR layer is meant to close that gap with structured, reviewable, defender-safe automation guidance.

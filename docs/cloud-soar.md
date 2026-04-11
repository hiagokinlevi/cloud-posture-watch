# Cloud SOAR Layer

`cloud-posture-watch` now includes a Cloud SOAR layer for routing findings into cloud-specific response playbooks.

## Purpose

The posture engine already tells you what is risky. The SOAR layer adds:

- response playbook routing
- approval-aware response guidance
- action preparation checklists
- multicloud rule mapping from findings to operator workflow

## Included Assets

- playbooks for AWS, Azure, and GCP cloud incidents
- YAML routing rules in `soar/rules/`
- approval and execution guidance in `soar/configs/`
- synthetic event support for testing and training
- CLI routing with `k1n-posture resolve-soar --input <event.json>`

## Operating Model

1. posture finding or alert enters triage
2. provider, flag, and resource type are normalized
3. SOAR rules select a playbook and action list
4. operators review approval requirements
5. teams execute safe, evidence-preserving steps

## Example Inputs

- `samples/events/aws_public_bucket_event.json`
- `samples/events/aws_compromised_access_key_event.json`
- `samples/events/azure_suspicious_service_principal_event.json`
- `samples/events/gcp_public_storage_bucket_event.json`

## CLI Example

```bash
k1n-posture resolve-soar \
  --input samples/events/azure_suspicious_service_principal_event.json \
  --format json
```

The output includes:

- matched rule identifier
- selected playbook path
- effective severity
- approval mode for that severity
- preparation actions that are allowed before live response
- execution-policy controls such as dry-run defaults and evidence preservation

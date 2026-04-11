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

## Operating Model

1. posture finding or alert enters triage
2. provider, flag, and resource type are normalized
3. SOAR rules select a playbook and action list
4. operators review approval requirements
5. teams execute safe, evidence-preserving steps

# First Cloud SOAR Runbook

This tutorial introduces the SOAR layer inside `cloud-posture-watch`.

## What You Will Learn

- how a finding maps to a playbook
- how approval requirements are represented
- how to distinguish preparation actions from live response actions

## Suggested Exercise

1. start with a synthetic AWS or Azure finding
2. route it through the SOAR rules
3. review the selected playbook
4. confirm which actions are preparation-only and which require approval

## Why This Matters

Cloud security teams often have findings but no shared response pattern. The SOAR layer is meant to close that gap with structured, reviewable, defender-safe automation guidance.

# GCP Public Storage Bucket

## Trigger Conditions

- `allUsers` or `allAuthenticatedUsers` member on bucket IAM
- public object exposure through inherited IAM or ACL-style controls
- drift from uniform bucket-level access baseline

## Immediate Triage

1. Identify bucket, project, and business owner.
2. Confirm whether the bucket should be public by design.
3. Determine whether sensitive or regulated data may be present.
4. Review access logging and recent IAM changes.

## Containment

1. Remove public principals if the exposure is not intentional.
2. Re-enable baseline controls such as uniform bucket-level access where required.
3. Preserve bucket IAM evidence and object listing evidence before changes.

## Investigation Focus

- project sensitivity
- recent policy changes
- object inventory and data classification
- downstream services that rely on the bucket

## Recovery

- restore least-privilege bucket IAM
- verify logging and retention posture
- confirm whether any exposed objects require incident notification

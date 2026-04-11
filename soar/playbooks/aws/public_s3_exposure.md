# AWS Public S3 Exposure

## Trigger Conditions

- bucket policy grants public read or write
- ACL allows global access
- Public Access Block disabled or partially disabled
- sensitive bucket exposed through posture drift

## Immediate Triage

1. Confirm bucket name, region, and owning account.
2. Determine whether exposure is read-only or write-capable.
3. Check whether the bucket is production, backup, or static-content only.
4. Review recent object access logging if available.

## Containment

1. Enable or restore Public Access Block where appropriate.
2. Remove broad bucket policy statements.
3. Preserve policy and ACL evidence before changing them.

## Investigation Focus

- object sensitivity
- access logging availability
- recent `GetObject`, `PutObject`, and policy changes
- replication or cross-account trust relationships

## Recovery

- restore secure bucket policy
- verify encryption, logging, and ownership controls
- notify data owners if sensitive exposure is confirmed

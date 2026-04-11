# AWS Compromised Access Key

## Trigger Conditions

- key observed in suspicious activity
- access from unexpected ASN or geography
- impossible travel or new automation pattern
- link to high-risk IAM findings or secret exposure

## Immediate Triage

1. Confirm the AWS account and IAM principal.
2. Validate whether the key is still active.
3. Check CloudTrail for the first suspicious API calls.
4. Determine whether privileged APIs, secrets, or storage were accessed.

## Containment

1. Disable the access key if business impact is acceptable.
2. If immediate disablement is risky, apply compensating controls and approval-gated restrictions.
3. Preserve CloudTrail, GuardDuty, and IAM evidence before broad changes.

## Investigation Focus

- `sts:GetCallerIdentity`
- privilege escalation paths
- secret retrieval
- S3 enumeration or object access
- IAM policy changes

## Recovery

- rotate affected credentials
- review attached policies and session activity
- verify downstream systems that trusted the compromised key

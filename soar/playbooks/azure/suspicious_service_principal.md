# Azure Suspicious Service Principal

## Trigger Conditions

- privileged role assignment to a service principal
- unfamiliar application registration with broad access
- guest or external principal in sensitive scope
- unusual token or role usage linked to automation identities

## Immediate Triage

1. Identify the service principal, app registration, and owning team.
2. Confirm assigned roles and scope.
3. Review the timeline of role assignment and credential creation.
4. Check sign-in or audit logs for recent use.

## Containment

1. Remove or reduce privileged role assignments if approved.
2. Disable credentials or certificates when compromise is suspected.
3. Preserve Entra and Azure activity evidence before large changes.

## Investigation Focus

- Owner / Contributor assignments
- recent credential additions
- external tenant links
- subscriptions or resource groups in sensitive scope

## Recovery

- rotate app credentials
- reassign least-privilege roles
- review automation dependencies before final disablement

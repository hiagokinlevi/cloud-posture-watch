# Cloud Posture Assessment Prompts

A reference collection of prompts for use with AI assistants when working with cloud posture findings.

---

## Interpreting a posture report

```
I have a cloud posture assessment report for my AWS account.
Here are the findings: [paste findings here]

Please:
1. Summarize the top 3 risks I should address first and explain why.
2. For each HIGH or CRITICAL finding, give me a concrete AWS CLI or Terraform
   command to remediate it.
3. Identify any findings that are likely false positives for a development
   environment and explain your reasoning.
```

---

## Reviewing an S3 bucket configuration

```
I ran cloud-posture-watch on my AWS account and it flagged the following
S3 bucket: [bucket name]

Risk flags: [paste flags]

The bucket is used for: [describe use case]

Please tell me:
- Which flags represent genuine risks for this use case?
- Which remediation steps should I prioritize?
- What is the minimum IAM policy I need to apply the fixes?
```

---

## Writing a YAML baseline

```
I want to create a custom security baseline for my [provider] environment.
My requirements are:
- [Requirement 1]
- [Requirement 2]
- [Requirement 3]

Please generate a YAML baseline file in the cloud-posture-watch format
with appropriate controls for my requirements. Follow the structure in
baselines/[provider]/standard.yaml.
```

---

## Understanding drift

```
My posture assessment showed the following drift items against the standard baseline:
[paste drift items]

For each drift item:
1. Explain what the drift means in plain language.
2. Tell me whether this is a genuine security risk or potentially a valid deviation.
3. If it is a risk, provide the remediation steps.
```

---

## Adding a new provider collector

```
I want to add a collector for [service name] on [provider].
The relevant API is [describe the API].
The security attributes I want to collect are:
- [Attribute 1]
- [Attribute 2]

Please write a Python collector module following the style of
providers/aws/storage_collector.py, including:
- A typed dataclass for the resource posture
- The collection function with docstring and inline comments
- Required permissions listed in the module docstring
```

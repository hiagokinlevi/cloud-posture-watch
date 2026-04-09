# Tutorial: Your First AWS Assessment

This tutorial walks you through running a posture assessment on an AWS account from scratch.

## Prerequisites

- Python 3.11+ installed
- An AWS account you are authorised to assess
- An IAM user or role with the read-only permissions listed in the README
- AWS CLI configured with a profile (`aws configure`)

## Step 1: Install cloud-posture-watch

```bash
git clone https://github.com/hiagokinlevi/cloud-posture-watch.git
cd cloud-posture-watch
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify the installation:

```bash
k1n-posture --help
```

## Step 2: Configure your environment

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```
PROVIDER=aws
AWS_PROFILE=your-profile-name
AWS_REGION=us-east-1
BASELINE_PROFILE=standard
OUTPUT_DIR=./output
```

## Step 3: Run the assessment

```bash
k1n-posture assess --provider aws --profile standard
```

You should see output similar to:

```
Provider:  AWS
Profile:   standard
Baseline:  baselines/aws/standard.yaml
Output:    ./output

Collecting S3 bucket posture...
  Found 12 bucket(s).

Report written to: output/posture_aws_20260401_143022.md
```

## Step 4: Review the report

Open the generated Markdown report:

```bash
open output/posture_aws_20260401_143022.md   # macOS
# or
cat output/posture_aws_20260401_143022.md
```

The report begins with an executive summary and risk score, followed by individual findings.

## Step 5: Understand the findings

A typical finding looks like this:

```
### Finding 1: [HIGH] S3 bucket Public Access Block is not fully enabled

- Resource: `my-app-uploads` (s3_bucket)
- Provider: AWS
- Severity: HIGH
- Flag: `public_access_not_fully_blocked`

**Recommendation:**

> Ensure all four settings are True: BlockPublicAcls, IgnorePublicAcls,
> BlockPublicPolicy, RestrictPublicBuckets.
```

To remediate this finding in the AWS Console:
1. Navigate to S3 > your bucket > Permissions
2. Click "Edit" under "Block public access (bucket settings)"
3. Enable all four checkboxes

Or via AWS CLI:

```bash
aws s3api put-public-access-block \
  --bucket my-app-uploads \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

## Step 6: Run a drift check

To see which buckets deviate from the standard baseline:

```bash
k1n-posture drift \
  --provider aws \
  --baseline baselines/aws/standard.yaml \
  --sensitivity medium
```

## Next steps

- Customize `baselines/aws/standard.yaml` for your organisation's requirements
- Set `FAIL_ON_SEVERITY=high` and integrate into your CI pipeline
- Read [posture-methodology.md](../../docs/posture-methodology.md) to understand how risk scores are calculated

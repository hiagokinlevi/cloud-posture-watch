from analyzers.aws_s3_secrets_exposure import analyze_aws_s3_secrets_exposure


def test_detects_regex_based_secret_in_content():
    evidence = {
        "s3": {
            "objects": [
                {
                    "bucket": "demo-bucket",
                    "key": "app.env",
                    "content": "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
                }
            ]
        }
    }

    findings = analyze_aws_s3_secrets_exposure(evidence)
    assert findings
    assert any(f["details"]["detector"] == "aws_access_key_id" for f in findings)


def test_detects_private_key_in_metadata():
    evidence = {
        "s3": {
            "objects": [
                {
                    "bucket": "keys",
                    "key": "id_rsa.txt",
                    "metadata": {
                        "note": "-----BEGIN PRIVATE KEY-----",
                    },
                }
            ]
        }
    }

    findings = analyze_aws_s3_secrets_exposure(evidence)
    assert any(f["severity"] == "critical" for f in findings)


def test_detects_high_entropy_token():
    evidence = {
        "s3": {
            "objects": [
                {
                    "bucket": "entropy",
                    "key": "blob.txt",
                    "content": "token=QWxhZGRpbjpPcGVuU2VzYW1lMTIzNDU2Nzg5MDEyMzQ=",
                }
            ]
        }
    }

    findings = analyze_aws_s3_secrets_exposure(evidence)
    assert any(f["details"]["detector"] == "high_entropy_token" for f in findings)

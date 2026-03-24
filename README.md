# Cloud Security Posture Dashboard

A Python-based CLI tool that audits AWS cloud environments for security 
misconfigurations and generates risk scores with actionable recommendations.

## Features

- Scans S3 buckets for public access, encryption, and versioning issues
- Audits IAM users for MFA, weak passwords, and old access keys
- Checks security groups for dangerous open ports
- Verifies CloudTrail logging is active
- Calculates an overall risk score out of 100
- Generates JSON audit reports

## Requirements

- Python 3.8+
- boto3
- AWS CLI configured with valid credentials

## Installation
```bash
git clone https://github.com/Bujjiasam733/cloud-security-dashboard.git
cd cloud-security-dashboard
python3 -m venv venv
source venv/bin/activate
pip install boto3 colorama
aws configure
```

## Usage
```bash
python3 main.py
python3 main.py --save
```

## Example Output
```
  Cloud Security Posture Dashboard v1.0

  Scan Time  : 2026-03-24 11:39:40
  Risk Score  : 70 / 100
  HIGH: 2  |  MEDIUM: 0  |  LOW: 0  |  PASSED: 3

  S3 Buckets
  ✓ PASS   S3 Bucket: my-bucket — Public access fully blocked
  ! HIGH   IAM User: admin — MFA not enabled
  ✓ PASS   CloudTrail: my-trail — Logging is active

  Summary
  2 critical issue(s) require immediate attention.
```

## Checks Performed

S3 buckets are checked for public access block configuration, default 
encryption, and versioning. IAM users are audited for MFA enablement, 
access key age, and account password policy. Security groups are scanned 
for dangerous ports open to the internet (0.0.0.0/0). CloudTrail is 
verified to be active and logging API calls.

## Legal Notice

Only run against AWS accounts you own or have explicit permission to audit.

## Author

Bujji Asam — [LinkedIn](https://linkedin.com/in/bujjiasam) | 
[GitHub](https://github.com/Bujjiasam733)
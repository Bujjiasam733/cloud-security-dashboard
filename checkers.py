import boto3
from botocore.exceptions import ClientError

def check_s3_buckets():
    findings = []
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        return [{"error": str(e)}]

    for bucket in buckets:
        name = bucket["Name"]

        # Check public access block
        try:
            pub = s3.get_public_access_block(Bucket=name)
            config = pub["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                findings.append({
                    "resource": f"S3 Bucket: {name}",
                    "severity": "HIGH",
                    "issue": "Public access not fully blocked",
                    "recommendation": "Enable all four public access block settings on the bucket."
                })
            else:
                findings.append({
                    "resource": f"S3 Bucket: {name}",
                    "severity": "PASS",
                    "issue": "Public access fully blocked",
                    "recommendation": ""
                })
        except ClientError:
            findings.append({
                "resource": f"S3 Bucket: {name}",
                "severity": "MEDIUM",
                "issue": "No public access block configuration found",
                "recommendation": "Configure public access block settings explicitly."
            })

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "Disabled")
            if status != "Enabled":
                findings.append({
                    "resource": f"S3 Bucket: {name}",
                    "severity": "LOW",
                    "issue": "Versioning not enabled",
                    "recommendation": "Enable versioning to protect against accidental deletion."
                })
        except ClientError:
            pass

        # Check encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            findings.append({
                "resource": f"S3 Bucket: {name}",
                "severity": "MEDIUM",
                "issue": "Default encryption not enabled",
                "recommendation": "Enable default encryption using AES-256 or AWS KMS."
            })

    return findings


def check_iam_users():
    findings = []
    iam = boto3.client("iam")

    try:
        users = iam.list_users().get("Users", [])
    except ClientError as e:
        return [{"error": str(e)}]

    if not users:
        findings.append({
            "resource": "IAM",
            "severity": "INFO",
            "issue": "No IAM users found",
            "recommendation": "Use IAM roles instead of users where possible."
        })
        return findings

    for user in users:
        username = user["UserName"]

        # Check MFA
        try:
            mfa = iam.list_mfa_devices(UserName=username)
            if not mfa["MFADevices"]:
                findings.append({
                    "resource": f"IAM User: {username}",
                    "severity": "HIGH",
                    "issue": "MFA not enabled",
                    "recommendation": "Enable MFA for all IAM users with console access."
                })
            else:
                findings.append({
                    "resource": f"IAM User: {username}",
                    "severity": "PASS",
                    "issue": "MFA enabled",
                    "recommendation": ""
                })
        except ClientError:
            pass

        # Check access keys age
        try:
            keys = iam.list_access_keys(UserName=username)
            for key in keys["AccessKeyMetadata"]:
                if key["Status"] == "Active":
                    from datetime import datetime, timezone
                    created = key["CreateDate"]
                    age = (datetime.now(timezone.utc) - created).days
                    if age > 90:
                        findings.append({
                            "resource": f"IAM User: {username}",
                            "severity": "MEDIUM",
                            "issue": f"Access key is {age} days old",
                            "recommendation": "Rotate access keys every 90 days."
                        })
        except ClientError:
            pass

    # Check password policy
    try:
        iam.get_account_password_policy()
    except ClientError:
        findings.append({
            "resource": "IAM Account",
            "severity": "MEDIUM",
            "issue": "No account password policy configured",
            "recommendation": "Set a strong password policy: min 14 chars, require uppercase, numbers, symbols."
        })

    return findings


def check_security_groups():
    findings = []
    ec2 = boto3.client("ec2")

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        return [{"error": str(e)}]

    dangerous_ports = {
        22:   "SSH",
        3389: "RDP",
        23:   "Telnet",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
    }

    for sg in sgs:
        name = sg.get("GroupName", "unknown")
        sg_id = sg["GroupId"]

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    for port, service in dangerous_ports.items():
                        if from_port <= port <= to_port:
                            findings.append({
                                "resource": f"Security Group: {name} ({sg_id})",
                                "severity": "HIGH",
                                "issue": f"Port {port} ({service}) open to 0.0.0.0/0",
                                "recommendation": f"Restrict port {port} to specific IP ranges only."
                            })

            for ipv6_range in rule.get("Ipv6Ranges", []):
                cidr = ipv6_range.get("CidrIpv6", "")
                if cidr == "::/0":
                    for port, service in dangerous_ports.items():
                        if from_port <= port <= to_port:
                            findings.append({
                                "resource": f"Security Group: {name} ({sg_id})",
                                "severity": "HIGH",
                                "issue": f"Port {port} ({service}) open to ::/0 (all IPv6)",
                                "recommendation": f"Restrict port {port} to specific IP ranges only."
                            })

    if not findings:
        findings.append({
            "resource": "Security Groups",
            "severity": "PASS",
            "issue": "No dangerous open ports found",
            "recommendation": ""
        })

    return findings


def check_cloudtrail():
    findings = []
    ct = boto3.client("cloudtrail")

    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            findings.append({
                "resource": "CloudTrail",
                "severity": "HIGH",
                "issue": "No CloudTrail trails configured",
                "recommendation": "Enable CloudTrail to log all API activity across your AWS account."
            })
            return findings

        for trail in trails:
            name = trail["Name"]
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if not status.get("IsLogging", False):
                findings.append({
                    "resource": f"CloudTrail: {name}",
                    "severity": "HIGH",
                    "issue": "CloudTrail exists but logging is disabled",
                    "recommendation": "Enable logging on this trail immediately."
                })
            else:
                findings.append({
                    "resource": f"CloudTrail: {name}",
                    "severity": "PASS",
                    "issue": "Logging is active",
                    "recommendation": ""
                })

    except ClientError as e:
        findings.append({
            "resource": "CloudTrail",
            "severity": "HIGH",
            "issue": f"Could not check CloudTrail: {str(e)}",
            "recommendation": "Ensure CloudTrail is configured and accessible."
        })

    return findings


def run_all_checks():
    return {
        "s3":             check_s3_buckets(),
        "iam":            check_iam_users(),
        "security_groups": check_security_groups(),
        "cloudtrail":     check_cloudtrail(),
    }
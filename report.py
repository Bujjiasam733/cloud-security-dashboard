import json
import os
from datetime import datetime
from utils import colorize, severity_color, BOLD, CYAN, RESET

def print_banner():
    print(f"""
{CYAN}{BOLD}
  Cloud Security Posture Dashboard v1.0
  github.com/Bujjiasam733
{RESET}""")

def score_color(score):
    if score >= 80:
        return "\033[92m"
    elif score >= 50:
        return "\033[93m"
    return "\033[91m"

def print_results(data):
    if "error" in data:
        print(colorize(f"\n  Error: {data['error']}", "\033[91m"))
        return

    summary = data["summary"]
    results = data["results"]
    score = summary["risk_score"]

    print(f"\n{BOLD}  Scan Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"\n  {BOLD}Risk Score  : {colorize(str(score) + ' / 100', score_color(score))}{RESET}")
    print(f"  {colorize('HIGH: ' + str(summary['high']), severity_color('HIGH'))}  |  "
          f"{colorize('MEDIUM: ' + str(summary['medium']), severity_color('MEDIUM'))}  |  "
          f"{colorize('LOW: ' + str(summary['low']), severity_color('LOW'))}  |  "
          f"{colorize('PASSED: ' + str(summary['passed']), severity_color('PASS'))}")

    sections = {
        "s3":              "S3 Buckets",
        "iam":             "IAM Users",
        "security_groups": "Security Groups",
        "cloudtrail":      "CloudTrail",
    }

    for key, title in sections.items():
        checks = results.get(key, [])
        print(f"\n{BOLD}  {title}{RESET}")
        print(f"  {'-'*60}")
        for item in checks:
            if "error" in item:
                print(colorize(f"  Error: {item['error']}", severity_color("HIGH")))
                continue
            sev = item.get("severity", "INFO")
            color = severity_color(sev)
            marker = "✓" if sev == "PASS" else "!"
            print(f"  {colorize(marker + ' ' + sev, color):<20} {item['resource']}")
            print(f"  {'':20} {item['issue']}")
            if item.get("recommendation"):
                print(f"  {'':20} Fix: {item['recommendation']}")

    print(f"\n{BOLD}  Summary{RESET}")
    print(f"  {'-'*40}")
    if summary["high"] > 0:
        print(colorize(f"\n  {summary['high']} critical issue(s) require immediate attention.", severity_color("HIGH")))
    if summary["medium"] > 0:
        print(colorize(f"  {summary['medium']} medium risk issue(s) should be reviewed.", severity_color("MEDIUM")))
    if summary["high"] == 0 and summary["medium"] == 0:
        print(colorize("\n  No critical issues detected.", severity_color("PASS")))

def save_report(data, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/cloud_audit_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n  Report saved: {filename}")
    return filename
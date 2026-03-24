from checkers import run_all_checks

def calculate_risk_score(results):
    score = 100
    deductions = {"HIGH": 15, "MEDIUM": 7, "LOW": 3}
    for checks in results.values():
        for item in checks:
            score -= deductions.get(item.get("severity", ""), 0)
    return max(0, score)

def scan_account():
    results = run_all_checks()
    score = calculate_risk_score(results)

    total = sum(len(v) for v in results.values())
    high   = sum(1 for v in results.values() for i in v if i.get("severity") == "HIGH")
    medium = sum(1 for v in results.values() for i in v if i.get("severity") == "MEDIUM")
    low    = sum(1 for v in results.values() for i in v if i.get("severity") == "LOW")
    passed = sum(1 for v in results.values() for i in v if i.get("severity") == "PASS")

    return {
        "results": results,
        "summary": {
            "risk_score": score,
            "total_checks": total,
            "high": high,
            "medium": medium,
            "low": low,
            "passed": passed,
        }
    }
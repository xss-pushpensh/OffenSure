"""Exploitability scoring engine."""
EXPOSURE_WEIGHT = {"internet": 1.0, "internal": 0.7, "localhost": 0.3, "unknown": 0.5}

def compute_score(crash: dict, reach: dict, exposure: str = "unknown") -> dict:
    cvss = crash.get("cvss", 0.0)
    static_reach = reach.get("static", False)
    runtime_reach = reach.get("runtime", False)
    exp_w = EXPOSURE_WEIGHT.get(exposure, 0.5)

    base = cvss * 10
    if static_reach: base += 10
    if runtime_reach: base += 20
    else: base -= 15
    base *= exp_w
    score = max(0.0, min(100.0, base))

    if score >= 80: tier = "P0"
    elif score >= 60: tier = "P1"
    elif score >= 35: tier = "P2"
    else: tier = "P3"

    return {
        "score": round(score, 2), "tier": tier, "cvss": cvss,
        "static_reachable": static_reach, "runtime_reachable": runtime_reach,
        "exposure": exposure, "cwe": crash.get("cwe"), "type": crash.get("type"),
    }

def score_all(triage_results: list, reach_map: dict, exposure: str = "unknown") -> list:
    out = []
    for c in triage_results:
        cwe = c.get("cwe", "CWE-000")
        reach = reach_map.get(cwe, {"static": False, "runtime": False})
        out.append({"crash": c, "score": compute_score(c, reach, exposure)})
    return out

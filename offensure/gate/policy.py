"""Policy engine. Loads YAML and evaluates findings."""
import yaml
from pathlib import Path

def load_policy(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text())

def evaluate(findings: list, policy: dict) -> dict:
    fail_tiers = set(policy.get("fail_on_tiers", []))
    warn_tiers = set(policy.get("warn_on_tiers", []))
    failures = [f for f in findings if f["score"]["tier"] in fail_tiers]
    warnings = [f for f in findings if f["score"]["tier"] in warn_tiers]
    return {"pass": len(failures) == 0, "failures": failures, "warnings": warnings, "total": len(findings)}

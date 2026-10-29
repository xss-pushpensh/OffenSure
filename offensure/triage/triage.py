"""Crash triage. Parses ASAN output, classifies crash, maps to CWE."""
import re, subprocess
from pathlib import Path

CRASH_PATTERNS = [
    (r"stack-buffer-overflow", "Stack Buffer Overflow", "CWE-121", "Critical", 9.8),
    (r"heap-buffer-overflow",  "Heap Buffer Overflow",  "CWE-122", "Critical", 9.8),
    (r"use-after-free",        "Use After Free",        "CWE-416", "Critical", 9.8),
    (r"double-free",           "Double Free",           "CWE-415", "High",     8.8),
    (r"integer-overflow",      "Integer Overflow",      "CWE-190", "High",     8.1),
    (r"null-dereference",      "Null Pointer Deref",    "CWE-476", "Medium",   5.5),
    (r"SEGV",                  "Segmentation Fault",    "CWE-476", "Medium",   5.5),
    (r"timeout",               "Timeout",               "CWE-400", "Low",      3.1),
    (r"out-of-memory",         "OOM",                   "CWE-400", "Low",      3.1),
]

def classify_asan_output(text: str) -> dict:
    for pattern, name, cwe, severity, cvss in CRASH_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {"type": name, "cwe": cwe, "severity": severity, "cvss": cvss, "raw": pattern}
    return {"type": "Unknown", "cwe": "CWE-000", "severity": "Info", "cvss": 0.0, "raw": None}

def triage_crash(binary: str, crash_file: str, timeout: int = 20) -> dict:
    try:
        r = subprocess.run([binary, crash_file], capture_output=True, text=True, timeout=timeout)
        output = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return {"crash_file": crash_file, "type": "Timeout", "cwe": "CWE-400",
                "severity": "Low", "cvss": 3.1, "output": "timeout"}

    info = classify_asan_output(output)
    info["crash_file"] = crash_file
    info["output"] = output[-4000:]
    return info

def triage_all(binary: str, artifact_dir: str) -> list:
    out = []
    for crash in sorted(Path(artifact_dir).glob("crash-*")):
        out.append(triage_crash(binary, str(crash)))
    for crash in sorted(Path(artifact_dir).glob("leak-*")):
        out.append(triage_crash(binary, str(crash)))
    return out

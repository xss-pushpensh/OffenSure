"""eBPF runtime reachability using uprobes via bpftrace."""
import subprocess, time
from pathlib import Path

BPFTRACE_TEMPLATE = """
uprobe:{binary}:{func}
{{
    printf("REACHED %s\\n", "{func}");
}}
"""

def check_reachability_bpftrace(binary: str, func: str, duration: int = 10):
    script = BPFTRACE_TEMPLATE.format(binary=binary, func=func)
    script_file = Path("/tmp/offensure_reach.bt")
    script_file.write_text(script)

    proc = subprocess.Popen(
        ["sudo", "bpftrace", str(script_file)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(duration)
    proc.terminate()
    try:
        out, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()

    return {
        "function": func,
        "binary": binary,
        "reachable": "REACHED" in out,
        "raw_output": out,
        "error": err,
    }

def check_multiple(binary: str, functions: list, duration: int = 5):
    return [check_reachability_bpftrace(binary, f, duration) for f in functions]

"""Static reachability using ELF symbols + objdump call graph."""
import subprocess, re

def list_functions(binary: str) -> list:
    r = subprocess.run(["nm", "-C", "--defined-only", binary], capture_output=True, text=True)
    funcs = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "t"):
            funcs.append(parts[2])
    return funcs

def get_callers(binary: str, func: str) -> list:
    r = subprocess.run(["objdump", "-d", binary], capture_output=True, text=True)
    callers, current = [], None
    for line in r.stdout.splitlines():
        m = re.match(r"^[0-9a-f]+ <(.+)>:", line)
        if m:
            current = m.group(1)
            continue
        if f"<{func}>" in line and "call" in line:
            if current and current not in callers:
                callers.append(current)
    return callers

def is_reachable_from(binary: str, target: str, entry: str, depth: int = 5) -> bool:
    visited, frontier = set(), [entry]
    for _ in range(depth):
        nxt = []
        for f in frontier:
            if f in visited: continue
            visited.add(f)
            if f == target: return True
            nxt.extend(get_callers(binary, f))
        frontier = nxt
        if not frontier: break
    return False

"""Fuzzer runner. Compiles harness, runs libFuzzer, collects crashes."""
import subprocess
from pathlib import Path

def build_libfuzzer_harness(target_dir: str, harness_c: str, out_bin: str) -> bool:
    target = Path(target_dir)
    lib = target / "libexample.a"
    cmd = [
        "clang", "-g", "-O1", "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined,fuzzer",
        "-I", str(target),
        harness_c, str(lib), "-o", out_bin,
    ]
    print("[*] Building harness:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("[!] Build failed")
        print(r.stderr)
        return False
    return True

def run_libfuzzer(binary: str, corpus_dir: str, artifact_dir: str, max_time: int = 60):
    Path(corpus_dir).mkdir(parents=True, exist_ok=True)
    Path(artifact_dir).mkdir(parents=True, exist_ok=True)
    cmd = [binary, f"-max_total_time={max_time}", f"-artifact_prefix={artifact_dir}/", corpus_dir]
    print("[*] Running fuzzer:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def collect_crashes(artifact_dir: str) -> list:
    p = Path(artifact_dir)
    out = []
    for f in p.glob("crash-*"):
        out.append(str(f))
    for f in p.glob("leak-*"):
        out.append(str(f))
    return out

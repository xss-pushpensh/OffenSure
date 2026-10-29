"""OffenSure CLI. End-to-end offensive product security pipeline."""
import typer, json
from pathlib import Path
from rich.console import Console
from rich.table import Table

from offensure.fuzzer.harness_gen import generate_harness
from offensure.fuzzer.runner import build_libfuzzer_harness, run_libfuzzer, collect_crashes
from offensure.triage.triage import triage_all
from offensure.reachability.ebpf_reach import check_reachability_bpftrace
from offensure.scoring.score import score_all
from offensure.patch.patcher import suggest_patch
from offensure.gate.policy import load_policy, evaluate
from offensure.report.generate import render_html, render_json, render_sarif

app = typer.Typer(help="OffenSure — Offensive Product Security Platform")
console = Console()


@app.command()
def fuzz(
    target_dir: str = typer.Option(..., help="Path to target library directory"),
    header: str = typer.Option("example_lib.h", help="Public header name"),
    fuzz_time: int = typer.Option(60, help="Fuzzing duration in seconds"),
    output: str = typer.Option("reports", help="Output directory"),
):
    """Step 1: Generate harness, build, and fuzz."""
    target = Path(target_dir).resolve()
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan][*] Target:[/] {target}")
    info = generate_harness(str(target), header)
    console.print(f"[green][+] Harness:[/] {info['libfuzzer']}")

    binary = out / "fuzz_libfuzzer"
    if not build_libfuzzer_harness(str(target), info["libfuzzer"], str(binary)):
        raise typer.Exit(1)
    console.print(f"[green][+] Binary:[/] {binary}")

    corpus = out / "corpus"
    artifacts = out / "artifacts"
    run_libfuzzer(str(binary), str(corpus), str(artifacts), fuzz_time)
    crashes = collect_crashes(str(artifacts))
    console.print(f"[yellow][!] Crashes:[/] {len(crashes)}")
    for c in crashes:
        console.print(f"    - {Path(c).name}")

    (out / "crashes.txt").write_text("\n".join(crashes))
    console.print(f"[green][+] Crash list:[/] {out/'crashes.txt'}")


@app.command()
def triage(
    binary: str = typer.Option(..., help="Path to fuzz binary"),
    artifacts: str = typer.Option(..., help="Artifacts directory with crash files"),
    output: str = typer.Option("reports", help="Output directory"),
):
    """Step 2: Triage crashes."""
    results = triage_all(binary, artifacts)
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "triage.json").write_text(json.dumps(results, indent=2, default=str))

    table = Table(title="Triage Results")
    for col in ["File", "Type", "CWE", "Severity", "CVSS"]:
        table.add_column(col)
    for r in results:
        table.add_row(Path(r["crash_file"]).name, r["type"], r["cwe"], r["severity"], str(r["cvss"]))
    console.print(table)
    console.print(f"[green][+] Saved:[/] {out/'triage.json'}")


@app.command()
def reach(
    binary: str = typer.Option(..., help="Path to binary"),
    function: str = typer.Option(..., help="Function name to check"),
    duration: int = typer.Option(5, help="Seconds to attach uprobe"),
):
    """Step 3: Check runtime reachability of a function via eBPF uprobe."""
    console.print(f"[cyan][*] Checking reachability:[/] {function}")
    r = check_reachability_bpftrace(binary, function, duration)
    if r["reachable"]:
        console.print(f"[bold red][!] REACHABLE:[/] {function} was called at runtime")
    else:
        console.print(f"[green][+] Not reached during {duration}s window[/]")


@app.command()
def score(
    triage_json: str = typer.Option(..., help="Path to triage.json"),
    binary: str = typer.Option(..., help="Binary for reachability"),
    policy_file: str = typer.Option("policies/default.yaml"),
    output: str = typer.Option("reports"),
):
    """Step 4: Score findings and generate report."""
    triage_data = json.loads(Path(triage_json).read_text())
    policy = load_policy(policy_file)
    exposure = policy.get("exposure", "unknown")

    reach_map = {}
    for c in triage_data:
        reach_map[c["cwe"]] = {"static": True, "runtime": False}

    findings = score_all(triage_data, reach_map, exposure)
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)

    html_path = render_html(findings, str(out / "report.html"))
    json_path = render_json(findings, str(out / "report.json"))
    sarif_path = render_sarif(findings, str(out / "report.sarif"))

    result = evaluate(findings, policy)
    console.print(f"[bold]Policy result:[/] {'PASS' if result['pass'] else 'FAIL'}")
    console.print(f"[green][+] HTML:[/]  {html_path}")
    console.print(f"[green][+] JSON:[/]  {json_path}")
    console.print(f"[green][+] SARIF:[/] {sarif_path}")

    if not result["pass"]:
        raise typer.Exit(2)


@app.command()
def patch(cwe: str = typer.Option(..., help="CWE to patch")):
    """Step 5: Get auto-patch suggestion."""
    p = suggest_patch(cwe)
    console.print(f"[bold cyan]CWE:[/] {cwe}")
    console.print(f"[bold]Available:[/] {p['available']}")
    console.print(f"[bold]Description:[/] {p['description']}")
    if p["available"]:
        console.print("[bold]Suggested diff:[/]")
        console.print(p["diff"])


@app.command()
def pipeline(
    target_dir: str = typer.Option(...),
    header: str = typer.Option("example_lib.h"),
    fuzz_time: int = typer.Option(60),
    output: str = typer.Option("reports"),
    policy_file: str = typer.Option("policies/default.yaml"),
):
    """End-to-end pipeline: fuzz -> triage -> score -> report -> gate."""
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)

    console.rule("[bold cyan]1. FUZZ")
    fuzz(target_dir, header, fuzz_time, output)

    console.rule("[bold cyan]2. TRIAGE")
    binary = out / "fuzz_libfuzzer"
    artifacts = out / "artifacts"
    triage(str(binary), str(artifacts), output)

    console.rule("[bold cyan]3. SCORE + REPORT + GATE")
    try:
        score(str(out / "triage.json"), str(binary), policy_file, output)
    except typer.Exit as e:
        if e.exit_code == 2:
            console.print("[bold red][!] Pipeline gate failed: P0/P1 findings present[/]")
        raise


if __name__ == "__main__":
    app()

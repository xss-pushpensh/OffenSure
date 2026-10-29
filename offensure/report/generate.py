"""Report generator: HTML, JSON, SARIF."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
import json

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

def render_html(findings: list, out_path: str):
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    html = env.get_template("report.html.j2").render(findings=findings)
    Path(out_path).write_text(html)
    return out_path

def render_json(findings: list, out_path: str):
    Path(out_path).write_text(json.dumps(findings, indent=2, default=str))
    return out_path

def render_sarif(findings: list, out_path: str):
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "OffenSure", "version": "0.1.0"}},
            "results": [
                {
                    "ruleId": f["score"]["cwe"],
                    "level": "error" if f["score"]["tier"] in ("P0", "P1") else "warning",
                    "message": {"text": f'{f["score"]["type"]} in {f["crash"]["crash_file"]}'},
                } for f in findings
            ],
        }],
    }
    Path(out_path).write_text(json.dumps(sarif, indent=2))
    return out_path

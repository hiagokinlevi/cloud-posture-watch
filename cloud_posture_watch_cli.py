import argparse
import json
from typing import Any, Dict, List, Optional, Tuple


def _severity_rank(severity: Any) -> int:
    s = str(severity or "").strip().lower()
    order = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
    }
    return order.get(s, 0)


def _priority_key(finding: Dict[str, Any]) -> Tuple[int, float]:
    # Higher severity/value means higher priority (kept first)
    sev = _severity_rank(finding.get("severity"))
    score = finding.get("risk_score")
    try:
        score_val = float(score) if score is not None else 0.0
    except Exception:
        score_val = 0.0
    return sev, score_val


def apply_max_findings_cap(
    findings: List[Dict[str, Any]], max_findings: Optional[int]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    metadata: Dict[str, Any] = {}
    if max_findings is None:
        return findings, metadata

    if max_findings < 0:
        raise ValueError("--max-findings must be >= 0")

    original_count = len(findings)
    if original_count <= max_findings:
        return findings, metadata

    indexed = list(enumerate(findings))
    indexed.sort(key=lambda x: (_priority_key(x[1])[0], _priority_key(x[1])[1], x[0]), reverse=True)
    kept = [item for _, item in indexed[:max_findings]]

    metadata["truncated"] = True
    metadata["original_count"] = original_count
    metadata["emitted_count"] = len(kept)
    return kept, metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-posture-watch")
    parser.add_argument("--format", choices=["console", "json", "markdown"], default="console")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Cap the number of emitted findings in output (lowest-priority findings truncated first).",
    )
    return parser


def assemble_report(findings: List[Dict[str, Any]], max_findings: Optional[int]) -> Dict[str, Any]:
    capped_findings, trunc_meta = apply_max_findings_cap(findings, max_findings)
    report: Dict[str, Any] = {
        "findings": capped_findings,
        "count": len(capped_findings),
    }
    report.update(trunc_meta)
    return report


def render_console(report: Dict[str, Any]) -> str:
    lines = [f"Findings: {report.get('count', 0)}"]
    if report.get("truncated"):
        lines.append(
            f"Output truncated: true (original_count={report.get('original_count')}, emitted_count={report.get('emitted_count')})"
        )
    for f in report.get("findings", []):
        lines.append(f"- [{f.get('severity', 'unknown')}] {f.get('title', 'untitled')}")
    return "\n".join(lines)


def render_markdown(report: Dict[str, Any]) -> str:
    out = [f"# Cloud Posture Watch Report", "", f"**Findings:** {report.get('count', 0)}", ""]
    if report.get("truncated"):
        out.extend(
            [
                "**truncated:** true",
                f"**original_count:** {report.get('original_count')}",
                f"**emitted_count:** {report.get('emitted_count')}",
                "",
            ]
        )
    for f in report.get("findings", []):
        out.append(f"- **{f.get('severity', 'unknown').upper()}**: {f.get('title', 'untitled')}")
    return "\n".join(out)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Placeholder findings source; analyzers remain unchanged.
    findings: List[Dict[str, Any]] = []

    report = assemble_report(findings, args.max_findings)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "markdown":
        print(render_markdown(report))
    else:
        print(render_console(report))


if __name__ == "__main__":
    main()

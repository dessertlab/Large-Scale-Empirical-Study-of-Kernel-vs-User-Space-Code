"""Unified report generation."""

from __future__ import annotations

import json
from pathlib import Path

from static_analysis.models import Finding, ToolName, ToolRunResult


def write_report(
    results: dict[ToolName, ToolRunResult],
    *,
    report_path: Path,
) -> Path:
    """Write the unified JSON report and return its path."""

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report_payload(results), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_path


def merge_report(
    results: dict[ToolName, ToolRunResult],
    *,
    report_path: Path,
) -> Path:
    """Merge freshly-run tools into an existing report, preserving the rest.

    Entries (and findings) for the tools present in ``results`` replace the
    matching entries in the existing report; all other tools are kept as-is.
    Falls back to :func:`write_report` when no prior report exists.
    """

    if not report_path.exists():
        return write_report(results, report_path=report_path)

    existing = json.loads(report_path.read_text(encoding="utf-8"))
    fresh = report_payload(results)
    rerun = set(results)

    kept_tools = [t for t in existing.get("tools", []) if t["tool"] not in rerun]
    kept_findings = [f for f in existing.get("findings", []) if f["tool"] not in rerun]

    tools = sorted(kept_tools + fresh["tools"], key=lambda t: t["tool"])
    findings = sorted(
        kept_findings + fresh["findings"],
        key=lambda f: (
            f["filename"],
            f["line"] if f["line"] is not None else -1,
            f["tool"],
            f["rule"] or "",
        ),
    )
    payload = {
        "summary": {
            "tools": len(tools),
            "completed": sum(1 for t in tools if t["status"] == "completed"),
            "failed": sum(1 for t in tools if t["status"] == "failed"),
            "timeout": sum(1 for t in tools if t["status"] == "timeout"),
            "unavailable": sum(1 for t in tools if t["status"] == "unavailable"),
            "findings": len(findings),
        },
        "tools": tools,
        "findings": findings,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_path


def report_payload(results: dict[ToolName, ToolRunResult]) -> dict[str, object]:
    """Build a deterministic JSON-serializable report payload."""

    ordered_results = [results[name] for name in sorted(results)]
    findings = sorted(
        (finding for result in ordered_results for finding in result.findings),
        key=_finding_sort_key,
    )
    return {
        "summary": {
            "tools": len(ordered_results),
            "completed": sum(1 for result in ordered_results if result.status == "completed"),
            "failed": sum(1 for result in ordered_results if result.status == "failed"),
            "timeout": sum(1 for result in ordered_results if result.status == "timeout"),
            "unavailable": sum(1 for result in ordered_results if result.status == "unavailable"),
            "findings": len(findings),
        },
        "tools": [_tool_payload(result) for result in ordered_results],
        "findings": [_finding_payload(finding) for finding in findings],
    }


def _tool_payload(result: ToolRunResult) -> dict[str, object]:
    return {
        "tool": result.tool,
        "status": result.status,
        "exit_code": result.exit_code,
        "findings": len(result.findings),
        "raw_output": str(result.raw_output_path) if result.raw_output_path else None,
        "stderr": str(result.stderr_path) if result.stderr_path else None,
        "message": result.message,
    }


def _finding_payload(finding: Finding) -> dict[str, object]:
    return {
        "tool": finding.tool,
        "filename": finding.filename,
        "line": finding.line,
        "cwe": finding.cwe,
        "rule": finding.rule,
        "message": finding.message,
    }


def _finding_sort_key(finding: Finding) -> tuple[str, int, str, str]:
    line = finding.line if finding.line is not None else -1
    rule = finding.rule or ""
    return finding.filename, line, finding.tool, rule

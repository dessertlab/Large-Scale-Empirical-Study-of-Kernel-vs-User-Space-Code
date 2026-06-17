#!/usr/bin/env python3
"""Print per-class analyzer finding count tables from outputs/."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


CLASS_ORDER = ("kernel", "application")
TOOL_ORDER = ("codeql", "cppcheck", "flawfinder", "semgrep", "ikos")
RED = "\033[31m"
RESET = "\033[0m"
ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def main() -> int:
    args = parse_args()
    outputs_dir = args.outputs

    if not outputs_dir.is_dir():
        print(f"outputs directory not found: {outputs_dir}", file=sys.stderr)
        return 1

    use_color = should_color(args.color)
    classes = requested_classes(outputs_dir, args.classes)
    if not classes:
        print(f"no class directories found under {outputs_dir}", file=sys.stderr)
        return 1

    for index, class_name in enumerate(classes):
        if index:
            print()
        print_class_table(outputs_dir / class_name, class_name, use_color)

    totals = total_findings_per_tool(outputs_dir, classes)
    write_tool_totals(args.tools_out, totals)
    print(f"\ntotal findings per tool written to {args.tools_out}")

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Print finding count tables from outputs/<class>/<project>/report.json."
    )
    parser.add_argument(
        "--outputs",
        type=Path,
        default=Path("outputs"),
        help="outputs directory to read (default: outputs)",
    )
    parser.add_argument(
        "--class",
        dest="classes",
        action="append",
        help="class to print; can be passed more than once (default: kernel and application)",
    )
    parser.add_argument(
        "--color",
        choices=("always", "auto", "never"),
        default="always",
        help="when to color NULL cells red (default: always)",
    )
    parser.add_argument(
        "--tools-out",
        type=Path,
        default=Path("experiments/txt/tools.txt"),
        help="path for the per-tool total findings file (default: experiments/txt/tools.txt)",
    )
    return parser.parse_args()


def should_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty()


def requested_classes(outputs_dir: Path, classes: list[str] | None) -> list[str]:
    if classes:
        return classes

    existing = [path.name for path in outputs_dir.iterdir() if path.is_dir()]
    ordered = [name for name in CLASS_ORDER if name in existing]
    ordered.extend(sorted(set(existing) - set(ordered), key=str.casefold))
    return ordered


def print_class_table(class_dir: Path, class_name: str, use_color: bool) -> None:
    projects = sorted(
        (path for path in class_dir.iterdir() if path.is_dir()),
        key=lambda path: path.name.casefold(),
    )
    reports = {project.name: load_report(project / "report.json") for project in projects}
    tools = class_tools(reports.values())

    header = ["project", *tools]
    rows = [
        [project.name, *project_cells(reports[project.name], tools, use_color)]
        for project in projects
    ]

    print(class_name)
    print(format_table(header, rows))


def total_findings_per_tool(outputs_dir: Path, classes: list[str]) -> dict[str, int]:
    """Sum findings per tool across every project of every class.

    Only completed runs contribute (mirroring the NULL cells in the tables: a
    tool that failed/timed out on a project reports no trustworthy count, so it
    is not added in). Tools are keyed by name so the same analyzer aggregates
    across both kernel and application.
    """
    totals: dict[str, int] = {}
    for class_name in classes:
        class_dir = outputs_dir / class_name
        if not class_dir.is_dir():
            continue
        for project in sorted(class_dir.iterdir(), key=lambda path: path.name.casefold()):
            if not project.is_dir():
                continue
            report = load_report(project / "report.json")
            if not report:
                continue
            for tool in report.get("tools", []):
                if not isinstance(tool, dict):
                    continue
                name = tool.get("tool")
                if not isinstance(name, str) or tool.get("status") != "completed":
                    continue
                count = tool.get("findings", 0)
                totals[name] = totals.get(name, 0) + (count if isinstance(count, int) else 0)
    return totals


def write_tool_totals(path: Path, totals: dict[str, int]) -> None:
    ordered = sorted(
        totals,
        key=lambda tool: (
            TOOL_ORDER.index(tool) if tool in TOOL_ORDER else len(TOOL_ORDER),
            tool.casefold(),
        ),
    )
    rows = [[tool, str(totals[tool])] for tool in ordered]
    rows.append(["TOTAL", str(sum(totals.values()))])
    path.parent.mkdir(parents=True, exist_ok=True)
    # Plain (uncolored) table so the file stays grep/diff-friendly.
    path.write_text(format_table(["tool", "findings"], rows) + "\n", encoding="utf-8")


def load_report(report_path: Path) -> dict[str, Any] | None:
    if not report_path.is_file():
        return None
    try:
        with report_path.open(encoding="utf-8") as report_file:
            return json.load(report_file)
    except (OSError, json.JSONDecodeError):
        return None


def class_tools(reports: Any) -> list[str]:
    found: set[str] = set()
    for report in reports:
        if not report:
            continue
        for tool in report.get("tools", []):
            tool_name = tool.get("tool")
            if isinstance(tool_name, str):
                found.add(tool_name)

    return sorted(
        found,
        key=lambda tool: (
            TOOL_ORDER.index(tool) if tool in TOOL_ORDER else len(TOOL_ORDER),
            tool.casefold(),
        ),
    )


def project_cells(report: dict[str, Any] | None, tools: list[str], use_color: bool) -> list[str]:
    if not report:
        return [null_cell(use_color) for _ in tools]

    by_tool = {
        tool["tool"]: tool
        for tool in report.get("tools", [])
        if isinstance(tool, dict) and isinstance(tool.get("tool"), str)
    }

    cells: list[str] = []
    for tool in tools:
        result = by_tool.get(tool)
        if not result or result.get("status") != "completed":
            cells.append(null_cell(use_color))
        else:
            cells.append(str(result.get("findings", 0)))
    return cells


def null_cell(use_color: bool) -> str:
    if use_color:
        return f"{RED}NULL{RESET}"
    return "NULL"


def format_table(header: list[str], rows: list[list[str]]) -> str:
    widths = [
        max(visible_len(row[column]) for row in [header, *rows])
        for column in range(len(header))
    ]

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    lines = [
        separator,
        table_row(header, widths),
        separator,
        *(table_row(row, widths) for row in rows),
        separator,
    ]
    return "\n".join(lines)


def table_row(row: list[str], widths: list[int]) -> str:
    cells = [
        f" {cell}{' ' * (width - visible_len(cell))} "
        for cell, width in zip(row, widths, strict=True)
    ]
    return "|" + "|".join(cells) + "|"


def visible_len(value: str) -> int:
    return len(ANSI_RE.sub("", value))


if __name__ == "__main__":
    raise SystemExit(main())

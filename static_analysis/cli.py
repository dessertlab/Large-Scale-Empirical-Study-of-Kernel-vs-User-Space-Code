"""Command-line entrypoint."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path

from static_analysis.config import SUPPORTED_TOOLS, load_config
from static_analysis.docker_executor import install_interrupt_handlers
from static_analysis.models import PipelineConfig, ToolName
from static_analysis.pipeline import run_enabled_tools
from static_analysis.progress import ConsoleReporter, NullReporter
from static_analysis.report import merge_report, write_report


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return _run(args)
    parser.print_help()
    return 2


def _run(args: argparse.Namespace) -> int:
    install_interrupt_handlers()
    project_root = Path(args.project_root).resolve()
    if not project_root.exists() or not project_root.is_dir():
        raise SystemExit(f"Project root does not exist or is not a directory: {project_root}")

    config = load_config(args.config)
    if args.tool:
        config = _select_tools(config, tuple(args.tool))
    config = _apply_codeql_overrides(
        config,
        ram=args.codeql_ram,
        threads=args.codeql_threads,
    )

    output_root = Path(args.output).resolve()
    reporter = (
        NullReporter()
        if args.quiet
        else ConsoleReporter(verbose=args.verbose, show_command=args.show_command)
    )
    results = run_enabled_tools(
        config,
        project_root=project_root,
        output_root=output_root,
        docker_executable=args.docker,
        reporter=reporter,
    )
    report_path = output_root / "report.json"
    if args.merge:
        report_path = merge_report(results, report_path=report_path)
    else:
        report_path = write_report(results, report_path=report_path)
    reporter.report_written(report_path)

    failed = [result for result in results.values() if result.status != "completed"]
    return 1 if failed else 0


def _apply_codeql_overrides(
    config: PipelineConfig,
    *,
    ram: int | None,
    threads: int | None,
) -> PipelineConfig:
    """Override CodeQL's ram/threads options from the command line.

    Used by run.sh to scale CodeQL down when several projects are analyzed in
    parallel, without editing config.toml.
    """

    if ram is None and threads is None:
        return config
    codeql = config.tools.get("codeql")
    if codeql is None:
        return config
    options = dict(codeql.options)
    if ram is not None:
        options["ram"] = ram
    if threads is not None:
        options["threads"] = threads
    tools = dict(config.tools)
    tools["codeql"] = replace(codeql, options=options)
    return replace(config, tools=tools)


def _select_tools(config: PipelineConfig, selected_tools: tuple[ToolName, ...]) -> PipelineConfig:
    selected = set(selected_tools)
    tools = {
        name: replace(tool, enabled=name in selected)
        for name, tool in config.tools.items()
    }
    return replace(config, tools=tools)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="static-analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run analyzers on a C/C++ project")
    run_parser.add_argument("project_root", help="project root to analyze")
    run_parser.add_argument("--config", default="config.toml", help="path to config.toml")
    run_parser.add_argument("--output", default="outputs/run", help="output directory")
    run_parser.add_argument("--docker", default="docker", help="docker executable")
    run_parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    run_parser.add_argument("--verbose", action="store_true", help="show detailed progress")
    run_parser.add_argument(
        "--show-command",
        action="store_true",
        help="print each docker command before execution",
    )
    run_parser.add_argument(
        "--tool",
        action="append",
        choices=SUPPORTED_TOOLS,
        help="run only this tool; may be provided more than once",
    )
    run_parser.add_argument(
        "--merge",
        action="store_true",
        help="merge results into an existing report.json instead of overwriting it "
        "(keeps tools that were not re-run)",
    )
    run_parser.add_argument(
        "--codeql-ram",
        type=int,
        default=None,
        help="override CodeQL's RAM budget (MB); useful when running projects in parallel",
    )
    run_parser.add_argument(
        "--codeql-threads",
        type=int,
        default=None,
        help="override CodeQL's thread count; useful when running projects in parallel",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main())

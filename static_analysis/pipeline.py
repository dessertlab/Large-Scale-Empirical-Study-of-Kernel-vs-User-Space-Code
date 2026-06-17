"""High-level pipeline orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from static_analysis.runners import create_runner
from static_analysis.models import PipelineConfig, ToolConfig, ToolName, ToolRunResult
from static_analysis.progress import NullReporter, ProgressReporter


def run_enabled_tools(
    config: PipelineConfig,
    *,
    project_root: Path,
    output_root: Path | None = None,
    docker_executable: str = "docker",
    reporter: ProgressReporter | None = None,
) -> dict[ToolName, ToolRunResult]:
    """Run configured tool runners in parallel."""

    root = output_root if output_root is not None else config.output.directory
    root.mkdir(parents=True, exist_ok=True)
    enabled_tools = [tool for tool in config.tools.values() if tool.enabled]
    progress = reporter if reporter is not None else NullReporter()
    tool_names = tuple(tool.name for tool in enabled_tools)
    progress.pipeline_started(
        project_root=project_root,
        output_root=root,
        tools=tool_names,
    )
    if not enabled_tools:
        progress.pipeline_finished({})
        return {}

    if config.pipeline.fail_fast:
        for tool in enabled_tools:
            progress.tool_queued(tool.name)
        results: dict[ToolName, ToolRunResult] = {}
        for tool in enabled_tools:
            result = _run_tool(
                tool,
                project_root=project_root,
                output_root=root,
                docker_executable=docker_executable,
                reporter=progress,
            )
            results[tool.name] = result
            progress.tool_finished(
                result,
                completed=len(results),
                total=len(enabled_tools),
            )
            if result.status == "failed":
                break
        progress.pipeline_finished(results)
        return results

    results: dict[ToolName, ToolRunResult] = {}
    with ThreadPoolExecutor(max_workers=config.pipeline.max_parallel_tools) as executor:
        for tool in enabled_tools:
            progress.tool_queued(tool.name)
        futures = {
            executor.submit(
                _run_tool,
                tool,
                project_root=project_root,
                output_root=root,
                docker_executable=docker_executable,
                reporter=progress,
            ): tool.name
            for tool in enabled_tools
        }
        for future in as_completed(futures):
            name = futures[future]
            result = future.result()
            results[name] = result
            progress.tool_finished(
                result,
                completed=len(results),
                total=len(enabled_tools),
            )
    progress.pipeline_finished(results)
    return results


def _run_tool(
    tool: ToolConfig,
    *,
    project_root: Path,
    output_root: Path,
    docker_executable: str,
    reporter: ProgressReporter,
) -> ToolRunResult:
    try:
        return create_runner(
            tool,
            docker_executable=docker_executable,
            reporter=reporter,
        ).execute(
            project_root=project_root,
            output_root=output_root,
        )
    except Exception as exc:
        return ToolRunResult(tool=tool.name, status="failed", message=str(exc))

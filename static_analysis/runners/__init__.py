"""Tool runner registry."""

from __future__ import annotations

from static_analysis.runners.base import ToolRunner
from static_analysis.runners.codeql import CodeqlRunner
from static_analysis.runners.cppcheck import CppcheckRunner
from static_analysis.runners.flawfinder import FlawfinderRunner
from static_analysis.runners.ikos import IkosRunner
from static_analysis.runners.semgrep import SemgrepRunner
from static_analysis.models import ToolConfig, ToolName
from static_analysis.progress import ProgressReporter


RUNNER_CLASSES: dict[ToolName, type[ToolRunner]] = {
    "cppcheck": CppcheckRunner,
    "semgrep": SemgrepRunner,
    "codeql": CodeqlRunner,
    "flawfinder": FlawfinderRunner,
    "ikos": IkosRunner,
}
TOOL_NAMES = tuple(RUNNER_CLASSES)


def create_runner(
    config: ToolConfig,
    *,
    docker_executable: str = "docker",
    reporter: ProgressReporter | None = None,
) -> ToolRunner:
    return RUNNER_CLASSES[config.name](
        config,
        docker_executable=docker_executable,
        reporter=reporter,
    )


__all__ = ["RUNNER_CLASSES", "TOOL_NAMES", "ToolRunner", "create_runner"]

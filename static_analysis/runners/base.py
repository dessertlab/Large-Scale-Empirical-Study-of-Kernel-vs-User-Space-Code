"""Common runner lifecycle primitives."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path

from static_analysis.docker_executor import docker_run_command, execute_command
from static_analysis.models import Finding, ToolConfig, ToolRunResult
from static_analysis.progress import NullReporter, ProgressReporter, heartbeat


_CWE_PATTERN = re.compile(r"\bCWE[-_ ]?(\d+)\b", re.IGNORECASE)


@dataclass(frozen=True)
class RunnerContext:
    project_root: Path
    output_root: Path
    tool_output_dir: Path
    stdout_path: Path
    stderr_path: Path


class ToolRunner:
    """Base lifecycle for one configured analyzer."""

    def __init__(
        self,
        config: ToolConfig,
        *,
        docker_executable: str = "docker",
        reporter: ProgressReporter | None = None,
    ) -> None:
        self.config = config
        self.docker_executable = docker_executable
        self.reporter = reporter if reporter is not None else NullReporter()

    def setup(self, *, project_root: Path, output_root: Path) -> RunnerContext:
        tool_output_dir = output_root / self.config.name
        return RunnerContext(
            project_root=project_root,
            output_root=output_root,
            tool_output_dir=tool_output_dir,
            stdout_path=tool_output_dir / f"stdout.{self.config.output_format}",
            stderr_path=tool_output_dir / "stderr.txt",
        )

    def docker_command(self, context: RunnerContext) -> list[str]:
        return docker_run_command(
            image=self.config.image,
            command=self.config.command,
            args=self.config.args,
            project_root=context.project_root,
            project_mount=self.config.container_workdir,
            output_dir=context.tool_output_dir,
            workdir=self.config.container_workdir,
            environment=self.config.environment,
            platform=self.config.platform,
            docker_executable=self.docker_executable,
        )

    def run(self, context: RunnerContext) -> ToolRunResult:
        command = self.docker_command(context)
        self.reporter.tool_command(self.config.name, command)
        with heartbeat(
            self.reporter,
            self.config.name,
            timeout_seconds=self.config.timeout_seconds,
        ):
            return execute_command(
                command,
                tool=self.config.name,
                timeout_seconds=self.config.timeout_seconds,
                allowed_exit_codes=self.config.allowed_exit_codes,
                stdout_path=context.stdout_path,
                stderr_path=context.stderr_path,
            )

    def parse(self, raw_output: str) -> tuple[Finding, ...]:
        raise NotImplementedError

    def parse_input_path(self, result: ToolRunResult) -> Path | None:
        return result.raw_output_path

    def execute(self, *, project_root: Path, output_root: Path) -> ToolRunResult:
        self.reporter.tool_phase(self.config.name, "setup")
        context = self.setup(project_root=project_root, output_root=output_root)
        self.reporter.tool_phase(self.config.name, "run")
        result = self.run(context)
        if result.status != "completed" or result.raw_output_path is None:
            return result
        self.reporter.tool_phase(self.config.name, "parse")
        parse_path = self.parse_input_path(result)
        if parse_path is None:
            return result
        findings = self.parse(parse_path.read_text(encoding="utf-8", errors="replace"))
        return replace(result, findings=findings, raw_output_path=parse_path)


def first_cwe(*values: object) -> str | None:
    for value in values:
        for candidate in cwe_candidates(value):
            if candidate:
                return candidate
    return None


def cwe_candidates(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, int) and not isinstance(value, bool):
        return [f"CWE-{value}"]
    if isinstance(value, str):
        if value.isdecimal():
            return [f"CWE-{value}"]
        return [f"CWE-{match.group(1)}" for match in _CWE_PATTERN.finditer(value)]
    if isinstance(value, list):
        candidates: list[str] = []
        for item in value:
            candidates.extend(cwe_candidates(item))
        return candidates
    return []


def as_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def as_string(value: object) -> str:
    return value if isinstance(value, str) else ""


def as_optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def as_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None

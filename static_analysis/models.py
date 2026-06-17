"""Shared data contracts for analyzer execution and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


ToolName = Literal["cppcheck", "semgrep", "codeql", "flawfinder", "ikos"]
RunStatus = Literal["completed", "failed", "skipped", "timeout", "unavailable"]
OutputFormat = Literal["json", "sarif", "xml"]


@dataclass(frozen=True)
class Finding:
    """One normalized vulnerability finding emitted by one configured tool."""

    tool: ToolName
    filename: str
    line: int | None
    cwe: str | None
    rule: str | None
    message: str


@dataclass(frozen=True)
class ToolRunResult:
    """Result envelope for one tool execution."""

    tool: ToolName
    status: RunStatus
    findings: tuple[Finding, ...] = ()
    exit_code: int | None = None
    duration_seconds: float | None = None
    raw_output_path: Path | None = None
    stderr_path: Path | None = None
    message: str | None = None


@dataclass(frozen=True)
class PipelineOptions:
    """Top-level execution knobs."""

    fail_fast: bool = False
    max_parallel_tools: int = 5


@dataclass(frozen=True)
class OutputConfig:
    """Report output settings."""

    directory: Path = Path("outputs")


@dataclass(frozen=True)
class ToolConfig:
    """Container and command configuration for one analyzer."""

    name: ToolName
    enabled: bool
    image: str
    command: str
    output_format: OutputFormat
    args: tuple[str, ...] = ()
    timeout_seconds: int = 900
    allowed_exit_codes: tuple[int, ...] = (0,)
    container_workdir: str = "/workspace"
    report_command: str | None = None
    platform: str | None = None
    environment: dict[str, str] = field(default_factory=dict)
    options: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PipelineConfig:
    """Validated configuration loaded from config.toml."""

    pipeline: PipelineOptions
    output: OutputConfig
    tools: dict[ToolName, ToolConfig]

    @property
    def enabled_tools(self) -> tuple[ToolName, ...]:
        return tuple(name for name, tool in self.tools.items() if tool.enabled)

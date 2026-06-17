"""TOML configuration loading and validation."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, get_args

from static_analysis.models import (
    OutputConfig,
    OutputFormat,
    PipelineConfig,
    PipelineOptions,
    ToolConfig,
    ToolName,
)


SUPPORTED_TOOLS: tuple[ToolName, ...] = (
    "cppcheck",
    "semgrep",
    "codeql",
    "flawfinder",
    "ikos",
)
SUPPORTED_OUTPUT_FORMATS = set(get_args(OutputFormat))


class ConfigError(ValueError):
    """Raised when config.toml is malformed or unsupported."""


def load_config(path: str | Path) -> PipelineConfig:
    """Load and validate the static-analysis TOML configuration."""

    config_path = Path(path)
    with config_path.open("rb") as handle:
        payload = tomllib.load(handle)

    pipeline = _pipeline_options(_table(payload, "pipeline", default={}))
    output = _output_config(_table(payload, "output", default={}))
    tools = _tools_config(_table(payload, "tools"))

    return PipelineConfig(
        pipeline=pipeline,
        output=output,
        tools=tools,
    )


def _pipeline_options(payload: dict[str, Any]) -> PipelineOptions:
    max_parallel_tools = _int(payload, "max_parallel_tools", default=5)
    if max_parallel_tools < 1:
        raise ConfigError("pipeline.max_parallel_tools must be greater than zero")
    return PipelineOptions(
        fail_fast=_bool(payload, "fail_fast", default=False),
        max_parallel_tools=max_parallel_tools,
    )


def _output_config(payload: dict[str, Any]) -> OutputConfig:
    return OutputConfig(
        directory=Path(_str(payload, "directory", default="outputs")),
    )


def _tools_config(payload: dict[str, Any]) -> dict[ToolName, ToolConfig]:
    configured_names = set(payload)
    unknown_names = configured_names.difference(SUPPORTED_TOOLS)
    if unknown_names:
        unknown = ", ".join(sorted(unknown_names))
        raise ConfigError(f"Unsupported tools configured: {unknown}")

    missing = set(SUPPORTED_TOOLS).difference(configured_names)
    if missing:
        missing_names = ", ".join(sorted(missing))
        raise ConfigError(f"Missing required tool configuration: {missing_names}")

    return {
        name: _tool_config(name, _table(payload, name))
        for name in SUPPORTED_TOOLS
    }


def _tool_config(name: ToolName, payload: dict[str, Any]) -> ToolConfig:
    output_format = _str(payload, "output_format", default="text")
    if output_format not in SUPPORTED_OUTPUT_FORMATS:
        raise ConfigError(f"tools.{name}.output_format is not supported: {output_format}")

    return ToolConfig(
        name=name,
        enabled=_bool(payload, "enabled", default=True),
        image=_required_str(payload, "image"),
        command=_required_str(payload, "command"),
        args=tuple(_str_list(payload, "args", default=[])),
        output_format=output_format,
        timeout_seconds=_int(payload, "timeout_seconds", default=900),
        allowed_exit_codes=tuple(_int_list(payload, "allowed_exit_codes", default=[0])),
        container_workdir=_str(payload, "container_workdir", default="/workspace"),
        report_command=_optional_str(payload.get("report_command")),
        platform=_optional_str(payload.get("platform")),
        environment=_str_dict(payload, "environment", default={}),
        options=_object_dict(payload, "options", default={}),
    )


def _table(
    payload: dict[str, Any],
    key: str,
    *,
    default: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = payload.get(key, default)
    if isinstance(value, dict):
        return value
    raise ConfigError(f"Expected [{key}] to be a table")


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if isinstance(value, str) and value:
        return value
    raise ConfigError(f"Expected {key} to be a non-empty string")


def _str(payload: dict[str, Any], key: str, *, default: str) -> str:
    value = payload.get(key, default)
    if isinstance(value, str):
        return value
    raise ConfigError(f"Expected {key} to be a string")


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ConfigError("Expected optional value to be a string")


def _bool(payload: dict[str, Any], key: str, *, default: bool) -> bool:
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value
    raise ConfigError(f"Expected {key} to be a boolean")


def _int(payload: dict[str, Any], key: str, *, default: int) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool):
        raise ConfigError(f"Expected {key} to be an integer")
    if isinstance(value, int):
        return value
    raise ConfigError(f"Expected {key} to be an integer")


def _str_list(
    payload: dict[str, Any],
    key: str,
    *,
    default: list[str],
) -> list[str]:
    value = payload.get(key, default)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ConfigError(f"Expected {key} to be a list of strings")


def _int_list(
    payload: dict[str, Any],
    key: str,
    *,
    default: list[int],
) -> list[int]:
    value = payload.get(key, default)
    if isinstance(value, list) and all(
        isinstance(item, int) and not isinstance(item, bool) for item in value
    ):
        return value
    raise ConfigError(f"Expected {key} to be a list of integers")


def _str_dict(
    payload: dict[str, Any],
    key: str,
    *,
    default: dict[str, str],
) -> dict[str, str]:
    value = payload.get(key, default)
    if isinstance(value, dict) and all(
        isinstance(item_key, str) and isinstance(item_value, str)
        for item_key, item_value in value.items()
    ):
        return dict(value)
    raise ConfigError(f"Expected {key} to be a string-to-string table")


def _object_dict(
    payload: dict[str, Any],
    key: str,
    *,
    default: dict[str, object],
) -> dict[str, object]:
    value = payload.get(key, default)
    if isinstance(value, dict):
        return dict(value)
    raise ConfigError(f"Expected {key} to be a table")

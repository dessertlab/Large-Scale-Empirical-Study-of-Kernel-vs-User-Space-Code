"""Progress reporting for interactive runs."""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, TextIO

from static_analysis.models import ToolRunResult


# How often a long-running tool prints a "still running" heartbeat.
HEARTBEAT_INTERVAL_SECONDS = 300


def format_duration(seconds: float) -> str:
    """Format a (possibly fractional) duration as HH:MM:SS. Clamps negatives to 0."""
    total = int(seconds)
    if total < 0:
        total = 0
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


@dataclass(frozen=True)
class ProgressEvent:
    name: str
    tool: str | None = None
    message: str | None = None


class ProgressReporter:
    """Interface for pipeline progress reporting."""

    def pipeline_started(
        self,
        *,
        project_root: Path,
        output_root: Path,
        tools: tuple[str, ...],
    ) -> None:
        pass

    def tool_queued(self, tool: str) -> None:
        pass

    def tool_phase(self, tool: str, phase: str) -> None:
        pass

    def tool_command(self, tool: str, command: list[str]) -> None:
        pass

    def tool_heartbeat(
        self,
        tool: str,
        *,
        elapsed_seconds: float,
        timeout_seconds: int,
    ) -> None:
        pass

    def tool_finished(self, result: ToolRunResult, *, completed: int, total: int) -> None:
        pass

    def pipeline_finished(self, results: dict[str, ToolRunResult]) -> None:
        pass

    def report_written(self, report_path: Path) -> None:
        pass


class NullReporter(ProgressReporter):
    """Reporter that intentionally emits nothing."""


class RecordingReporter(ProgressReporter):
    """Test reporter that records events without printing."""

    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []

    def pipeline_started(
        self,
        *,
        project_root: Path,
        output_root: Path,
        tools: tuple[str, ...],
    ) -> None:
        self.events.append(
            ProgressEvent(
                "pipeline_started",
                message=f"{project_root}|{output_root}|{','.join(tools)}",
            )
        )

    def tool_queued(self, tool: str) -> None:
        self.events.append(ProgressEvent("tool_queued", tool=tool))

    def tool_phase(self, tool: str, phase: str) -> None:
        self.events.append(ProgressEvent(f"tool_{phase}", tool=tool))

    def tool_command(self, tool: str, command: list[str]) -> None:
        self.events.append(ProgressEvent("tool_command", tool=tool, message=" ".join(command)))

    def tool_heartbeat(
        self,
        tool: str,
        *,
        elapsed_seconds: float,
        timeout_seconds: int,
    ) -> None:
        self.events.append(
            ProgressEvent(
                "tool_heartbeat",
                tool=tool,
                message=f"{int(elapsed_seconds)}|{timeout_seconds}",
            )
        )

    def tool_finished(self, result: ToolRunResult, *, completed: int, total: int) -> None:
        self.events.append(
            ProgressEvent(
                "tool_finished",
                tool=result.tool,
                message=f"{result.status}|{completed}/{total}",
            )
        )

    def pipeline_finished(self, results: dict[str, ToolRunResult]) -> None:
        self.events.append(ProgressEvent("pipeline_finished", message=str(len(results))))

    def report_written(self, report_path: Path) -> None:
        self.events.append(ProgressEvent("report_written", message=str(report_path)))


class ConsoleReporter(ProgressReporter):
    """Human-readable terminal progress reporter."""

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        verbose: bool = False,
        show_command: bool = False,
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.verbose = verbose
        self.show_command = show_command

    def pipeline_started(
        self,
        *,
        project_root: Path,
        output_root: Path,
        tools: tuple[str, ...],
    ) -> None:
        self._write("Static Analysis")
        self._write(f"Project: {project_root}")
        self._write(f"Output: {output_root}")
        self._write(f"Tools: {', '.join(tools)}")
        self._write("")

    def tool_queued(self, tool: str) -> None:
        if self.verbose:
            self._write(f"[{tool}] queued")

    def tool_phase(self, tool: str, phase: str) -> None:
        if phase == "run":
            self._write(f"[{tool}] starting")
            return
        if self.verbose:
            self._write(f"[{tool}] {phase}")

    def tool_command(self, tool: str, command: list[str]) -> None:
        if self.show_command:
            self._write(f"[{tool}] command: {' '.join(command)}")

    def tool_heartbeat(
        self,
        tool: str,
        *,
        elapsed_seconds: float,
        timeout_seconds: int,
    ) -> None:
        elapsed = format_duration(elapsed_seconds)
        if timeout_seconds and timeout_seconds > 0:
            remaining = format_duration(max(0.0, timeout_seconds - elapsed_seconds))
            self._write(
                f"[{tool}] still running | elapsed {elapsed} "
                f"| timeout {format_duration(timeout_seconds)} "
                f"| remaining before timeout {remaining}"
            )
        else:
            self._write(f"[{tool}] still running | elapsed {elapsed} | timeout none")

    def tool_finished(self, result: ToolRunResult, *, completed: int, total: int) -> None:
        details = [f"{len(result.findings)} findings"]
        if result.exit_code is not None:
            details.append(f"exit {result.exit_code}")
        if result.duration_seconds is not None:
            details.append(f"{result.duration_seconds:.2f}s")
        self._write(
            f"[{completed}/{total}] {result.tool} {result.status}: {', '.join(details)}"
        )
        if self.verbose and result.raw_output_path is not None:
            self._write(f"[{result.tool}] raw: {result.raw_output_path}")
        if self.verbose and result.stderr_path is not None:
            self._write(f"[{result.tool}] stderr: {result.stderr_path}")
        if result.message:
            self._write(f"[{result.tool}] {result.message}")

    def pipeline_finished(self, results: dict[str, ToolRunResult]) -> None:
        completed = sum(1 for result in results.values() if result.status == "completed")
        failed = sum(1 for result in results.values() if result.status == "failed")
        findings = sum(len(result.findings) for result in results.values())
        self._write("")
        self._write(
            f"Summary: {completed} completed, {failed} failed, {findings} findings"
        )

    def report_written(self, report_path: Path) -> None:
        self._write(f"Report written: {report_path}")

    def _write(self, message: str) -> None:
        print(message, file=self.stream)


@contextmanager
def heartbeat(
    reporter: ProgressReporter,
    tool: str,
    *,
    timeout_seconds: int,
    interval: float = HEARTBEAT_INTERVAL_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> Iterator[None]:
    """Emit `reporter.tool_heartbeat` every `interval` seconds for the wrapped block.

    A background daemon thread does the emitting so it keeps ticking while the
    body blocks in subprocess.run. The thread is stopped and joined on exit —
    whether the body returns, raises, times out, or is interrupted — so no
    heartbeat survives the tool. With NullReporter (used for --quiet) the
    callback is a no-op, so quiet runs stay silent.
    """
    stop = threading.Event()
    start = clock()

    def _loop() -> None:
        while not stop.wait(interval):
            reporter.tool_heartbeat(
                tool,
                elapsed_seconds=clock() - start,
                timeout_seconds=timeout_seconds,
            )

    thread = threading.Thread(target=_loop, name=f"heartbeat-{tool}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()

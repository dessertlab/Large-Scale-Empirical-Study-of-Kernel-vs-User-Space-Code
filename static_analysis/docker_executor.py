"""Low-level Docker execution primitives."""

from __future__ import annotations

import atexit
import itertools
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from static_analysis.models import ToolName, ToolRunResult


CONTAINER_OUTPUT_DIR = "/output"

# Best-effort upper bound for the `docker kill` we issue when a run times out,
# so a wedged daemon can never make the kill itself hang the pipeline.
_KILL_TIMEOUT_SECONDS = 60

_NAME_COUNTER = itertools.count()

# Containers currently running under execute_command, keyed by name -> docker
# executable. Tools run in a ThreadPoolExecutor, so a signal (delivered only to
# the main thread) cannot interrupt a worker's blocked subprocess.run; this
# registry lets a SIGINT/SIGTERM handler reach across threads and kill every
# live container instead of orphaning it.
_LIVE_LOCK = threading.Lock()
_LIVE_CONTAINERS: dict[str, str] = {}
_HANDLERS_INSTALLED = False

# Extra docker commands to run when the process is interrupted (after live
# containers are killed) — e.g. removing a tool's scratch dir that the kill
# itself leaves on the host bind mount. Each is a plain `docker run ...`; it is
# made named/killable by run_guarded so the shutdown cleanup cannot orphan.
_CLEANUP_LOCK = threading.Lock()
_TERMINATION_CLEANUPS: list[list[str]] = []

# Cap shutdown-path cleanups so an unresponsive daemon can't hang the exit.
_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS = 120


def _unique_container_name() -> str:
    """A name unique within this process tree.

    `os.getpid()` separates the parallel `static-analysis run` jobs spawned by
    run.sh; the counter separates tools running concurrently inside one job.
    Used so a timed-out run can target its own container with `docker kill`
    instead of orphaning it (a killed `docker run` client leaves the container
    running on the daemon — the cause of the multi-day, disk-filling runs).
    """
    return f"sa-{os.getpid()}-{next(_NAME_COUNTER)}"


def _register_container(docker_executable: str, name: str) -> None:
    with _LIVE_LOCK:
        _LIVE_CONTAINERS[name] = docker_executable


def _unregister_container(name: str) -> None:
    with _LIVE_LOCK:
        _LIVE_CONTAINERS.pop(name, None)


def register_termination_cleanup(command: list[str]) -> None:
    """Register a docker command to run if the process is interrupted."""
    with _CLEANUP_LOCK:
        _TERMINATION_CLEANUPS.append(list(command))


def unregister_termination_cleanup(command: list[str]) -> None:
    with _CLEANUP_LOCK:
        try:
            _TERMINATION_CLEANUPS.remove(list(command))
        except ValueError:
            pass


def terminate_live_containers() -> None:
    """Kill live containers, then run pending cleanups. Best effort, never raises."""
    with _LIVE_LOCK:
        targets = list(_LIVE_CONTAINERS.items())
    for name, docker_executable in targets:
        _kill_target(docker_executable, name)
    with _CLEANUP_LOCK:
        cleanups = list(_TERMINATION_CLEANUPS)
    for command in cleanups:
        run_guarded(command, timeout_seconds=_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS)


def install_interrupt_handlers() -> None:
    """Make Ctrl-C / SIGTERM kill in-flight containers before the process dies.

    Idempotent and safe to skip when not on the main thread (e.g. under a test
    runner): the per-call BaseException guard in execute_command still covers
    the common Ctrl-C case, this just extends it to SIGTERM and worker threads.
    """
    global _HANDLERS_INSTALLED
    if _HANDLERS_INSTALLED:
        return
    _HANDLERS_INSTALLED = True
    atexit.register(terminate_live_containers)

    def _handler(signum, _frame):
        terminate_live_containers()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            # Not the main thread, or signal unsupported on this platform.
            pass


def docker_run_command(
    *,
    image: str,
    command: str,
    args: tuple[str, ...],
    project_root: Path,
    project_mount: str,
    output_dir: Path,
    workdir: str,
    environment: dict[str, str],
    platform: str | None = None,
    docker_executable: str = "docker",
    container_name: str | None = None,
) -> list[str]:
    """Build a docker run command without tool-specific knowledge."""

    command_parts = [
        docker_executable,
        "run",
        "--rm",
    ]
    if platform:
        command_parts.extend(["--platform", platform])
    command_parts.extend(["--name", container_name or _unique_container_name()])
    command_parts.extend(
        [
            "--volume",
            f"{project_root.resolve()}:{project_mount}:ro",
            "--volume",
            f"{output_dir.resolve()}:{CONTAINER_OUTPUT_DIR}",
            "--workdir",
            workdir,
        ]
    )
    for key, value in sorted(environment.items()):
        command_parts.extend(["--env", f"{key}={value}"])
    command_parts.extend([image, command, *args])
    return command_parts


def execute_command(
    command: list[str],
    *,
    tool: ToolName,
    timeout_seconds: int,
    allowed_exit_codes: tuple[int, ...],
    stdout_path: Path,
    stderr_path: Path,
) -> ToolRunResult:
    """Execute a command and persist raw stdout/stderr."""

    started_at = time.monotonic()
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    target = _container_target(command)
    if target is not None:
        _register_container(*target)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=None if timeout_seconds <= 0 else timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run only SIGKILLs the `docker run` client; the container
        # keeps running on the daemon. Stop it explicitly so a timed-out run is
        # actually dead and its scratch (e.g. CodeQL's codeql-db) stops growing.
        killed = _kill_target(*target) if target is not None else None
        stdout_path.write_text(_output_text(exc.stdout), encoding="utf-8")
        stderr_path.write_text(_output_text(exc.stderr), encoding="utf-8")
        message = f"Timed out after {timeout_seconds} seconds."
        if killed is False:
            message += " (container kill failed; check for orphaned containers)"
        return ToolRunResult(
            tool=tool,
            status="timeout",
            duration_seconds=_elapsed(started_at),
            raw_output_path=stdout_path,
            stderr_path=stderr_path,
            message=message,
        )
    except FileNotFoundError as exc:
        return ToolRunResult(
            tool=tool,
            status="unavailable",
            duration_seconds=_elapsed(started_at),
            raw_output_path=stdout_path,
            stderr_path=stderr_path,
            message=str(exc),
        )
    except BaseException:
        # KeyboardInterrupt / SystemExit / anything that aborts the run mid-flight
        # must not leave the container running on the daemon.
        if target is not None:
            _kill_target(*target)
        raise
    finally:
        if target is not None:
            _unregister_container(target[1])

    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    status = "completed" if completed.returncode in allowed_exit_codes else "failed"
    return ToolRunResult(
        tool=tool,
        status=status,
        exit_code=completed.returncode,
        duration_seconds=_elapsed(started_at),
        raw_output_path=stdout_path,
        stderr_path=stderr_path,
    )


def _container_target(command: list[str]) -> tuple[str, str] | None:
    """Return (docker_executable, container_name) from a docker command.

    None when the command has no `--name` (e.g. a non-docker command), so the
    caller knows there is nothing to register or kill.
    """
    if "--name" not in command:
        return None
    name_index = command.index("--name")
    if name_index + 1 >= len(command):
        return None
    docker_executable = command[0] if command else "docker"
    return docker_executable, command[name_index + 1]


def _kill_target(docker_executable: str, container_name: str) -> bool:
    """Kill one container, best effort. True on clean kill, False on failure.

    Never raises: a failure here must not mask the timeout/interrupt the caller
    is already handling.
    """
    try:
        result = subprocess.run(
            [docker_executable, "kill", container_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=_KILL_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def run_guarded(command: list[str], *, timeout_seconds: int):
    """Run a short `docker run ...` with the same orphan-safety as execute_command.

    The container is named (one is injected if absent), registered so a signal
    can reach it, and killed if the command times out or is interrupted. Use for
    auxiliary containers (e.g. scratch cleanup) that must never be orphaned.
    Returns the CompletedProcess, or None if it timed out.
    """
    command = list(command)
    target = _container_target(command)
    if target is None and len(command) >= 2 and command[1] == "run":
        name = _unique_container_name()
        command[2:2] = ["--name", name]
        target = (command[0], name)
    if target is not None:
        _register_container(*target)
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=None if timeout_seconds <= 0 else timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        if target is not None:
            _kill_target(*target)
        return None
    except BaseException:
        if target is not None:
            _kill_target(*target)
        raise
    finally:
        if target is not None:
            _unregister_container(target[1])


def _elapsed(started_at: float) -> float:
    return round(time.monotonic() - started_at, 6)


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value

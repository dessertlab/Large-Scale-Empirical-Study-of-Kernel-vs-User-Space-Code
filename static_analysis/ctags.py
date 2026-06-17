"""Helpers for locating Universal Ctags across Linux and macOS."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class CtagsResolutionError(RuntimeError):
    """Raised when Universal Ctags cannot be found."""


_FALLBACK_CANDIDATES = (
    "uctags",
    "ctags-universal",
    "/opt/homebrew/bin/ctags",
    "/opt/homebrew/bin/uctags",
    "/opt/homebrew/opt/universal-ctags/bin/ctags",
    "/opt/homebrew/opt/universal-ctags/bin/uctags",
    "/usr/local/bin/ctags",
    "/usr/local/bin/uctags",
    "/usr/local/opt/universal-ctags/bin/ctags",
    "/usr/local/opt/universal-ctags/bin/uctags",
)


def resolve_universal_ctags(executable: str = "ctags") -> str:
    """Return a Universal Ctags executable path, preferring the requested binary."""

    tried: list[str] = []
    for candidate in _candidate_executables(executable):
        resolved = _resolve_candidate(candidate)
        if resolved is None or resolved in tried:
            continue
        tried.append(resolved)
        first_line = _version_first_line(resolved)
        if "Universal Ctags" in first_line:
            return resolved

    tried_list = ", ".join(tried) if tried else executable
    raise CtagsResolutionError(
        "Universal Ctags executable not found. "
        f"Tried: {tried_list}. "
        "On macOS install it with `brew install universal-ctags`, "
        "or pass `--ctags-bin /path/to/ctags`."
    )


def _candidate_executables(executable: str) -> tuple[str, ...]:
    if executable in {"ctags", "uctags"}:
        return (executable, *_FALLBACK_CANDIDATES)
    return (executable,)


def _resolve_candidate(candidate: str) -> str | None:
    path = Path(candidate)
    if path.parent != Path("."):
        return str(path) if path.exists() else None
    return shutil.which(candidate)


def _version_first_line(executable: str) -> str:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return ""
    output = completed.stdout or completed.stderr
    return output.splitlines()[0] if output else ""

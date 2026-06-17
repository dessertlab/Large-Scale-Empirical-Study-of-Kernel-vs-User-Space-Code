"""CodeQL runner."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from static_analysis.runners.base import RunnerContext
from static_analysis.runners.sarif import SarifRunner
from static_analysis.docker_executor import (
    docker_run_command,
    register_termination_cleanup,
    run_guarded,
    unregister_termination_cleanup,
)
from static_analysis.models import ToolRunResult


DEFAULT_QUERIES = ("codeql/cpp-queries:Security/CWE",)
DEFAULT_ALERT_QUERY_KINDS = ("problem", "path-problem")

# Query ids excluded from every run, by @id. These are a safety net for when the
# experimental suite is re-enabled (it is off by default): several experimental
# C/C++ queries have undeclared (n/a) precision and do not terminate within
# budget on large codebases. On esp-idf the supported queries all finish in
# ~4 min, while individual experimental queries thrash memory (evicting ~500MiB
# every few seconds) for many hours without completing — observed for both
# CWE-409 DecompressionBombs and CWE-787 UnsignedToSignedPointerArith.
DEFAULT_EXCLUDED_QUERY_IDS = (
    "cpp/sign-conversion-pointer-arithmetic",
    "cpp/data-decompression-bomb",
)

# Cap for the throwaway cleanup container, so a wedged daemon can't hang us.
_DB_CLEANUP_TIMEOUT_SECONDS = 300


class CodeqlRunner(SarifRunner):
    tool_name = "codeql"

    def parse(self, raw_output):
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="replace")
        return super().parse(raw_output)

    def run(self, context: RunnerContext) -> ToolRunResult:
        # Registered for the whole run so that if the process is interrupted
        # (SIGINT/SIGTERM) mid-analysis, the shutdown path removes the partial
        # codeql-db too — not just kills the container.
        cleanup_command = self._database_cleanup_command(context.tool_output_dir)
        register_termination_cleanup(cleanup_command)
        try:
            result = super().run(context)
        finally:
            unregister_termination_cleanup(cleanup_command)
        # On success the in-container script already removes codeql-db. On a
        # timeout (container SIGKILLed) or a failed analysis (set -e aborts
        # before the script's cleanup) the database is left on the host bind
        # mount, hundreds of GB of dead scratch. Drop it.
        if result.status != "completed" and (context.tool_output_dir / "codeql-db").exists():
            run_guarded(cleanup_command, timeout_seconds=_DB_CLEANUP_TIMEOUT_SECONDS)
        return result

    def _database_cleanup_command(self, tool_output_dir: Path) -> list[str]:
        # The DB is written by the container as root, so an unprivileged caller
        # cannot rmtree it from the host. Delete it from inside a container
        # (same image) where we are root. run_guarded names/registers it so the
        # cleanup itself can never be orphaned.
        command = [self.docker_executable, "run", "--rm"]
        if self.config.platform:
            command += ["--platform", self.config.platform]
        command += [
            "--volume",
            f"{tool_output_dir.resolve()}:/output",
            self.config.image,
            "bash",
            "-lc",
            "rm -rf /output/codeql-db",
        ]
        return command

    def docker_command(self, context: RunnerContext) -> list[str]:
        options = self.config.options
        build_mode = _string_option(options, "build_mode", default="none")
        if build_mode != "none":
            raise ValueError("CodeQL build_mode must be none for C/C++ analysis")
        threads = _int_option(options, "threads", default=1, minimum=0)
        ram = _int_option(options, "ram", default=8192)
        queries = _query_options(options)
        alert_query_kinds = _string_list_option(
            options,
            "alert_query_kinds",
            default=DEFAULT_ALERT_QUERY_KINDS,
        )
        excluded_query_ids = _excluded_query_ids(options)
        script = _analysis_script(
            build_mode=build_mode,
            threads=threads,
            ram=ram,
            queries=queries,
            alert_query_kinds=alert_query_kinds,
            excluded_query_ids=excluded_query_ids,
        )
        return docker_run_command(
            image=self.config.image,
            command="bash",
            args=("-lc", script),
            project_root=context.project_root,
            project_mount=self.config.container_workdir,
            output_dir=context.tool_output_dir,
            workdir=self.config.container_workdir,
            environment=self.config.environment,
            platform=self.config.platform,
            docker_executable=self.docker_executable,
        )

    def parse_input_path(self, result: ToolRunResult) -> Path | None:
        if result.raw_output_path is None:
            return None
        sarif_path = result.raw_output_path.parent / "results.sarif"
        return sarif_path if sarif_path.exists() else result.raw_output_path


def _analysis_script(
    *,
    build_mode: str,
    threads: int,
    ram: int,
    queries: tuple[str, ...],
    alert_query_kinds: tuple[str, ...],
    excluded_query_ids: tuple[str, ...],
) -> str:
    qls = _query_suite_content(queries, alert_query_kinds, excluded_query_ids)
    return "\n".join(
        (
            "set -euo pipefail",
            "rm -rf /output/codeql-db /output/results.sarif /output/codeql-queries.qls",
            "cat > /output/codeql-queries.qls <<'CODEQL_QUERIES'",
            qls,
            "CODEQL_QUERIES",
            "codeql database create /output/codeql-db "
            "--language=cpp "
            "--source-root=/workspace "
            f"--build-mode={shlex.quote(build_mode)} "
            f"--threads={threads} "
            f"--ram={ram} "
            "--overwrite "
            "1>&2",
            "codeql database analyze /output/codeql-db "
            "/output/codeql-queries.qls "
            "--format=sarif-latest "
            f"--threads={threads} "
            f"--ram={ram} "
            "--output=/output/results.sarif "
            "1>&2",
            # The database is only build scratch (often hundreds of GB); once
            # results.sarif is written it is never read again, so delete it to
            # keep the dbs from accumulating and filling the disk across runs.
            # `set -e` already aborts before here if create/analyze failed, so a
            # failed run keeps its db for resume/debugging; the `-s` guard is a
            # belt-and-suspenders check that the result was actually produced.
            "if [ -s /output/results.sarif ]; then rm -rf /output/codeql-db; fi",
        )
    )


def _query_options(options: dict[str, object]) -> tuple[str, ...]:
    return _string_list_option(options, "queries", default=DEFAULT_QUERIES)


def _excluded_query_ids(options: dict[str, object]) -> tuple[str, ...]:
    # Unlike `queries`, an empty exclusion list is valid (exclude nothing).
    value = options.get("exclude_query_ids", DEFAULT_EXCLUDED_QUERY_IDS)
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return tuple(item for item in value if item)
    raise ValueError("CodeQL exclude_query_ids must be a list of strings")


def _string_list_option(
    options: dict[str, object],
    key: str,
    *,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    value = options.get(key, default)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        items = tuple(item for item in value if item)
        if items:
            return items
    if isinstance(value, tuple) and all(isinstance(item, str) for item in value):
        items = tuple(item for item in value if item)
        if items:
            return items
    raise ValueError(f"CodeQL {key} must be a non-empty list of strings")


def _query_suite_content(
    queries: tuple[str, ...],
    alert_query_kinds: tuple[str, ...],
    excluded_query_ids: tuple[str, ...] = (),
) -> str:
    lines: list[str] = []
    for query in queries:
        lines.extend(_query_suite_location(query))
    lines.extend(
        [
            "- include:",
            "    kind:",
            *[f"    - {kind}" for kind in alert_query_kinds],
        ]
    )
    # Drop specific queries by @id after the includes have selected the set.
    for query_id in excluded_query_ids:
        lines.extend(
            [
                "- exclude:",
                f"    id: {json.dumps(query_id)}",
            ]
        )
    return "\n".join(lines) + "\n"


def _query_suite_location(query: str) -> list[str]:
    if ":" not in query:
        if query.endswith(".qls"):
            return [f"- import: {json.dumps(query)}"]
        return [f"- queries: {json.dumps(query)}"]
    pack, path = query.split(":", 1)
    if not pack or not path:
        return [f"- queries: {json.dumps(query)}"]
    if path.endswith(".qls"):
        return [
            f"- import: {json.dumps(path)}",
            f"  from: {json.dumps(pack)}",
        ]
    return [
        f"- queries: {json.dumps(path)}",
        f"  from: {json.dumps(pack)}",
    ]


def _int_option(
    options: dict[str, object],
    key: str,
    *,
    default: int,
    minimum: int = 1,
) -> int:
    value = options.get(key, default)
    if isinstance(value, int) and not isinstance(value, bool) and value >= minimum:
        return value
    if minimum == 0:
        raise ValueError(f"CodeQL {key} must be a non-negative integer")
    raise ValueError(f"CodeQL {key} must be a positive integer")


def _string_option(options: dict[str, object], key: str, *, default: str) -> str:
    value = options.get(key, default)
    if isinstance(value, str) and value:
        return value
    raise ValueError(f"CodeQL {key} must be a non-empty string")

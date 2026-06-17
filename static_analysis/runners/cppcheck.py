"""Cppcheck runner.

Cppcheck does not scale to a whole large tree in one process: on the FreeBSD
kernel a single `cppcheck /workspace` run grew unbounded and was OOM-killed
(exit 137) after ~20h, losing every finding because its XML was never closed.

This runner therefore splits the project into chunks (one per top-level
subdirectory) and analyzes each in its own short-lived container with `-j`
parallelism. Running a fresh process per chunk frees memory between chunks and,
crucially, isolates failures: if one chunk (e.g. the huge `sys/`) times out or
is OOM-killed, the findings from every other chunk are still merged and kept.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from static_analysis.runners.base import RunnerContext, ToolRunner, as_int, first_cwe
from static_analysis.docker_executor import docker_run_command, execute_command
from static_analysis.models import Finding, RunStatus, ToolRunResult
from static_analysis.progress import heartbeat


DEFAULT_JOBS = 4

_VERSION_PATTERN = re.compile(r'<cppcheck\s+version="([^"]+)"')


class CppcheckRunner(ToolRunner):
    def run(self, context: RunnerContext) -> ToolRunResult:
        workdir = self.config.container_workdir
        flags = _flags(self.config.args, workdir)
        jobs = _jobs(self.config.options)
        job_flag = ("-j", str(jobs)) if jobs > 1 else ()
        max_configs = _max_configs(self.config.options)
        config_flag = (f"--max-configs={max_configs}",) if max_configs is not None else ()
        specs = _chunk_specs(context.project_root, workdir)

        chunk_dir = context.tool_output_dir / "chunks"
        results: list[ToolRunResult] = []
        stdout_sections: list[str] = []
        stderr_texts: list[str] = []

        with heartbeat(self.reporter, self.config.name, timeout_seconds=0):
            for name, targets in specs:
                args = (*flags, *job_flag, *config_flag, *targets)
                command = docker_run_command(
                    image=self.config.image,
                    command=self.config.command,
                    args=args,
                    project_root=context.project_root,
                    project_mount=workdir,
                    output_dir=context.tool_output_dir,
                    workdir=workdir,
                    environment=self.config.environment,
                    platform=self.config.platform,
                    docker_executable=self.docker_executable,
                )
                self.reporter.tool_command(self.config.name, command)
                chunk_stdout = chunk_dir / f"{name}.stdout.txt"
                chunk_stderr = chunk_dir / f"{name}.stderr.txt"
                result = execute_command(
                    command,
                    tool=self.config.name,
                    # The configured timeout now applies per chunk, so a single
                    # pathological chunk can be bounded without sacrificing the
                    # ones that finish quickly.
                    timeout_seconds=self.config.timeout_seconds,
                    allowed_exit_codes=self.config.allowed_exit_codes,
                    stdout_path=chunk_stdout,
                    stderr_path=chunk_stderr,
                )
                results.append(result)
                stdout_text = chunk_stdout.read_text(encoding="utf-8", errors="replace")
                stderr_text = chunk_stderr.read_text(encoding="utf-8", errors="replace")
                stdout_sections.append(
                    f"===== chunk {name} (status {result.status}, "
                    f"exit {result.exit_code}) =====\n" + stdout_text
                )
                # cppcheck --xml writes to stderr, but fall back to stdout so the
                # merge is robust to either stream carrying the report.
                stderr_texts.append(stderr_text if _xml_payload(stderr_text) else stdout_text)

        context.stdout_path.write_text("\n".join(stdout_sections), encoding="utf-8")
        _write_merged_xml(stderr_texts, context.stderr_path)

        findings = self.parse(context.stderr_path.read_text(encoding="utf-8", errors="replace"))
        return ToolRunResult(
            tool=self.config.name,
            status=_aggregate_status(results),
            findings=findings,
            exit_code=results[0].exit_code if len(results) == 1 else None,
            duration_seconds=sum(r.duration_seconds or 0.0 for r in results),
            raw_output_path=context.stdout_path,
            stderr_path=context.stderr_path,
            message=_chunk_summary(specs, results),
        )

    def parse_input_path(self, result: ToolRunResult) -> Path | None:
        if result.stderr_path is None:
            return result.raw_output_path
        stderr = result.stderr_path.read_text(encoding="utf-8")
        if _xml_payload(stderr):
            return result.stderr_path
        return result.raw_output_path

    def parse(self, raw_output: str) -> tuple[Finding, ...]:
        payload = _xml_payload(raw_output)
        if not payload:
            return ()
        root = ET.fromstring(payload)
        findings: list[Finding] = []
        for error in root.findall(".//error"):
            location = error.find("location")
            filename = location.attrib.get("file", "") if location is not None else ""
            line = as_int(location.attrib.get("line")) if location is not None else None
            message = error.attrib.get("msg") or error.attrib.get("verbose") or ""
            findings.append(
                Finding(
                    tool="cppcheck",
                    filename=filename,
                    line=line,
                    cwe=first_cwe(error.attrib.get("cwe"), message, error.attrib.get("verbose")),
                    rule=error.attrib.get("id"),
                    message=message,
                )
            )
        return tuple(findings)


def _flags(args: tuple[str, ...], workdir: str) -> tuple[str, ...]:
    """Configured args minus the scan target and any pre-set ``-j``.

    The scan target (``/workspace``), parallelism (``-j``) and ``--max-configs``
    are supplied per chunk from options, so drop them here and keep only the
    analysis flags (``--xml``, ``--enable=…``).
    """
    kept: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == workdir:
            continue
        if arg in ("-j", "--max-configs"):
            skip_next = True
            continue
        if arg.startswith("-j") or arg.startswith("--max-configs="):
            continue
        kept.append(arg)
    return tuple(kept)


def _jobs(options: dict[str, object]) -> int:
    value = options.get("jobs", DEFAULT_JOBS)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    raise ValueError("cppcheck jobs must be a positive integer")


def _max_configs(options: dict[str, object]) -> int | None:
    """Optional cap on preprocessor configurations checked per file.

    Unset means no ``--max-configs`` flag, so cppcheck keeps its own default
    (12) and behaviour is unchanged. Lowering it (e.g. 1-2) tames the heavily
    ``#ifdef``-ed trees (FreeBSD's ``sys/dev`` drivers) where re-checking each
    file under many macro combinations dominates the runtime.
    """
    value = options.get("max_configs")
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    raise ValueError("cppcheck max_configs must be a positive integer")


def _chunk_specs(project_root: Path, workdir: str) -> list[tuple[str, tuple[str, ...]]]:
    """One chunk per top-level subdirectory, plus one for loose root files.

    Together these cover exactly what a recursive scan of ``workdir`` would, so
    no source is dropped. Falls back to scanning the whole mount when the
    project is flat or empty.
    """
    entries = sorted(project_root.iterdir(), key=lambda p: p.name)
    subdirs = [e for e in entries if e.is_dir() and not e.name.startswith(".")]
    files = [e for e in entries if e.is_file() and not e.name.startswith(".")]

    specs: list[tuple[str, tuple[str, ...]]] = [
        (d.name, (f"{workdir}/{d.name}",)) for d in subdirs
    ]
    if files:
        specs.append(("_root_files", tuple(f"{workdir}/{f.name}" for f in files)))
    if not specs:
        specs.append(("_all", (workdir,)))
    return specs


def _aggregate_status(results: list[ToolRunResult]) -> RunStatus:
    statuses = [r.status for r in results]
    if all(s == "completed" for s in statuses):
        return "completed"
    if any(s == "failed" for s in statuses):
        return "failed"
    if any(s == "timeout" for s in statuses):
        return "timeout"
    return "failed"


def _chunk_summary(
    specs: list[tuple[str, tuple[str, ...]]],
    results: list[ToolRunResult],
) -> str | None:
    completed = sum(1 for r in results if r.status == "completed")
    if completed == len(results):
        return None
    bad = [
        f"{name} ({result.status}"
        + (f", exit {result.exit_code}" if result.exit_code is not None else "")
        + ")"
        for (name, _), result in zip(specs, results)
        if result.status != "completed"
    ]
    return f"{completed}/{len(results)} chunks completed; failed: {', '.join(bad)}"


def _write_merged_xml(chunk_texts: list[str], dest: Path) -> None:
    version = "2"
    errors: list[ET.Element] = []
    for text in chunk_texts:
        matched = _VERSION_PATTERN.search(text)
        if matched:
            version = matched.group(1)
        errors.extend(_iter_error_elements(text))

    root = ET.Element("results", {"version": "2"})
    ET.SubElement(root, "cppcheck", {"version": version})
    errors_el = ET.SubElement(root, "errors")
    for error in errors:
        errors_el.append(error)

    dest.parent.mkdir(parents=True, exist_ok=True)
    body = ET.tostring(root, encoding="unicode")
    dest.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + body, encoding="utf-8")


def _iter_error_elements(text: str) -> list[ET.Element]:
    """Pull the ``<error>`` elements out of one chunk's XML.

    Uses a pull parser so a chunk whose output was truncated mid-stream (the
    container was OOM-killed or timed out before ``</results>``) still yields
    every ``<error>`` that was fully written; the incomplete trailing element
    simply never fires an end event and is skipped.
    """
    payload = _xml_payload(text)
    if not payload:
        return []
    parser = ET.XMLPullParser(events=("end",))
    try:
        parser.feed(payload)
    except ET.ParseError:
        pass
    return [elem for event, elem in parser.read_events() if elem.tag == "error"]


def _xml_payload(raw_output: str) -> str:
    start = raw_output.find("<")
    return raw_output[start:].strip() if start >= 0 else ""

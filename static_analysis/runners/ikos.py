"""IKOS runner."""

from __future__ import annotations

import json
import textwrap
from typing import Any

from static_analysis.runners.base import RunnerContext, ToolRunner, as_dict, as_int, as_string
from static_analysis.docker_executor import docker_run_command
from static_analysis.models import Finding


class IkosRunner(ToolRunner):
    def docker_command(self, context: RunnerContext) -> list[str]:
        script = _analysis_script(
            command=self.config.command,
            args=self.config.args,
            report_command=self.config.report_command or "ikos-report",
            options=self.config.options,
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

    def parse(self, raw_output: str) -> tuple[Finding, ...]:
        payload = json.loads(raw_output or "[]")
        documents = payload if isinstance(payload, list) else [payload]
        findings: list[Finding] = []
        for document in documents:
            if not isinstance(document, dict):
                continue
            file_index = _file_index(document)
            statement_index = _statement_index(document)
            for item in _entries(document):
                status = _status(item.get("status"))
                if status not in {"error", "warning", "unreachable"}:
                    continue
                rule = _rule(item)
                filename, line = _location(item, file_index, statement_index)
                findings.append(
                    Finding(
                        tool="ikos",
                        filename=filename,
                        line=line,
                        cwe=_CWE_BY_RULE.get(rule),
                        rule=rule,
                        message=_message(item, rule),
                    )
                )
        return tuple(findings)


def _analysis_script(
    *,
    command: str,
    args: tuple[str, ...],
    report_command: str,
    options: dict[str, object],
) -> str:
    config = {
        "command": command,
        "args": list(args),
        "report_command": report_command,
        "source_extensions": _string_list_option(
            options,
            "source_extensions",
            default=(".c", ".cc", ".cpp"),
        ),
        "include_dirs": _string_list_option(
            options,
            "include_dirs",
            default=("/workspace", "/workspace/include", "/workspace/src"),
        ),
        "c_flags": _string_list_option(options, "c_flags", default=("-std=c11",)),
        "cpp_flags": _string_list_option(options, "cpp_flags", default=("-std=c++20",)),
        "auto_include_header_dirs": _bool_option(
            options,
            "auto_include_header_dirs",
            default=True,
        ),
    }
    config_json = json.dumps(config, sort_keys=True)
    return (
        "python3 - <<'PY'\n"
        "import json\n"
        f"CONFIG = json.loads(r'''{config_json}''')\n"
        + _IKOS_PYTHON_SCRIPT
        + "\nPY"
    )


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
    raise ValueError(f"IKOS {key} must be a non-empty list of strings")


def _bool_option(options: dict[str, object], key: str, *, default: bool) -> bool:
    value = options.get(key, default)
    if isinstance(value, bool):
        return value
    raise ValueError(f"IKOS {key} must be a boolean")


def _entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("results", "checks", "reports"):
        value = document.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _file_index(document: dict[str, Any]) -> dict[int, str]:
    files = document.get("files", [])
    if isinstance(files, dict):
        files = list(files.values())
    index: dict[int, str] = {}
    for item in files if isinstance(files, list) else []:
        if isinstance(item, dict) and isinstance(item.get("id"), int):
            index[item["id"]] = as_string(item.get("path"))
    return index


def _statement_index(document: dict[str, Any]) -> dict[int, dict[str, Any]]:
    statements = document.get("statements", [])
    if isinstance(statements, dict):
        statements = list(statements.values())
    index: dict[int, dict[str, Any]] = {}
    for item in statements if isinstance(statements, list) else []:
        if isinstance(item, dict) and isinstance(item.get("id"), int):
            index[item["id"]] = item
    return index


def _rule(item: dict[str, Any]) -> str:
    value = item.get("check", item.get("kind", item.get("rule_id")))
    if isinstance(value, int):
        return _RULE_NUMBERS.get(value, str(value))
    rule = as_string(value).strip().lower().replace("_", "-")
    return _RULE_ALIASES.get(rule, rule) if rule else "ikos.unknown"


def _status(value: object) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return _STATUS_NUMBERS.get(value, "unknown")
    status = as_string(value).strip().lower().replace("_", "-")
    return _STATUS_ALIASES.get(status, status)


def _location(
    item: dict[str, Any],
    file_index: dict[int, str],
    statement_index: dict[int, dict[str, Any]],
) -> tuple[str, int | None]:
    location = as_dict(item.get("location"))
    filename = as_string(location.get("file"))
    line = as_int(location.get("line"))
    statement_id = item.get("statement_id")
    statement = statement_index.get(statement_id) if isinstance(statement_id, int) else None
    if statement:
        line = as_int(statement.get("line")) or line
        file_id = statement.get("file_id")
        if isinstance(file_id, int):
            filename = file_index.get(file_id, filename)
    return filename, line


def _message(item: dict[str, Any], rule: str) -> str:
    message = as_string(item.get("message")) or as_string(item.get("description"))
    return message or f"IKOS finding: {rule}"


_STATUS_NUMBERS = {
    0: "safe",
    1: "warning",
    2: "error",
    3: "unreachable",
}


_STATUS_ALIASES = {
    "ok": "safe",
    "safe": "safe",
    "warning": "warning",
    "error": "error",
    "unreachable": "unreachable",
}


_RULE_NUMBERS = {
    0: "unreachable",
    1: "unexpected-operand",
    2: "uninitialized-variable",
    3: "assert",
    4: "division-by-zero",
    5: "shift-count",
    6: "begin-int-overflow",
    7: "signed-int-underflow",
    8: "signed-int-overflow",
    9: "unsigned-int-underflow",
    10: "unsigned-int-overflow",
    11: "end-int-overflow",
    12: "null-pointer-deref",
    13: "null-pointer-comparison",
    14: "invalid-pointer-comparison",
    15: "pointer-comparison",
    16: "pointer-overflow",
    17: "invalid-pointer-deref",
    18: "unknown-memory-access",
    19: "unaligned-pointer",
    20: "begin-buffer-overflow",
    21: "buffer-overflow-gets",
    22: "buffer-overflow",
    23: "end-buffer-overflow",
    24: "begin-soundness",
    25: "ignored-store",
    26: "ignored-memory-copy",
    27: "ignored-memory-move",
    28: "ignored-memory-set",
    29: "ignored-free",
    30: "ignored-call-side-effect-pointer-param",
    31: "ignored-call-side-effect",
    32: "recursive-function-call",
    33: "end-soundness",
    34: "begin-function-call",
    35: "function-call-inline-asm",
    36: "unknown-function-call-pointer",
    37: "function-call",
    38: "end-function-call",
    39: "free",
}


_RULE_ALIASES = {
    "boa": "buffer-overflow",
    "buffer-overflow-checker": "buffer-overflow",
    "dbz": "division-by-zero",
    "dfa": "free",
    "double-free": "free",
    "nullity": "null-pointer-deref",
}


_CWE_BY_RULE = {
    "unreachable": "CWE-561",
    "uninitialized-variable": "CWE-457",
    "assert": "CWE-617",
    "division-by-zero": "CWE-369",
    "shift-count": "CWE-758",
    "signed-int-underflow": "CWE-191",
    "signed-int-overflow": "CWE-190",
    "unsigned-int-underflow": "CWE-191",
    "unsigned-int-overflow": "CWE-190",
    "null-pointer-deref": "CWE-476",
    "null-pointer-comparison": "CWE-758",
    "invalid-pointer-comparison": "CWE-758",
    "pointer-comparison": "CWE-758",
    "pointer-overflow": "CWE-823",
    "invalid-pointer-deref": "CWE-119",
    "unknown-memory-access": "CWE-119",
    "unaligned-pointer": "CWE-758",
    "buffer-overflow-gets": "CWE-242",
    "buffer-overflow": "CWE-119",
    "unknown-function-call-pointer": "CWE-758",
    "function-call": "CWE-758",
    "free": "CWE-415",
}


_IKOS_PYTHON_SCRIPT = textwrap.dedent(
    r'''
    import json
    import re
    import subprocess
    from pathlib import Path


    PROJECT_ROOT = Path("/workspace")
    OUTPUT_ROOT = Path("/output")
    LOG_PATH = OUTPUT_ROOT / "ikos.log"
    MANIFEST_PATH = OUTPUT_ROOT / "targets.json"
    HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx"}
    CPP_EXTENSIONS = {".cc", ".cpp", ".cxx"}

    def main():
        targets = _targets()
        include_dirs = _include_dirs()
        reports = []
        manifest = []
        for index, source in enumerate(targets, start=1):
            db_path = OUTPUT_ROOT / f"ikos-{index}-{_safe_name(source)}.db"
            flags = _flags_for(source, include_dirs)
            bc_path = OUTPUT_ROOT / f"ikos-{index}-{_safe_name(source)}.bc"
            compile_command = _compile_to_bitcode(source, bc_path, flags)

            entry = {
                "source": str(source),
                "bitcode": str(bc_path),
                "database": str(db_path),
                "compile_command": compile_command,
                "command": None,
                "status": "failed",
                "exit_code": None,
                "message": None,
            }

            compiled = _run(compile_command)

            if compiled.returncode != 0 or not bc_path.exists():
                entry["exit_code"] = compiled.returncode
                entry["message"] = compiled.stderr.strip() or compiled.stdout.strip()
                manifest.append(entry)
                continue

            command = [
                CONFIG["command"],
                *CONFIG["args"],
                "-o",
                str(db_path),
                str(bc_path),
            ]

            entry["command"] = command

            completed = _run(command)
            entry["exit_code"] = completed.returncode

            if completed.returncode in {0, 1} and db_path.exists():
                report = _report(db_path)

                if report.returncode == 0 and report.stdout.strip():
                    try:
                        payload = json.loads(report.stdout)
                    except json.JSONDecodeError as exc:
                        entry["message"] = f"invalid report JSON: {exc}"
                    else:
                        reports.append(payload)
                        entry["status"] = "analyzed"
                else:
                    entry["message"] = report.stderr.strip() or report.stdout.strip() or "empty report"
            else:
                entry["message"] = completed.stderr.strip() or completed.stdout.strip()

            manifest.append(entry)
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(reports))


    def _compile_to_bitcode(source, bc_path, flags):
        compiler = "clang++" if source.suffix in CPP_EXTENSIONS else "clang"
        return [
            compiler,
            "-emit-llvm",
            "-c",
            "-g",
            "-O0",
            *flags,
            "-o",
            str(bc_path),
            str(source),
        ]
    
    def _targets():
        extensions = set(CONFIG["source_extensions"])
        return sorted(
            path
            for path in PROJECT_ROOT.rglob("*")
            if path.is_file() and path.suffix in extensions
        )


    def _include_dirs():
        dirs = [_path(value) for value in CONFIG["include_dirs"]]
        if CONFIG["auto_include_header_dirs"]:
            dirs.extend(
                path.parent
                for path in PROJECT_ROOT.rglob("*")
                if path.is_file() and path.suffix in HEADER_EXTENSIONS
            )
        seen = set()
        result = []
        for path in dirs:
            if not path.exists() or not path.is_dir():
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            result.append(path)
        return result


    def _flags_for(source, include_dirs):
        flags = list(CONFIG["cpp_flags"] if source.suffix in CPP_EXTENSIONS else CONFIG["c_flags"])
        for include_dir in include_dirs:
            flags.extend(["-I", str(include_dir)])
        return flags


    def _path(value):
        path = Path(value)
        return path if path.is_absolute() else PROJECT_ROOT / path


    def _run(command):
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        _append_log(command, completed)
        return completed


    def _report(db_path):
        command = [
            CONFIG["report_command"],
            "--format",
            "json",
            "--report-verbosity",
            "1",
            str(db_path),
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        _append_log(command, completed)
        return completed


    def _append_log(command, completed):
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write("$ " + " ".join(command) + "\n")
            handle.write(f"exit_code={completed.returncode}\n")
            if completed.stdout:
                handle.write("[stdout]\n" + completed.stdout + "\n")
            if completed.stderr:
                handle.write("[stderr]\n" + completed.stderr + "\n")


    def _safe_name(path):
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)


    main()
    '''
).strip()

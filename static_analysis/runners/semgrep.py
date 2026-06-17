"""Semgrep runner."""

from __future__ import annotations

import json

from static_analysis.runners.base import ToolRunner, as_dict, as_int, as_optional_string, as_string, first_cwe
from static_analysis.models import Finding


class SemgrepRunner(ToolRunner):
    def parse(self, raw_output: str) -> tuple[Finding, ...]:
        payload = json.loads(raw_output or "{}")
        payload = payload if isinstance(payload, dict) else {}
        results = payload.get("results", [])
        findings: list[Finding] = []
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            start = as_dict(result.get("start"))
            extra = as_dict(result.get("extra"))
            metadata = as_dict(extra.get("metadata"))
            findings.append(
                Finding(
                    tool="semgrep",
                    filename=as_string(result.get("path")),
                    line=as_int(start.get("line")),
                    cwe=first_cwe(metadata.get("cwe")),
                    rule=as_optional_string(result.get("check_id")),
                    message=as_string(extra.get("message")),
                )
            )
        return tuple(findings)


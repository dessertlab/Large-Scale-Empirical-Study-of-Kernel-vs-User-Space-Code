"""SARIF-based runner support."""

from __future__ import annotations

import json
import re
from typing import Any

from static_analysis.runners.base import ToolRunner, as_dict, as_int, as_optional_string, as_string, first_cwe
from static_analysis.models import Finding, ToolName


_SARIF_CWE_TAG_PATTERN = re.compile(r"(?:^|/)cwe-(\d+)$", re.IGNORECASE)


class SarifRunner(ToolRunner):
    tool_name: ToolName

    def parse(self, raw_output: str) -> tuple[Finding, ...]:
        payload = _json_object(raw_output)
        runs = payload.get("runs", [])
        findings: list[Finding] = []
        for run in runs if isinstance(runs, list) else []:
            if not isinstance(run, dict):
                continue
            rule_metadata = _rule_metadata(run)
            results = run.get("results", [])
            for result in results if isinstance(results, list) else []:
                if not isinstance(result, dict):
                    continue
                rule = as_optional_string(result.get("ruleId"))
                metadata = rule_metadata.get(rule or "", {})
                filename, line = _location(result)
                message = as_dict(result.get("message"))
                properties = as_dict(result.get("properties"))
                findings.append(
                    Finding(
                        tool=self.tool_name,
                        filename=filename,
                        line=line,
                        cwe=first_cwe(
                            _cwe_tags(properties),
                            _cwe_tags(metadata),
                            message.get("text"),
                        ),
                        rule=rule,
                        message=as_string(message.get("text")),
                    )
                )
        return tuple(findings)


def _json_object(raw_output: str) -> dict[str, Any]:
    start = raw_output.find("{")
    if start > 0:
        raw_output = raw_output[start:]
    payload = json.loads(raw_output or "{}")
    return payload if isinstance(payload, dict) else {}


def _rule_metadata(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = as_dict(as_dict(run.get("tool")).get("driver"))
    rules = driver.get("rules", [])
    metadata: dict[str, dict[str, Any]] = {}
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            metadata[rule_id] = as_dict(rule.get("properties"))
    return metadata


def _location(result: dict[str, Any]) -> tuple[str, int | None]:
    locations = result.get("locations", [])
    first = locations[0] if isinstance(locations, list) and locations else {}
    physical = as_dict(as_dict(first).get("physicalLocation"))
    artifact = as_dict(physical.get("artifactLocation"))
    region = as_dict(physical.get("region"))
    return as_string(artifact.get("uri")), as_int(region.get("startLine"))


def _cwe_tags(properties: dict[str, Any]) -> list[str]:
    tags = properties.get("tags", [])
    cwes: list[str] = []
    for tag in tags if isinstance(tags, list) else []:
        if not isinstance(tag, str):
            continue
        match = _SARIF_CWE_TAG_PATTERN.search(tag)
        if match:
            cwes.append(f"CWE-{match.group(1)}")
    return cwes


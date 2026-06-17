"""Synthesize static-analysis reports with cross-tool voting."""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from itertools import combinations
from pathlib import Path
from typing import Iterable

from static_analysis.ctags import CtagsResolutionError, resolve_universal_ctags


TOOLS = ("flawfinder", "semgrep", "codeql", "cppcheck")
VOTE_KEYS = {
    1: "one_out_of_four",
    2: "two_out_of_four",
    3: "three_out_of_four",
    4: "four_out_of_four",
}
NO_CWE_VOTE_KEYS = {
    2: "two_out_four_no_cwe",
    3: "three_out_four_no_cwe",
    4: "four_out_four_no_cwe",
}
CLUSTER_RULES = (
    VOTE_KEYS[1],
    VOTE_KEYS[2],
    VOTE_KEYS[3],
    VOTE_KEYS[4],
    NO_CWE_VOTE_KEYS[2],
    NO_CWE_VOTE_KEYS[3],
    NO_CWE_VOTE_KEYS[4],
)
_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class FunctionSpan:
    filename: str
    name: str
    start_line: int
    end_line: int
    scope: str | None = None

    @property
    def identifier(self) -> str:
        name = f"{self.scope}::{self.name}" if self.scope else self.name
        return f"{self.filename}::{name}:{self.start_line}-{self.end_line}"

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


@dataclass(frozen=True)
class NormalizedFinding:
    tool: str
    filename: str
    line: int | None
    cwe: str
    function: str | None = None


@dataclass(frozen=True)
class FindingCluster:
    cluster_id: int
    rule: str
    tools: list[str]
    cwes: list[str]
    representative_cwe: str | None
    findings: list[NormalizedFinding]


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item: int) -> int:
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1


class CWEHierarchy:
    """In-memory CWE ancestor table used by the voting heuristic."""

    def __init__(self, child_of: dict[str, Iterable[str]]) -> None:
        self.child_of = {
            _normalize_cwe_id(child): tuple(_normalize_cwe_id(parent) for parent in parents)
            for child, parents in child_of.items()
        }
        self._ancestors_cache: dict[str, frozenset[str]] = {}

    @classmethod
    def from_xml(cls, xml_path: Path) -> "CWEHierarchy":
        from cwe_mapping.cwe_mapping import CWENavigator

        navigator = CWENavigator(str(xml_path))
        return cls(navigator.child_of)

    def ancestors(self, cwe: str) -> frozenset[str]:
        normalized = normalize_cwe(cwe)
        if normalized is None:
            return frozenset()
        cwe_id = _normalize_cwe_id(normalized)
        if cwe_id in self._ancestors_cache:
            return self._ancestors_cache[cwe_id]

        ancestors: set[str] = set()
        stack = list(self.child_of.get(cwe_id, ()))
        while stack:
            parent = stack.pop()
            if parent in ancestors:
                continue
            ancestors.add(parent)
            stack.extend(self.child_of.get(parent, ()))

        result = frozenset(ancestors)
        self._ancestors_cache[cwe_id] = result
        return result

    def are_related_or_same(self, left: str | None, right: str | None) -> bool:
        if left is None or right is None:
            return False
        left_id = _normalize_cwe_id(left)
        right_id = _normalize_cwe_id(right)
        if left_id == right_id:
            return True
        return left_id in self.ancestors(right) or right_id in self.ancestors(left)

    def representative(self, cwes: Iterable[str | None]) -> str | None:
        normalized = sorted({cwe for cwe in cwes if cwe is not None}, key=_cwe_sort_key)
        if not normalized:
            return None

        for candidate in normalized:
            candidate_id = _normalize_cwe_id(candidate)
            if all(
                candidate_id == _normalize_cwe_id(other)
                or candidate_id in self.ancestors(other)
                for other in normalized
            ):
                return candidate

        return None


def synthesize_class(
    class_name: str,
    *,
    outputs_root: Path = Path("outputs"),
    metadata_root: Path = Path("dataset_construction/metadata"),
    synthesis_root: Path = Path("synthesis"),
    cwe_xml: Path = Path("cwe_mapping/cwec_v4.20.xml"),
    dataset_root: Path = Path("dataset"),
) -> Path:
    metadata = _load_metadata(metadata_root / f"{class_name}_metadata.json")
    hierarchy = CWEHierarchy.from_xml(cwe_xml)

    class_output_root = outputs_root / class_name
    if not class_output_root.exists():
        raise FileNotFoundError(f"Output directory not found: {class_output_root}")

    class_synthesis_root = synthesis_root / class_name
    class_synthesis_root.mkdir(parents=True, exist_ok=True)

    synthesized = []
    for report_path in sorted(class_output_root.glob("*/report.json")):
        project = report_path.parent.name
        if project not in metadata:
            raise KeyError(f"Missing metadata for project '{project}' in class '{class_name}'")
        function_map = build_function_map(
            dataset_root / class_name / project,
            project=project,
            class_name=class_name,
        )
        findings = prepare_findings(
            _read_json(report_path),
            project=project,
            class_name=class_name,
            function_map=function_map,
        )
        clusters_by_rule = build_clusters_by_rule(findings, hierarchy)
        cluster_files = write_cluster_files(
            clusters_by_rule,
            class_synthesis_root=class_synthesis_root,
            project=project,
        )
        synthesized.append(
            {
                project: summarize_project_from_cluster_files(
                    metadata[project],
                    cluster_files,
                )
            }
        )

    output_path = synthesis_root / f"{class_name}.json"
    output_path.write_text(json.dumps(synthesized, indent=2) + "\n", encoding="utf-8")
    return output_path


def summarize_project(
    report: dict[str, object],
    metadata: dict[str, object],
    hierarchy: CWEHierarchy,
    *,
    project: str,
    class_name: str | None = None,
    function_map: dict[str, list[FunctionSpan]] | None = None,
) -> dict[str, object]:
    findings = prepare_findings(
        report,
        project=project,
        class_name=class_name,
        function_map=function_map,
    )
    clusters_by_rule = build_clusters_by_rule(findings, hierarchy)
    return summarize_project_from_clusters(metadata, clusters_by_rule)


def prepare_findings(
    report: dict[str, object],
    *,
    project: str,
    class_name: str | None = None,
    function_map: dict[str, list[FunctionSpan]] | None = None,
) -> list[NormalizedFinding]:
    findings = []
    for raw in report.get("findings", []):
        if not isinstance(raw, dict):
            continue
        finding = normalize_finding(
            raw,
            project=project,
            class_name=class_name,
            function_map=function_map,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def build_clusters_by_rule(
    findings: list[NormalizedFinding],
    hierarchy: CWEHierarchy,
) -> dict[str, list[FindingCluster]]:
    clusters_by_rule: dict[str, list[FindingCluster]] = {
        VOTE_KEYS[1]: [
            _cluster_from_indices(
                [index],
                findings,
                rule=VOTE_KEYS[1],
                hierarchy=hierarchy,
                representative_mode="representative",
            )
            for index in range(len(findings))
        ]
    }

    cwe_voted = vote_findings(findings, hierarchy)
    for threshold in (2, 3, 4):
        accepted = [cluster for cluster in cwe_voted if _tool_count(cluster, findings) >= threshold]
        clusters_by_rule[VOTE_KEYS[threshold]] = [
            _cluster_from_indices(
                cluster,
                findings,
                rule=VOTE_KEYS[threshold],
                hierarchy=hierarchy,
                representative_mode="representative",
                cluster_id=cluster_id,
            )
            for cluster_id, cluster in enumerate(accepted, start=1)
        ]

    no_cwe_voted = vote_findings(findings, hierarchy, require_related_cwe=False)
    for threshold in (2, 3, 4):
        accepted = [cluster for cluster in no_cwe_voted if _tool_count(cluster, findings) >= threshold]
        clusters_by_rule[NO_CWE_VOTE_KEYS[threshold]] = [
            _cluster_from_indices(
                cluster,
                findings,
                rule=NO_CWE_VOTE_KEYS[threshold],
                hierarchy=hierarchy,
                representative_mode="all_cwes",
                cluster_id=cluster_id,
            )
            for cluster_id, cluster in enumerate(accepted, start=1)
        ]

    return clusters_by_rule


def write_cluster_files(
    clusters_by_rule: dict[str, list[FindingCluster]],
    *,
    class_synthesis_root: Path,
    project: str,
) -> dict[str, Path]:
    class_synthesis_root.mkdir(parents=True, exist_ok=True)
    cluster_files = {}
    for rule in CLUSTER_RULES:
        path = class_synthesis_root / f"{project}_{rule}.json"
        payload = [_cluster_payload(cluster) for cluster in clusters_by_rule.get(rule, [])]
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        cluster_files[rule] = path
    return cluster_files


def summarize_project_from_cluster_files(
    metadata: dict[str, object],
    cluster_files: dict[str, Path],
) -> dict[str, object]:
    clusters_by_rule = {
        rule: _read_json(path)
        for rule, path in cluster_files.items()
    }
    return _summary_from_cluster_payloads(metadata, clusters_by_rule)


def summarize_project_from_clusters(
    metadata: dict[str, object],
    clusters_by_rule: dict[str, list[FindingCluster]],
) -> dict[str, object]:
    return _summary_from_cluster_payloads(
        metadata,
        {
            rule: [_cluster_payload(cluster) for cluster in clusters]
            for rule, clusters in clusters_by_rule.items()
        },
    )


def vote_findings(
    findings: list[NormalizedFinding],
    hierarchy: CWEHierarchy,
    *,
    require_related_cwe: bool = True,
) -> list[list[int]]:
    union_find = UnionFind(len(findings))
    indices_by_file: dict[str, list[int]] = defaultdict(list)
    for index, finding in enumerate(findings):
        indices_by_file[finding.filename].append(index)

    for indices in indices_by_file.values():
        indices_by_line: dict[int, list[int]] = defaultdict(list)
        indices_by_function: dict[str, list[int]] = defaultdict(list)
        for index in indices:
            finding = findings[index]
            if finding.line is not None:
                indices_by_line[finding.line].append(index)
            if finding.function is not None:
                indices_by_function[finding.function].append(index)

        for same_line_indices in indices_by_line.values():
            for left, right in combinations(same_line_indices, 2):
                if findings[left].tool != findings[right].tool:
                    union_find.union(left, right)

        for same_function_indices in indices_by_function.values():
            for left, right in combinations(same_function_indices, 2):
                if findings[left].tool == findings[right].tool:
                    continue
                if (
                    not require_related_cwe
                    or hierarchy.are_related_or_same(findings[left].cwe, findings[right].cwe)
                ):
                    union_find.union(left, right)

    clusters: dict[int, list[int]] = defaultdict(list)
    for index in range(len(findings)):
        clusters[union_find.find(index)].append(index)
    return list(clusters.values())


def normalize_finding(
    raw: dict[str, object],
    *,
    project: str,
    class_name: str | None = None,
    function_map: dict[str, list[FunctionSpan]] | None = None,
) -> NormalizedFinding | None:
    cwe = normalize_cwe(raw.get("cwe"))
    if cwe is None:
        return None
    filename = normalize_path(str(raw.get("filename", "")), project=project, class_name=class_name)
    line = _normalize_line(raw.get("line"))
    return NormalizedFinding(
        tool=str(raw.get("tool", "")).lower(),
        filename=filename,
        line=line,
        cwe=cwe,
        function=find_function(function_map or {}, filename, line),
    )


def build_function_map(
    source_root: Path,
    *,
    project: str,
    class_name: str | None = None,
) -> dict[str, list[FunctionSpan]]:
    if not source_root.exists():
        return {}

    try:
        ctags_bin = resolve_universal_ctags()
    except CtagsResolutionError as error:
        raise RuntimeError(str(error)) from error

    command = [
        ctags_bin,
        "-R",
        "--languages=C,C++",
        "--kinds-C=f",
        "--kinds-C++=f",
        "--fields=+ne",
        "--output-format=json",
        "-f",
        "-",
        str(source_root),
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except FileNotFoundError as error:
        raise RuntimeError(str(error)) from error
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise RuntimeError(f"ctags failed for {source_root}{detail}") from error

    function_map: dict[str, list[FunctionSpan]] = defaultdict(list)
    for line in result.stdout.splitlines():
        try:
            tag = json.loads(line)
        except json.JSONDecodeError:
            continue
        span = _function_span_from_tag(tag, project=project, class_name=class_name)
        if span is not None:
            function_map[span.filename].append(span)

    for spans in function_map.values():
        spans.sort(key=lambda span: (span.start_line, span.end_line, span.name))
    return dict(function_map)


def find_function(
    function_map: dict[str, list[FunctionSpan]],
    filename: str,
    line: int | None,
) -> str | None:
    if line is None:
        return None
    containing = [span for span in function_map.get(filename, []) if span.contains(line)]
    if not containing:
        return None
    span = min(containing, key=lambda item: (item.end_line - item.start_line, item.start_line))
    return span.identifier


def normalize_path(path: str, *, project: str, class_name: str | None = None) -> str:
    normalized = path.replace("\\", "/").strip()
    if normalized.startswith("file://"):
        normalized = normalized[7:]

    marker_prefixes = ["/workspace/"]
    if class_name:
        marker_prefixes.append(f"/dataset/{class_name}/{project}/")
    marker_prefixes.append(f"/{project}/")

    for marker in marker_prefixes:
        if marker in normalized:
            normalized = normalized.rsplit(marker, 1)[1]
            break

    if normalized.startswith("/workspace"):
        normalized = normalized[len("/workspace") :]
    normalized = normalized.lstrip("/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith(f"{project}/"):
        normalized = normalized[len(project) + 1 :]

    normalized = posixpath.normpath(normalized)
    return "" if normalized == "." else normalized


def normalize_cwe(value: object) -> str | None:
    if value is None:
        return None
    match = _CWE_RE.search(str(value))
    if not match:
        return None
    return format_cwe_id(match.group(1))


def format_cwe_id(cwe_id: str) -> str:
    return f"CWE-{_normalize_cwe_id(cwe_id).zfill(3)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="synthesize-results",
        description="Synthesize static-analysis report.json files into synthesis/<class>.json.",
    )
    parser.add_argument("class_name", help="dataset class to synthesize, e.g. kernel")
    parser.add_argument("--outputs-root", type=Path, default=Path("outputs"))
    parser.add_argument("--metadata-root", type=Path, default=Path("dataset_construction/metadata"))
    parser.add_argument("--synthesis-root", type=Path, default=Path("synthesis"))
    parser.add_argument("--cwe-xml", type=Path, default=Path("cwe_mapping/cwec_v4.20.xml"))
    parser.add_argument("--dataset-root", type=Path, default=Path("dataset"))
    args = parser.parse_args(argv)

    output_path = synthesize_class(
        args.class_name,
        outputs_root=args.outputs_root,
        metadata_root=args.metadata_root,
        synthesis_root=args.synthesis_root,
        cwe_xml=args.cwe_xml,
        dataset_root=args.dataset_root,
    )
    print(output_path)
    return 0


def _cluster_from_indices(
    indices: list[int],
    findings: list[NormalizedFinding],
    *,
    rule: str,
    hierarchy: CWEHierarchy,
    representative_mode: str,
    cluster_id: int | None = None,
) -> FindingCluster:
    ordered_indices = sorted(
        indices,
        key=lambda index: (
            findings[index].filename,
            findings[index].line or -1,
            findings[index].tool,
            findings[index].cwe,
        ),
    )
    cluster_findings = [findings[index] for index in ordered_indices]
    cwes = sorted({finding.cwe for finding in cluster_findings}, key=_cwe_sort_key)
    representative_cwe = hierarchy.representative(cwes) if representative_mode == "representative" else None
    return FindingCluster(
        cluster_id=cluster_id if cluster_id is not None else ordered_indices[0] + 1,
        rule=rule,
        tools=sorted({finding.tool for finding in cluster_findings}),
        cwes=cwes,
        representative_cwe=representative_cwe,
        findings=cluster_findings,
    )


def _cluster_payload(cluster: FindingCluster) -> dict[str, object]:
    return {
        "cluster_id": cluster.cluster_id,
        "rule": cluster.rule,
        "tools": cluster.tools,
        "cwes": cluster.cwes,
        "representative_cwe": cluster.representative_cwe,
        "findings": [asdict(finding) for finding in cluster.findings],
    }


def _function_span_from_tag(
    tag: dict[str, object],
    *,
    project: str,
    class_name: str | None = None,
) -> FunctionSpan | None:
    if tag.get("_type") != "tag" or tag.get("kind") != "function":
        return None
    start = _normalize_line(tag.get("line"))
    end = _normalize_line(tag.get("end")) or start
    name = str(tag.get("name", "")).strip()
    path = str(tag.get("path", "")).strip()
    if start is None or end is None or not name or not path:
        return None
    filename = normalize_path(path, project=project, class_name=class_name)
    scope = str(tag.get("scope", "")).strip() or None
    return FunctionSpan(
        filename=filename,
        name=name,
        start_line=start,
        end_line=max(start, end),
        scope=scope,
    )


def _summary_from_cluster_payloads(
    metadata: dict[str, object],
    clusters_by_rule: dict[str, list[dict[str, object]]],
) -> dict[str, object]:
    summary: dict[str, object] = {
        "LOC": int(metadata.get("LOC", metadata.get("loc", 0))),
        "functions": int(metadata.get("functions", 0)),
        "hits_per_tool": _hits_per_tool_from_one_out_of_four(clusters_by_rule.get(VOTE_KEYS[1], [])),
    }

    for rule in (VOTE_KEYS[1], VOTE_KEYS[2], VOTE_KEYS[3], VOTE_KEYS[4]):
        summary[rule] = _summary_from_rule_clusters(
            clusters_by_rule.get(rule, []),
            prefer_representative=True,
        )
    for rule in (NO_CWE_VOTE_KEYS[2], NO_CWE_VOTE_KEYS[3], NO_CWE_VOTE_KEYS[4]):
        summary[rule] = _summary_from_rule_clusters(
            clusters_by_rule.get(rule, []),
            prefer_representative=False,
        )
    return summary


def _summary_from_rule_clusters(
    clusters: list[dict[str, object]],
    *,
    prefer_representative: bool,
) -> dict[str, object]:
    counts: Counter[str] = Counter()
    for cluster in clusters:
        representative = cluster.get("representative_cwe")
        if prefer_representative and isinstance(representative, str):
            counts.update([representative])
        else:
            counts.update(cwe for cwe in cluster.get("cwes", []) if isinstance(cwe, str))
    return {
        "unique_cwes": sorted(counts, key=_cwe_sort_key),
        "tot_vulns": len(clusters),
        "vulns_per_cwe": dict(sorted(counts.items(), key=lambda item: _cwe_sort_key(item[0]))),
    }


def _hits_per_tool_from_one_out_of_four(clusters: list[dict[str, object]]) -> dict[str, int]:
    hits_per_tool = {tool: 0 for tool in TOOLS}
    for cluster in clusters:
        findings = cluster.get("findings", [])
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            tool = finding.get("tool")
            if isinstance(tool, str) and tool in hits_per_tool:
                hits_per_tool[tool] += 1
    return hits_per_tool


def _tool_count(cluster: list[int], findings: list[NormalizedFinding]) -> int:
    return len({findings[index].tool for index in cluster})


def _normalize_line(value: object) -> int | None:
    if value is None:
        return None
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _normalize_cwe_id(cwe: str) -> str:
    match = _CWE_RE.search(str(cwe))
    raw = match.group(1) if match else str(cwe)
    stripped = raw.strip().removeprefix("CWE-").removeprefix("cwe-").lstrip("0")
    return stripped or "0"


def _cwe_sort_key(cwe: str) -> tuple[int, str]:
    cwe_id = _normalize_cwe_id(cwe)
    return (int(cwe_id) if cwe_id.isdigit() else 10**9, cwe_id)


def _read_json(path: Path) -> dict[str, object] | list[dict[str, object]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_metadata(path: Path) -> dict[str, dict[str, object]]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return {}
    return {str(project): value for project, value in data.items() if isinstance(value, dict)}


if __name__ == "__main__":
    raise SystemExit(main())

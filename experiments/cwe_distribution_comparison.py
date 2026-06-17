#!/usr/bin/env python3
"""Compare two_out_of_four CWE distributions between kernel and application."""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import statistics
import sys
import textwrap
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import numpy as np
from scipy.stats import mannwhitneyu as scipy_mannwhitneyu


CRITERION = "two_out_of_four"
CWE_VIEW_1000 = "1000"
# CWE-1435: "Weaknesses in the 2025 CWE Top 25 Most Dangerous Software
# Weaknesses". Present from catalog v4.20 onwards (v4.18 only had the 2024 list).
CWE_VIEW_TOP25_2025 = "1435"
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
DEFAULT_ALPHA = 0.05
DEFAULT_BOOTSTRAP = 2_000
CLIFF_THRESHOLDS = (0.147, 0.33, 0.474)
UNKNOWN_ROOT = "UNKNOWN"


@dataclass(frozen=True)
class CweInfo:
    cwe_id: str
    name: str
    root_id: str
    root_name: str


@dataclass(frozen=True)
class Comparison:
    group_id: str
    group_name: str
    mann_whitney_u: float
    p_value: float
    p_value_ci: tuple[float, float]
    q_value: float
    cliffs_delta: float
    cliffs_delta_ci: tuple[float, float]
    delta_interpretation: str
    dominance: str
    kernel_mean_pct: float
    application_mean_pct: float


def main() -> int:
    args = parse_args()
    synthesis_dir = args.synthesis_dir
    cwe_xml = args.cwe_xml

    if not synthesis_dir.is_dir():
        print(f"synthesis directory not found: {synthesis_dir}", file=sys.stderr)
        return 1
    if not cwe_xml.is_file():
        print(f"CWE XML not found: {cwe_xml}", file=sys.stderr)
        return 1

    cwe_catalog = load_cwe_catalog(cwe_xml)
    top25_2025 = load_top25_2025(cwe_xml)

    kernel, kernel_projects = load_class_percentages(synthesis_dir / "kernel.json")
    application, application_projects = load_class_percentages(synthesis_dir / "application.json")
    # Mann-Whitney/Cliff's delta only make sense for CWEs observed in both
    # domains; class-exclusive CWEs are covered separately by
    # print_unique_cwe_analysis (comparing against an all-zero vector would
    # be a degenerate presence/absence test, not a distribution comparison).
    cwe_ids = sorted(set(kernel) & set(application), key=cwe_sort_key)
    cwe_comparisons = build_comparisons(
        cwe_ids,
        kernel,
        application,
        name_for=lambda cwe_id: cwe_catalog.get(
            cwe_id, CweInfo(cwe_id, "Unknown", UNKNOWN_ROOT, "Unknown")
        ).name,
        n_boot=args.bootstrap,
    )
    if args.significant:
        cwe_comparisons = [item for item in cwe_comparisons if item.p_value < args.alpha]

    # Per-CWE-root analysis: aggregating CWEs that share a CWE-1000 root
    # category collapses the zero-inflation that affects rare individual
    # CWEs (see print_unique_cwe_analysis discussion), trading granularity
    # for statistical power. Complements, does not replace, the per-CWE table.
    kernel_roots, _ = load_class_root_percentages(synthesis_dir / "kernel.json", cwe_catalog)
    application_roots, _ = load_class_root_percentages(
        synthesis_dir / "application.json", cwe_catalog
    )
    root_ids = sorted(set(kernel_roots) & set(application_roots), key=cwe_sort_key)
    root_comparisons = build_comparisons(
        root_ids,
        kernel_roots,
        application_roots,
        name_for=lambda root_id: cwe_catalog.get(
            root_id, CweInfo(root_id, "Unknown", root_id, "Unknown")
        ).name,
        n_boot=args.bootstrap,
    )
    if args.significant:
        root_comparisons = [item for item in root_comparisons if item.p_value < args.alpha]

    print_unique_cwe_analysis(
        kernel, application, kernel_projects, application_projects, cwe_catalog, top25_2025
    )
    print()
    print_comparisons_table(
        f"Per-CWE comparison ({len(cwe_comparisons)} CWEs shared between domains)", cwe_comparisons
    )
    print()
    print_comparisons_table(
        f"Per-CWE-root comparison ({len(root_comparisons)} CWE-1000 categories shared between domains)",
        root_comparisons,
    )

    if args.csv:
        write_comparisons_csv(args.csv, cwe_comparisons)
        print()
        print(f"CSV written to {args.csv}")
    if args.root_csv:
        write_comparisons_csv(args.root_csv, root_comparisons)
        print()
        print(f"CSV written to {args.root_csv}")

    return 0


def print_unique_cwe_analysis(
    kernel: dict[str, list[float]],
    application: dict[str, list[float]],
    kernel_projects: int,
    application_projects: int,
    catalog: dict[str, CweInfo],
    top25_2025: set[str],
) -> None:
    k_cwes = set(kernel)
    a_cwes = set(application)
    only_kernel = sorted(k_cwes - a_cwes, key=cwe_sort_key)
    only_application = sorted(a_cwes - k_cwes, key=cwe_sort_key)
    common = sorted(k_cwes & a_cwes, key=cwe_sort_key)

    # How many of each class's unique CWEs land in the 2025 MITRE Top 25.
    k_top25 = sorted(k_cwes & top25_2025, key=cwe_sort_key)
    a_top25 = sorted(a_cwes & top25_2025, key=cwe_sort_key)

    def top25_cell(hits: list[str]) -> str:
        if not top25_2025:
            return "n/a"
        return f"{len(hits)}/{len(top25_2025)}"

    print("Unique CWE analysis (two_out_of_four, deduplicated across projects)")
    print(
        format_table(
            ["", "kernel", "application"],
            [
                ["projects", str(kernel_projects), str(application_projects)],
                ["unique CWEs", str(len(k_cwes)), str(len(a_cwes))],
                ["union", str(len(k_cwes | a_cwes)), ""],
                ["intersection", str(len(common)), ""],
                ["exclusive CWEs", str(len(only_kernel)), str(len(only_application))],
                ["in 2025 Top 25", top25_cell(k_top25), top25_cell(a_top25)],
            ],
        )
    )

    def cwe_label(cwe_id: str) -> str:
        info = catalog.get(cwe_id)
        return f"{cwe_id} ({info.name})" if info else cwe_id

    if not top25_2025:
        print(
            "\n  Note: the CWE catalog has no 2025 Top 25 view (CWE-1435); "
            "Top 25 overlap reported as n/a."
        )
    else:
        print(
            f"\n  2025 MITRE Top 25 coverage (of {len(top25_2025)} ranked weaknesses):"
        )
        print(f"    kernel: {len(k_top25)} present")
        for cwe_id in k_top25:
            print(f"      {cwe_label(cwe_id)}")
        print(f"    application: {len(a_top25)} present")
        for cwe_id in a_top25:
            print(f"      {cwe_label(cwe_id)}")

    if only_kernel:
        print(f"\n  CWEs exclusive to kernel ({len(only_kernel)}):")
        for cwe_id in only_kernel:
            print(f"    {cwe_label(cwe_id)}")

    if only_application:
        print(f"\n  CWEs exclusive to application ({len(only_application)}):")
        for cwe_id in only_application:
            print(f"    {cwe_label(cwe_id)}")

    if common:
        print(f"\n  CWEs in common ({len(common)}): {', '.join(common)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare project-level CWE percentage distributions between kernel "
            "and application using Mann-Whitney U and Cliff's delta."
        )
    )
    parser.add_argument(
        "--synthesis-dir",
        type=Path,
        default=Path("synthesis"),
        help="directory containing kernel.json and application.json",
    )
    parser.add_argument(
        "--cwe-xml",
        type=Path,
        default=Path("cwe_mapping/cwec_v4.20.xml"),
        help="MITRE CWE catalog XML used for names and CWE-1000 roots",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("experiments/csv/cwe_distribution_comparison.csv"),
        help="optional CSV output path for the per-CWE comparison",
    )
    parser.add_argument(
        "--root-csv",
        type=Path,
        default=Path("experiments/csv/cwe_root_distribution_comparison.csv"),
        help="optional CSV output path for the per-CWE-root comparison",
    )
    parser.add_argument(
        "--significant",
        action="store_true",
        help="print and export only entries with p-value below --alpha",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=DEFAULT_ALPHA,
        help=f"significance threshold used by --significant (default: {DEFAULT_ALPHA})",
    )
    parser.add_argument(
        "--bootstrap",
        type=int,
        default=DEFAULT_BOOTSTRAP,
        help=(
            "number of percentile-bootstrap resamples used for the p-value and "
            f"Cliff's delta confidence intervals (default: {DEFAULT_BOOTSTRAP})"
        ),
    )
    return parser.parse_args()


def load_class_distributions(path: Path) -> tuple[list[dict[str, int]], list[int]]:
    """Per-project raw CWE counts (normalized ids) and total vuln count.

    Shared by load_class_percentages (per-CWE) and load_class_root_percentages
    (per-CWE-1000-category); projects with no usable data get an empty count
    dict and a total of 0, so percentages default to 0.0 rather than being
    dropped (keeping per-class sample size consistent across CWEs/roots).
    """
    payload = load_json(path, default=[])
    project_counts: list[dict[str, int]] = []
    project_totals: list[int] = []

    if not isinstance(payload, list):
        return project_counts, project_totals

    for item in payload:
        if not isinstance(item, dict) or len(item) != 1:
            continue
        _, values = next(iter(item.items()))
        if not isinstance(values, dict):
            continue
        criterion = values.get(CRITERION)
        if not isinstance(criterion, dict):
            continue
        total = criterion.get("tot_vulns")
        per_cwe = criterion.get("vulns_per_cwe")
        if not isinstance(total, int) or total <= 0 or not isinstance(per_cwe, dict):
            project_counts.append({})
            project_totals.append(0)
            continue

        counts: dict[str, int] = {}
        for cwe_id, count in per_cwe.items():
            if isinstance(cwe_id, str) and isinstance(count, int):
                normalized = normalize_cwe_id(cwe_id)
                counts[normalized] = counts.get(normalized, 0) + count
        project_counts.append(counts)
        project_totals.append(total)

    return project_counts, project_totals


def load_class_percentages(path: Path) -> tuple[dict[str, list[float]], int]:
    counts, totals = load_class_distributions(path)
    all_cwes: set[str] = set()
    for project_counts in counts:
        all_cwes.update(project_counts)

    distributions = {
        cwe_id: [
            (project_counts.get(cwe_id, 0) / total * 100) if total > 0 else 0.0
            for project_counts, total in zip(counts, totals)
        ]
        for cwe_id in all_cwes
    }
    return distributions, len(counts)


def load_class_root_percentages(
    path: Path, catalog: dict[str, CweInfo]
) -> tuple[dict[str, list[float]], int]:
    counts, totals = load_class_distributions(path)

    project_root_counts: list[dict[str, int]] = []
    all_roots: set[str] = set()
    for project_counts in counts:
        per_root: dict[str, int] = {}
        for cwe_id, count in project_counts.items():
            root_id = catalog[cwe_id].root_id if cwe_id in catalog else UNKNOWN_ROOT
            per_root[root_id] = per_root.get(root_id, 0) + count
        project_root_counts.append(per_root)
        all_roots.update(per_root)

    distributions = {
        root_id: [
            (per_root.get(root_id, 0) / total * 100) if total > 0 else 0.0
            for per_root, total in zip(project_root_counts, totals)
        ]
        for root_id in all_roots
    }
    return distributions, len(counts)


def load_json(path: Path, *, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        with path.open(encoding="utf-8") as json_file:
            return json.load(json_file)
    except (OSError, json.JSONDecodeError):
        return default


def load_top25_2025(path: Path) -> set[str]:
    """Normalized CWE ids that make up the 2025 CWE Top 25 (view CWE-1435).

    Returns an empty set if the catalog predates the 2025 list (e.g. v4.18),
    so callers degrade to reporting zero overlaps rather than crashing.
    """
    root = ET.parse(path).getroot()
    view = root.find(f".//cwe:View[@ID='{CWE_VIEW_TOP25_2025}']", NS)
    if view is None:
        return set()
    members: set[str] = set()
    for member in view.findall(".//cwe:Members/cwe:Has_Member", NS):
        cwe_id = member.get("CWE_ID")
        if cwe_id:
            members.add(normalize_cwe_id(cwe_id))
    return members


def load_cwe_catalog(path: Path) -> dict[str, CweInfo]:
    tree = ET.parse(path)
    root = tree.getroot()

    names: dict[str, str] = {}
    members: dict[str, list[str]] = {}
    parents: dict[str, list[str]] = {}

    for tag in ("Weakness", "Category"):
        for element in root.findall(f".//cwe:{tag}", NS):
            cwe_id = element.get("ID")
            if not cwe_id:
                continue
            names[cwe_id] = element.get("Name") or "Unknown"
            for related in element.findall(".//cwe:Related_Weakness", NS):
                if related.get("Nature") == "ChildOf" and related.get("View_ID") == CWE_VIEW_1000:
                    parent = related.get("CWE_ID")
                    if parent:
                        parents.setdefault(cwe_id, []).append(parent)
            for member in element.findall(".//cwe:Relationships/cwe:Has_Member", NS):
                child = member.get("CWE_ID")
                if child:
                    members.setdefault(cwe_id, []).append(child)
                    parents.setdefault(child, []).append(cwe_id)

    view_members: list[str] = []
    view = root.find(f".//cwe:View[@ID='{CWE_VIEW_1000}']", NS)
    if view is not None:
        for member in view.findall(".//cwe:Members/cwe:Has_Member", NS):
            cwe_id = member.get("CWE_ID")
            if cwe_id:
                view_members.append(cwe_id)

    root_by_cwe: dict[str, str] = {}
    for view_member in view_members:
        assign_root(view_member, view_member, members, root_by_cwe)

    catalog: dict[str, CweInfo] = {}
    for cwe_id, name in names.items():
        root_id = root_by_cwe.get(cwe_id) or climb_to_view_root(cwe_id, set(view_members), parents)
        catalog[f"CWE-{int(cwe_id):03d}"] = CweInfo(
            cwe_id=f"CWE-{int(cwe_id):03d}",
            name=name,
            root_id=f"CWE-{int(root_id):03d}" if root_id else UNKNOWN_ROOT,
            root_name=names.get(root_id, "Unknown") if root_id else "Unknown",
        )
    return catalog


def assign_root(
    cwe_id: str,
    root_id: str,
    members: dict[str, list[str]],
    root_by_cwe: dict[str, str],
) -> None:
    if cwe_id in root_by_cwe:
        return
    root_by_cwe[cwe_id] = root_id
    for child in members.get(cwe_id, []):
        assign_root(child, root_id, members, root_by_cwe)


def climb_to_view_root(
    cwe_id: str, view_members: set[str], parents: dict[str, list[str]]
) -> str | None:
    current = cwe_id
    visited: set[str] = set()
    while current and current not in visited:
        visited.add(current)
        if current in view_members:
            return current
        next_parents = parents.get(current, [])
        current = next_parents[0] if next_parents else None
    return None


def build_comparisons(
    ids: list[str],
    kernel_dist: dict[str, list[float]],
    application_dist: dict[str, list[float]],
    name_for: Callable[[str], str],
    n_boot: int,
) -> list[Comparison]:
    """Mann-Whitney U + Cliff's delta for each id, with bootstrap CIs and a
    Benjamini-Yekutieli q-value computed jointly across the whole id list
    (the q-value depends on the full set of p-values, so it must be
    computed once all of them are known, not per id)."""
    raw: list[tuple[str, str, float, float, tuple[float, float], float, tuple[float, float], float, float]] = []
    for group_id in ids:
        kernel_values = kernel_dist[group_id]
        application_values = application_dist[group_id]
        test = scipy_mannwhitneyu(
            kernel_values, application_values, alternative="two-sided", method="asymptotic"
        )
        delta = cliffs_delta(kernel_values, application_values)
        p_ci, delta_ci = _bootstrap_mw_ci(kernel_values, application_values, n_boot=n_boot)
        raw.append(
            (
                group_id,
                name_for(group_id),
                float(test.statistic),
                float(test.pvalue),
                p_ci,
                delta,
                delta_ci,
                statistics.fmean(kernel_values),
                statistics.fmean(application_values),
            )
        )

    q_values = _benjamini_yekutieli([item[3] for item in raw])
    comparisons = [
        Comparison(
            group_id=group_id,
            group_name=group_name,
            mann_whitney_u=u_stat,
            p_value=p_value,
            p_value_ci=p_ci,
            q_value=q_value,
            cliffs_delta=delta,
            cliffs_delta_ci=delta_ci,
            delta_interpretation=interpret_cliffs_delta(delta),
            dominance=dominance(delta),
            kernel_mean_pct=kernel_mean,
            application_mean_pct=application_mean,
        )
        for (group_id, group_name, u_stat, p_value, p_ci, delta, delta_ci, kernel_mean, application_mean), q_value
        in zip(raw, q_values)
    ]
    comparisons.sort(key=lambda item: (item.p_value, -abs(item.cliffs_delta), item.group_id))
    return comparisons


def _bootstrap_mw_ci(
    kernel_values: list[float],
    application_values: list[float],
    n_boot: int,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[tuple[float, float], tuple[float, float]]:
    """Percentile bootstrap CI for the Mann-Whitney p-value and Cliff's delta.

    Resamples projects with replacement independently within each class and
    recomputes both statistics. With small/zero-inflated samples (e.g. 7
    kernel projects) both statistics are highly discrete, so this CI shows
    how much the point estimates would move under resampling, rather than
    relying on a single asymptotic value.
    """
    rng = np.random.default_rng(seed)
    kernel_arr = np.asarray(kernel_values, dtype=float)
    application_arr = np.asarray(application_values, dtype=float)
    n_kernel, n_application = len(kernel_arr), len(application_arr)
    p_samples = np.empty(n_boot)
    delta_samples = np.empty(n_boot)
    for i in range(n_boot):
        kernel_sample = kernel_arr[rng.integers(0, n_kernel, size=n_kernel)]
        application_sample = application_arr[rng.integers(0, n_application, size=n_application)]
        _, p_samples[i] = scipy_mannwhitneyu(
            kernel_sample, application_sample, alternative="two-sided", method="asymptotic"
        )
        delta_samples[i] = cliffs_delta(list(kernel_sample), list(application_sample))
    return _percentile_ci(p_samples, alpha), _percentile_ci(delta_samples, alpha)


def _percentile_ci(samples: np.ndarray, alpha: float) -> tuple[float, float]:
    valid = samples[~np.isnan(samples)]
    if valid.size == 0:
        return float("nan"), float("nan")
    low, high = np.percentile(valid, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(low), float(high)


def _benjamini_yekutieli(pvalues: list[float]) -> list[float]:
    """Benjamini-Yekutieli FDR-adjusted p-values (q-values).

    Unlike the simpler Benjamini-Hochberg procedure, BY stays valid under
    arbitrary dependence between tests. That matters here because per-CWE
    (or per-root) percentages within the same project are compositional
    (they sum to 100% per project), so the tests are not independent.
    """
    m = len(pvalues)
    if m == 0:
        return []
    harmonic_number = sum(1.0 / i for i in range(1, m + 1))
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running_min = 1.0
    for rank in range(m, 0, -1):
        idx = order[rank - 1]
        candidate = pvalues[idx] * harmonic_number * m / rank
        running_min = min(running_min, candidate, 1.0)
        adjusted[idx] = running_min
    return adjusted


def cliffs_delta(x_values: list[float], y_values: list[float]) -> float:
    greater = 0
    lower = 0
    for x_value in x_values:
        for y_value in y_values:
            if x_value > y_value:
                greater += 1
            elif x_value < y_value:
                lower += 1
    return (greater - lower) / (len(x_values) * len(y_values))


def dominance(delta: float) -> str:
    if delta > 0:
        return "kernel"
    if delta < 0:
        return "application"
    return "tie"


def interpret_cliffs_delta(delta: float) -> str:
    magnitude = abs(delta)
    if magnitude < CLIFF_THRESHOLDS[0]:
        return "negligible"
    if magnitude < CLIFF_THRESHOLDS[1]:
        return "small"
    if magnitude < CLIFF_THRESHOLDS[2]:
        return "medium"
    return "large"


def print_comparisons_table(title: str, comparisons: list[Comparison]) -> None:
    rows = [
        [
            item.group_id,
            shorten(item.group_name, 60),
            f"{item.mann_whitney_u:.3f}",
            f"{item.p_value:.6g}",
            f"[{item.p_value_ci[0]:.4g}, {item.p_value_ci[1]:.4g}]",
            f"{item.q_value:.6g}",
            f"{item.cliffs_delta:.4f}",
            f"[{item.cliffs_delta_ci[0]:.4f}, {item.cliffs_delta_ci[1]:.4f}]",
            item.delta_interpretation,
            item.dominance,
        ]
        for item in comparisons
    ]
    print(title)
    print(
        format_table(
            [
                "ID",
                "Name",
                "Mann-Whitney U",
                "p-value",
                "95% CI (p)",
                "q-value (BY)",
                "Cliff's delta",
                "95% CI (delta)",
                "Interpretation",
                "Dominance",
            ],
            rows,
        )
    )


def write_comparisons_csv(path: Path, comparisons: list[Comparison]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                "ID",
                "Name",
                "Mann-Whitney U",
                "p-value",
                "p-value CI low",
                "p-value CI high",
                "q-value (BY)",
                "Cliff's delta",
                "delta CI low",
                "delta CI high",
                "Cliff's interpretation",
                "Dominance",
                "kernel mean %",
                "application mean %",
            ]
        )
        for item in comparisons:
            writer.writerow(
                [
                    item.group_id,
                    item.group_name,
                    f"{item.mann_whitney_u:.6f}",
                    f"{item.p_value:.12g}",
                    f"{item.p_value_ci[0]:.12g}",
                    f"{item.p_value_ci[1]:.12g}",
                    f"{item.q_value:.12g}",
                    f"{item.cliffs_delta:.6f}",
                    f"{item.cliffs_delta_ci[0]:.6f}",
                    f"{item.cliffs_delta_ci[1]:.6f}",
                    item.delta_interpretation,
                    item.dominance,
                    f"{item.kernel_mean_pct:.6f}",
                    f"{item.application_mean_pct:.6f}",
                ]
            )


def shorten(value: str, max_chars: int) -> str:
    value = " ".join(value.split())
    if len(value) <= max_chars:
        return value
    return textwrap.shorten(value, width=max_chars, placeholder="...")


def format_table(header: list[str], rows: list[list[str]]) -> str:
    widths = [
        max(len(row[column]) for row in [header, *rows])
        for column in range(len(header))
    ]
    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    lines = [separator, table_row(header, widths), separator]
    lines.extend(table_row(row, widths) for row in rows)
    lines.append(separator)
    return "\n".join(lines)


def table_row(row: list[str], widths: list[int]) -> str:
    cells = [f" {cell:<{width}} " for cell, width in zip(row, widths, strict=True)]
    return "|" + "|".join(cells) + "|"


def normalize_cwe_id(cwe_id: str) -> str:
    suffix = cwe_id.removeprefix("CWE-")
    return f"CWE-{int(suffix):03d}" if suffix.isdigit() else cwe_id


def cwe_sort_key(cwe_id: str) -> tuple[int, str]:
    suffix = cwe_id.removeprefix("CWE-")
    return (int(suffix), cwe_id) if suffix.isdigit() else (10**9, cwe_id)


if __name__ == "__main__":
    raise SystemExit(main())

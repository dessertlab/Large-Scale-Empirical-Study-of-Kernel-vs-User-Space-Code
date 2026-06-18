# Large-Scale Empirical Study of Kernel vs. User-Space C/C++ Code

This repository contains all data and artifacts, including source code and datasets, supporting the results of the paper titled "*Is Privileged Code Safer? A Large-Scale Static-Analysis Study of Kernel vs. User-Space C/C++ Code*" submitted to the IEEE International Conference on Source Code Analysis & Manipulation (SCAM 2026), co-located with the 42nd International Conference on Software Maintenance and Evolution (ICSME 2026).


This repository builds a curated C/C++ dataset, runs a container-based static-analysis pipeline over every downloaded project, and synthesizes the analyzer findings into per-class summaries. It is organized around three steps:

1. dataset construction, handled by `dataset_construction/`
2. static analysis execution, handled by `static_analysis/`
3. post-processing and synthesis, handled by `static_analysis/synthesis.py`

For the full workflow, use the root-level shell scripts described below.

## Repository Structure

```text
.
├── README.md                   # project overview and full workflow guide
├── config.toml                 # static-analysis tool configuration
├── init_sats.sh                # builds the analyzer Docker images
├── run.sh                      # builds the dataset, analyzes projects, then synthesizes results (resumable & self-healing; supports --skip-dataset, --force, --jobs, --class, --report-failed, --rerun-failed)
├── cwe_mapping/                # CWE hierarchy utilities used during synthesis
├── dataset_construction/       # dataset download, filtering, and metadata generation
│   ├── README.md               # dataset-only usage guide
│   ├── build_dataset.py        # dataset construction entrypoint
│   ├── config.py               # C/C++ extensions and excluded directories
│   ├── metadata/               # generated per-class metadata
│   └── src/                    # project lists grouped by class
├── static_analysis/            # analyzer CLI, orchestration, runners, and Dockerfiles
│   ├── README.md               # analysis and synthesis usage guide
│   ├── cli.py                  # `static-analysis` command entrypoint
│   ├── pipeline.py             # tool orchestration
│   ├── runners/                # analyzer-specific implementations
│   └── docker/tools/           # analyzer Dockerfiles
├── tests/                      # unit tests and C/C++ fixture projects
├── experiments/                # post-hoc experimental analyses and generated figures/tables
│   ├── print_findings_tables.py # per-tool finding count tables + tools.txt totals
│   ├── csv/                    # generated CSV outputs
│   ├── plots/                  # generated PNG/SVG figures
│   └── txt/                    # generated text outputs (e.g. tools.txt)
├── dataset/                    # generated dataset output
├── outputs/                    # generated analysis reports
└── synthesis/                  # generated cluster files and final synthesis reports
```

`dataset/`, `outputs/`, and `synthesis/` are generated directories. They are created or updated by `run.sh` and by the lower-level commands documented in the module READMEs.

## Requirements

- Linux, WSL2, or macOS
- Python 3.11+
- `uv`
- Docker
- Git
- Bash (the macOS system bash 3.2 is enough for the normal sequential run;
  only `run.sh --jobs N` with `N > 1` needs bash 4.3+ for `wait -n`)
- Universal Ctags, required by dataset construction and function-level synthesis
  (`brew install universal-ctags` on macOS; the `universal-ctags` package on
  Debian/Ubuntu)

### Platform notes

The analyzers run inside Docker Linux containers, so their behaviour is identical
on Linux and macOS. Two host-level differences are worth keeping in mind:

- **CodeQL on Apple Silicon.** The CodeQL bundle is published only for `linux/amd64`,
  so its image is pinned to that platform (see `init_sats.sh` and `config.toml`).
  It runs correctly on arm64 Macs but under emulation, which is significantly
  slower than native amd64 Linux — hence the long `timeout_seconds` for CodeQL.
- **Filesystem case sensitivity.** macOS (APFS) is case-insensitive by default while
  most Linux filesystems are case-sensitive. The project code is unaffected, but a
  downloaded dataset that contains source files differing only in letter case may
  resolve differently on the two systems.
- **Docker memory on macOS.** On Linux, containers can use the host's full RAM; on
  macOS, Docker runs in a VM (Docker Desktop, OrbStack, Colima, ...) with its own
  fixed memory limit. If that limit is below CodeQL's RAM budget, CodeQL is
  OOM-killed (exit 137) on large projects. `run.sh` guards against this by sizing
  CodeQL from the daemon's reported memory (`docker info`), not host RAM — but make
  sure the VM's memory limit is large enough (e.g. raise it to ~32 GB on a 48 GB Mac).

Install the Python environment from the repository root:

```bash
uv sync --dev
```

## Initialize The Analyzer Images

Before running the full analysis workflow, build the Docker images used by the analyzers:

```bash
bash init_sats.sh
```

To force Docker to rebuild without cache:

```bash
bash init_sats.sh --no-cache
```

The script builds the images referenced by `config.toml` from the Dockerfiles in `static_analysis/docker/tools/`.

## Run The Full Workflow

Use `run.sh` when you want to download the complete dataset, analyze every generated project, and synthesize the results:

```bash
./run.sh
```

The script runs the workflow in this order:

1. Build the dataset:

```bash
uv run python dataset_construction/build_dataset.py
```

2. Discover every project under `dataset/<class>/<project>/`.

3. Run the static-analysis CLI for each project:

```bash
uv run static-analysis run dataset/<class>/<project>/ --output outputs/<class>/<project>
```

4. Synthesize every analyzed class:

```bash
uv run python -m static_analysis.synthesis <class>
```

If dataset construction fails, `run.sh` stops immediately. If analysis fails for one project, the script reports that project as failed and continues with the remaining projects. Synthesis is still attempted for the discovered classes, then the script exits with a non-zero status if either analysis or synthesis failed.

### Options

The script accepts the following flags:

- `--skip-dataset` — reuse the existing `dataset/` and skip the construction step (step 1). Useful when the dataset is already built and you only want to re-run analysis and synthesis.
- `--force` — re-analyze every project from scratch, even if its output already contains a `report.json`.
- `--jobs N` — analyze up to `N` projects in parallel (default `1`). Projects are independent and write to disjoint output directories, so this is safe. Because CodeQL is memory-hungry, its RAM and thread budget are scaled down automatically based on the detected machine size and `N` (see below). Parallel mode requires bash 4.3+.
- `--class NAME` — restrict the run to projects under `dataset/NAME/` (for example `kernel` or `application`). May be passed more than once to select multiple classes. Applies to every mode, including the fix modes below.

```bash
./run.sh --skip-dataset                 # analyze and synthesize an already-built dataset
./run.sh --skip-dataset --force         # also re-run projects that were already analyzed
./run.sh --skip-dataset --jobs 4        # analyze up to 4 projects at a time
./run.sh --skip-dataset --class kernel  # analyze and synthesize only the kernel projects
```

By default the run is **resumable and self-healing**: when a project's output directory already contains `report.json`, the script inspects it and re-runs **only the tools that did not complete** (status `failed`, `timeout`, or `unavailable`) plus any currently enabled tools missing from the report, merging the fresh results back in; a project is skipped entirely only when *all* enabled tools completed. This means an interrupted run can be restarted to both continue from where it stopped and recover partial tool failures, without repeating analyses that already succeeded. Skipped projects still register their class for the synthesis step. Use `--force` to ignore existing reports and analyze everything from scratch.

**CodeQL sizing.** For *every* run (parallel or not), the script sizes CodeQL to what Docker can actually give: it reads the daemon's memory and CPU count from `docker info` — which equals host RAM on Linux but is the VM's limit on macOS — reserves ~30% for the OS, Docker, and the lighter analyzers that run alongside CodeQL, then splits the rest across the `N` jobs, clamping CodeQL's per-job budget to a sane `[2048, 32768]` MB range and `[1, 20]` threads. These values are passed to the CLI via `--codeql-ram` / `--codeql-threads`, so `config.toml` is never modified. If the requested job count would overcommit the reserved Docker memory after applying the 2048 MB minimum, the script stops and asks you to lower `--jobs` or increase Docker memory. Applying this even with `--jobs 1` prevents a single project from asking CodeQL for more memory than the daemon has — the cause of exit-137 OOM kills, especially inside the smaller Docker VM on macOS. In parallel mode each project's analyzer output is also written to `outputs/<class>/<project>/run.log` to keep the console readable.

**CodeQL query scope.** The default CodeQL profile runs the stable `Security/CWE` C/C++ suite. The experimental CWE suite is not enabled by default because several experimental queries can explode on multi-million-line projects. For targeted extra coverage, add `codeql/cpp-queries:experimental/Security/CWE` back to `tools.codeql.options.queries`; the runner still excludes known non-terminating experimental query IDs when experimental suites are enabled.

### Inspecting And Fixing Failed Tools

Even when `report.json` exists, individual enabled analyzers can fail (status `failed`, `timeout`, or `unavailable`) while the others succeed, and old reports can be missing tools that are now enabled. Two modes operate on the existing `outputs/` to inspect and recover from these partial results. Both honor `--class` and do **not** rebuild the dataset or run synthesis.

- `--report-failed` — scan every `outputs/<class>/<project>/` directory and print, per project, enabled tools whose status is not `completed` plus enabled tools missing from the report. A directory with no (or an unreadable) `report.json` — e.g. a crashed or interrupted run — is reported as needing a full run, so such projects are not silently skipped. Nothing is executed, and `dataset/` does not need to be present.
- `--rerun-failed` — same scan, then re-run **only** the failed or missing tools of each affected project (or all tools when `report.json` is absent). The fresh results are merged back into the existing `report.json` (via the CLI `--merge` flag), so the tools that already completed are preserved. This mode runs projects sequentially and applies the same Docker-aware CodeQL sizing as the main pipeline.

```bash
./run.sh --report-failed                 # print which tools failed, run nothing
./run.sh --report-failed --class kernel  # ...restricted to the kernel class
./run.sh --rerun-failed                  # re-run only the failed tools and merge the results
./run.sh --rerun-failed --class kernel
```

`--rerun-failed` re-executes the affected analyzers in Docker, so it can take a while; it exits non-zero if any re-run still fails or if the matching `dataset/<class>/<project>/` source directory is missing. `--report-failed` and `--rerun-failed` are mutually exclusive.

## Outputs

After a successful run, the generated dataset is stored under:

```text
dataset/<class>/<project>/
```

Analysis results are written under:

```text
outputs/<class>/<project>/
├── report.json
├── cppcheck/
├── semgrep/
├── codeql/
├── flawfinder/
└── ikos/
```

`report.json` is the normalized report produced by the pipeline. Tool-specific subdirectories contain raw outputs and intermediate files.

Synthesis results are written under:

```text
synthesis/
├── <class>.json
└── <class>/
    ├── <project>_one_out_of_four.json
    ├── <project>_two_out_of_four.json
    ├── <project>_three_out_of_four.json
    ├── <project>_four_out_of_four.json
    ├── <project>_two_out_four_no_cwe.json
    ├── <project>_three_out_four_no_cwe.json
    └── <project>_four_out_four_no_cwe.json
```

The per-project files materialize finding clusters for each voting rule. The final `synthesis/<class>.json` report aggregates LOC, function counts, tool hits, unique CWEs, total vulnerabilities, and per-CWE counts from those intermediate cluster files. Findings with `cwe: null` are excluded before clustering and counting.

## Analysis Utilities And Experiments

The repository also includes small post-processing scripts for inspecting completed runs and producing experimental tables/figures. They assume `outputs/`, `dataset_construction/metadata/`, and/or `synthesis/` already exist.

### Per-Tool Finding Count Tables

`experiments/print_findings_tables.py` reads `outputs/<class>/<project>/report.json` and prints one table per class with projects on rows and tools on columns. A missing or non-completed tool is printed as red `NULL`. It also writes `experiments/txt/tools.txt`, a table of the overall finding count per tool summed across every project of every class (completed runs only).

```bash
./experiments/print_findings_tables.py
uv run python experiments/print_findings_tables.py
uv run python experiments/print_findings_tables.py --class kernel --color always
uv run python experiments/print_findings_tables.py --color never
```

### Vulnerability Density Report

`experiments/vulnerability_density_report.py` computes vulnerability incidence using the `two_out_of_four` synthesis criterion. It uses metadata from `dataset_construction/metadata/<class>_metadata.json` as the preferred denominator source, then falls back to `synthesis/<class>.json` when metadata is missing or incomplete. It prints project-level and class-aggregate tables for both vulnerabilities per 1k functions and vulnerabilities per KLOC.

The script also reads `projects_with_taxonomy.xlsx`: kernel project charts use colors tied to the selected/analyzed submodules listed in the `Kernel Selection` sheet, while application charts use colors from the taxonomy `category` code in the `App Taxonomy` sheet.

It also writes `experiments/txt/voting.txt`, a table of the overall number of validated vulnerabilities under each of the four agreement schemes (`one_out_of_four` through `four_out_of_four`, summed across every project of every class; the `no_cwe` variants are excluded).

```bash
./experiments/vulnerability_density_report.py
uv run python experiments/vulnerability_density_report.py
uv run python experiments/vulnerability_density_report.py --class kernel
uv run python experiments/vulnerability_density_report.py --no-plots
```

By default it writes:

```text
experiments/csv/vulnerability_density_report.csv
experiments/txt/voting.txt
experiments/plots/vulnerability_density_kernel_by_functions.svg
experiments/plots/vulnerability_density_kernel_by_functions.png
experiments/plots/vulnerability_density_kernel_by_loc.svg
experiments/plots/vulnerability_density_kernel_by_loc.png
experiments/plots/vulnerability_density_application_by_functions.svg
experiments/plots/vulnerability_density_application_by_functions.png
experiments/plots/vulnerability_density_application_by_loc.svg
experiments/plots/vulnerability_density_application_by_loc.png
experiments/plots/vulnerability_density_class_aggregate_by_functions.svg
experiments/plots/vulnerability_density_class_aggregate_by_functions.png
experiments/plots/vulnerability_density_class_aggregate_by_loc.svg
experiments/plots/vulnerability_density_class_aggregate_by_loc.png
```

### CWE Distribution Comparison

`experiments/cwe_distribution_comparison.py` compares CWE distributions between `kernel` and `application` under the `two_out_of_four` strategy. For each CWE, it compares project-level percentages with Mann-Whitney U, reports Cliff's delta and its interpretation, and resolves CWE names and CWE-1000 roots from `cwe_mapping/cwec_v4.20.xml`. The unique-CWE summary also reports how many of each class's unique CWEs fall in the 2025 MITRE Top 25 (catalog view CWE-1435).

By default it prints the full table and writes:

```text
experiments/csv/cwe_distribution_comparison.csv
experiments/csv/cwe_root_distribution_comparison.csv
experiments/plots/cwe_distribution_effect_plot.svg
experiments/plots/cwe_distribution_effect_plot.png
```

Run the full comparison:

```bash
./experiments/cwe_distribution_comparison.py
uv run python experiments/cwe_distribution_comparison.py
```

Filter to statistically significant CWEs:

```bash
uv run python experiments/cwe_distribution_comparison.py --significant
uv run python experiments/cwe_distribution_comparison.py --significant --alpha 0.01
```

Write the significant-only table and figures to separate files:

```bash
uv run python experiments/cwe_distribution_comparison.py \
  --significant \
  --csv experiments/csv/cwe_distribution_comparison_significant.csv \
  --svg experiments/plots/cwe_distribution_effect_plot_significant.svg \
  --png experiments/plots/cwe_distribution_effect_plot_significant.png
```

The generated plot is a horizontal effect-size plot suitable for paper figures: the x-axis is Cliff's delta, zero separates the two classes, dashed vertical lines mark the standard Cliff's delta magnitude thresholds, marker color indicates dominance, and filled markers indicate `p < alpha`.

Useful syntax checks for the experimental scripts:

```bash
uv run python -m py_compile experiments/print_findings_tables.py
uv run python -m py_compile experiments/vulnerability_density_report.py
uv run python -m py_compile experiments/cwe_distribution_comparison.py
```

## Run Only One Step

If you only want to download or refresh the dataset, read [dataset_construction/README.md](dataset_construction/README.md). It documents class filters, project filters, staging behavior, metadata output, and useful `build_dataset.py` options.

If you already have a project and only want to run static analysis, read [static_analysis/README.md](static_analysis/README.md). It documents the `static-analysis run` command, selected-tool execution, verbosity options, configuration, and output layout.

## Tests

Run the test suite with:

```bash
uv run pytest
```

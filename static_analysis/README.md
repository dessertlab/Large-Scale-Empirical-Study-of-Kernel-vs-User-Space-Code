# Static Analysis Module

This module contains the command-line interface, analyzer pipeline, tool runners, Dockerfiles, and synthesis logic used to analyze C/C++ projects and summarize their findings.

## Module Structure

```text
static_analysis/
├── README.md
├── cli.py                  # `static-analysis` entrypoint
├── config.py               # root config.toml loader
├── docker_executor.py      # Docker command construction and execution
├── models.py               # shared data models
├── pipeline.py             # analyzer orchestration
├── progress.py             # progress reporters
├── report.py               # normalized JSON report writer
├── synthesis.py            # post-processing, clustering, and synthesis reports
├── runners/                # analyzer-specific runners
└── docker/tools/           # analyzer Dockerfiles
```

## Supported Analyzers

- `cppcheck`
- `semgrep`
- `codeql`
- `flawfinder`
- `ikos`

Tool images, commands, arguments, timeouts, and accepted exit codes are configured in the root `config.toml` file. Each tool has an `enabled` flag in its `[tools.<name>]` section; set it to `false` to skip that analyzer in the full workflow (for a single run you can instead select tools with `--tool`, see [Useful Options](#useful-options)).

CodeQL is the slowest analyzer. Its `[tools.codeql.options]` section exposes performance knobs:

- `threads` — worker threads for both database creation and analysis; `0` uses all available CPU cores (recommended on multi-core hosts), `1` forces single-threaded.
- `ram` — memory budget in MB for database creation and analysis.

Both values are passed to `codeql database create` and `codeql database analyze`, so raising them on a machine with spare cores and memory significantly reduces CodeQL runtime.

## Build Analyzer Images

From the repository root:

```bash
bash init_sats.sh
```

Use `--no-cache` when you need a clean Docker rebuild:

```bash
bash init_sats.sh --no-cache
```

## Analyze A Project

Run the analyzer pipeline on any C/C++ project directory:

```bash
uv run static-analysis run dataset/<class>/<project>/ --output outputs/<class>/<project>
```

Example using the test fixture:

```bash
uv run static-analysis run tests/projects/c_cpp_insecure_demo --output outputs/demo
```

## Useful Options

Run only selected tools:

```bash
uv run static-analysis run dataset/kernel/serenityos --tool cppcheck --tool flawfinder
```

Re-run selected tools and merge them into an existing report instead of overwriting it:

```bash
uv run static-analysis run dataset/kernel/serenityos \
  --output outputs/kernel/serenityos --tool codeql --merge
```

Without `--merge`, a run rewrites `report.json` with only the tools it just executed, discarding the entries of tools that were not selected. With `--merge`, the freshly-run tools replace their previous entries in the existing `report.json` while all other tools (and their findings) are preserved, and the summary counts are recomputed. This is what powers `./run.sh --rerun-failed` (see the root README), which re-runs only the failed analyzers of each project. If no report exists yet, `--merge` behaves like a normal write.

Show more execution detail:

```bash
uv run static-analysis run dataset/kernel/serenityos --verbose --show-command
```

Use an explicit configuration file:

```bash
uv run static-analysis run dataset/kernel/serenityos --config config.toml --output outputs/kernel/serenityos
```

Use a different Docker executable:

```bash
uv run static-analysis run dataset/kernel/serenityos --docker podman
```

Override CodeQL's RAM (MB) and thread budget for a single run, without editing `config.toml`. This is mainly used by `./run.sh --jobs N` to scale CodeQL down when several projects are analyzed in parallel:

```bash
uv run static-analysis run dataset/kernel/serenityos --codeql-ram 8192 --codeql-threads 5
```

## Synthesize Results

After the SATs have produced `outputs/<class>/<project>/report.json`, run the synthesis step for a class:

```bash
uv run python -m static_analysis.synthesis kernel
```

By default, synthesis reads:

```text
outputs/<class>/<project>/report.json
dataset_construction/metadata/<class>_metadata.json
dataset/<class>/<project>/
cwe_mapping/cwec_v4.20.xml
```

The dataset project directory is passed to Universal Ctags to map finding line numbers to function spans. You can override roots when needed:

```bash
uv run python -m static_analysis.synthesis kernel \
  --outputs-root outputs \
  --metadata-root dataset_construction/metadata \
  --dataset-root dataset \
  --synthesis-root synthesis \
  --cwe-xml cwe_mapping/cwec_v4.20.xml
```

The synthesis step first filters out findings whose normalized CWE is missing, including `"cwe": null`. It then materializes clusters under `synthesis/<class>/` and computes the final `synthesis/<class>.json` report from those cluster files.

Voting rules:

- `one_out_of_four`: every remaining finding is accepted as its own cluster.
- `two_out_of_four`, `three_out_of_four`, `four_out_of_four`: findings from distinct tools match when they are in the same file and on the same line, or when they are in the same function and their CWEs are equal or ancestor/descendant in the CWE hierarchy. When related CWEs differ, the more generic ancestor is used for the final per-CWE count.
- `two_out_four_no_cwe`, `three_out_four_no_cwe`, `four_out_four_no_cwe`: findings from distinct tools match when they are in the same file and on the same line, or when they are in the same function. Per-CWE counts include every distinct CWE present in the accepted cluster.

Intermediate cluster files use this layout:

```text
synthesis/<class>/
├── <project>_one_out_of_four.json
├── <project>_two_out_of_four.json
├── <project>_three_out_of_four.json
├── <project>_four_out_of_four.json
├── <project>_two_out_four_no_cwe.json
├── <project>_three_out_four_no_cwe.json
└── <project>_four_out_four_no_cwe.json
```

Each cluster records `cluster_id`, `rule`, participating `tools`, `cwes`, optional `representative_cwe`, and the normalized findings with file, line, CWE, tool, and function identifier.

## Output Layout

Each analyzer run writes raw tool outputs plus a normalized report:

```text
outputs/<class>/<project>/
├── report.json
├── cppcheck/
├── semgrep/
├── codeql/
├── flawfinder/
└── ikos/
```

Post-processing writes the final class summary and per-rule cluster files under `synthesis/` as described above.

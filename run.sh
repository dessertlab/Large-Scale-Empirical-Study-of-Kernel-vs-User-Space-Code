#!/usr/bin/env bash
set -uo pipefail

# The sequential path works on bash 3.2 (the macOS system bash); only --jobs > 1
# needs bash 4.3+ for `wait -n`, which is checked where it is used.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR" || exit 1

usage() {
  cat <<EOF
Usage: ./run.sh [--skip-dataset] [--force] [--jobs N] [--class NAME ...]
       ./run.sh --report-failed [--class NAME ...]
       ./run.sh --rerun-failed [--class NAME ...]

  --skip-dataset    reuse the existing dataset/ and skip the construction step
  --force           re-analyze every project from scratch, even if a report
                    already exists
  --jobs N          analyze up to N projects in parallel (default 1). Because
                    CodeQL is memory-hungry, its RAM/threads are scaled down
                    automatically based on the detected machine size and N.
                    Parallel mode requires bash 4.3+.
  --class NAME      restrict to projects under dataset/NAME/ (e.g. kernel);
                    may be passed more than once. Applies to every mode.

  --report-failed   do not run anything; scan outputs/ and print a per-project
                    report of which tools failed (status != completed)
  --rerun-failed    scan outputs/ and re-run ONLY the failed tools of each
                    project, merging the fresh results back into report.json
                    (completed tools are preserved)

  -h, --help        show this help

Resume behaviour: when a project already has report.json, only the tools that
did not complete (status failed/timeout/unavailable) are re-run and merged back
in; a project is skipped entirely only when all of its tools completed. This
makes an interrupted run restartable while still recovering partial failures.
Use --force to ignore existing reports and analyze everything from scratch.
EOF
}

skip_dataset=0
force=0
report_failed=0
rerun_failed=0
jobs=1
classes=()

while (($#)); do
  case "$1" in
    --skip-dataset)
      skip_dataset=1
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    --jobs)
      if [[ $# -lt 2 ]]; then
        echo "--jobs requires a value" >&2
        exit 2
      fi
      if ! [[ "$2" =~ ^[1-9][0-9]*$ ]]; then
        echo "--jobs must be a positive integer (got: $2)" >&2
        exit 2
      fi
      jobs="$2"
      shift 2
      ;;
    --class)
      if [[ $# -lt 2 ]]; then
        echo "--class requires a value" >&2
        exit 2
      fi
      classes+=("$2")
      shift 2
      ;;
    --report-failed)
      report_failed=1
      shift
      ;;
    --rerun-failed)
      rerun_failed=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ $report_failed -eq 1 && $rerun_failed -eq 1 ]]; then
  echo "Choose either --report-failed or --rerun-failed, not both" >&2
  exit 2
fi

# Returns 0 when $1 is among the requested --class values (or none were given).
class_selected() {
  ((${#classes[@]} == 0)) && return 0
  local wanted
  for wanted in "${classes[@]}"; do
    [[ "$wanted" == "$1" ]] && return 0
  done
  return 1
}

remember_class() {
  local discovered
  if ((${#discovered_classes[@]})); then
    for discovered in "${discovered_classes[@]}"; do
      [[ "$discovered" == "$1" ]] && return 0
    done
  fi
  discovered_classes+=("$1")
}

# Format a whole number of seconds as HH:MM:SS (bash 3.2 compatible).
fmt_hms() {
  local total=$1
  ((total < 0)) && total=0
  printf '%02d:%02d:%02d' $((total / 3600)) $(((total % 3600) / 60)) $((total % 60))
}

# Print "| elapsed HH:MM:SS | ETA ~HH:MM:SS" for a sequential run. The ETA is a
# deliberately rough estimate derived ONLY from already-completed items; until
# at least one completes it is "ETA unknown" rather than a fabricated number.
# Args: start_epoch completed_count remaining_count
progress_suffix() {
  local start=$1 completed=$2 remaining=$3
  local elapsed avg eta
  elapsed=$(( $(date +%s) - start ))
  if ((completed > 0)); then
    avg=$((elapsed / completed))
    eta=$((avg * remaining))
    printf '| elapsed %s | ETA ~%s' "$(fmt_hms "$elapsed")" "$(fmt_hms "$eta")"
  else
    printf '| elapsed %s | ETA unknown' "$(fmt_hms "$elapsed")"
  fi
}

# Prints the config-enabled tools that should be present in a complete report.
enabled_tools() {
  uv run python - config.toml <<'PY'
import sys

from static_analysis.config import load_config

config = load_config(sys.argv[1])
print(" ".join(config.enabled_tools))
PY
}

# Prints the space-separated names of enabled tools that need to be run for $1:
# enabled tools with status != completed, plus enabled tools missing from the
# report entirely.
failed_tools() {
  uv run python - "$1" ${enabled_tool_args[@]+"${enabled_tool_args[@]}"} <<'PY'
import json, sys

report_path = sys.argv[1]
expected_tools = sys.argv[2:]
expected = set(expected_tools)
try:
    with open(report_path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, ValueError):
    sys.exit(3)

tools = data.get("tools", [])
if not isinstance(tools, list):
    sys.exit(3)

seen = set()
needs_run = []
for entry in tools:
    if not isinstance(entry, dict):
        sys.exit(3)
    tool = entry.get("tool")
    if not isinstance(tool, str) or not tool:
        sys.exit(3)
    seen.add(tool)
    if tool in expected and entry.get("status") != "completed":
        needs_run.append(tool)

for tool in expected_tools:
    if tool not in seen:
        needs_run.append(tool)

deduped = []
deduped_seen = set()
for tool in needs_run:
    if tool not in deduped_seen:
        deduped.append(tool)
        deduped_seen.add(tool)

print(" ".join(deduped))
PY
}

# Total physical RAM in MB, cross-platform (Linux /proc, macOS sysctl).
detect_total_ram_mb() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    local bytes
    bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
    echo $((bytes / 1024 / 1024))
  elif [[ -r /proc/meminfo ]]; then
    awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo
  else
    echo 0
  fi
}

# Number of logical CPUs, cross-platform.
detect_cores() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sysctl -n hw.ncpu 2>/dev/null || echo 1
  elif command -v nproc >/dev/null 2>&1; then
    nproc
  else
    echo 1
  fi
}

# Memory (MB) actually available to containers. On Linux this equals host RAM,
# but on macOS Docker runs in a VM (Docker Desktop, OrbStack, Colima, ...) with
# its own limit, so we must ask the daemon instead of trusting host RAM —
# otherwise CodeQL would be sized for far more memory than the VM has and get
# OOM-killed. Falls back to host RAM if the daemon can't be queried.
detect_docker_memory_mb() {
  local bytes
  bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || true)"
  if [[ "$bytes" =~ ^[0-9]+$ ]] && ((bytes > 0)); then
    echo $((bytes / 1024 / 1024))
  else
    detect_total_ram_mb
  fi
}

# CPUs available to containers (the Docker VM on macOS), with a host fallback.
detect_docker_cpus() {
  local n
  n="$(docker info --format '{{.NCPU}}' 2>/dev/null || true)"
  if [[ "$n" =~ ^[0-9]+$ ]] && ((n > 0)); then
    echo "$n"
  else
    detect_cores
  fi
}

# Conservative per-job CodeQL RAM (MB) and thread count for the requested job
# count, based on what Docker can actually give (its VM on macOS, the host on
# Linux). Globals CODEQL_RAM / CODEQL_THREADS / DOCKER_MEM_MB are set for the
# callers. We reserve ~30% for the OS, Docker, and the other (lighter)
# analyzers that run alongside CodeQL, split the rest across jobs, and clamp to
# a sane [2048, 32768] MB range.
compute_codeql_resources() {
  local n="$1"
  local cores usable per_ram per_threads
  DOCKER_MEM_MB="$(detect_docker_memory_mb)"
  cores="$(detect_docker_cpus)"

  if [[ "$DOCKER_MEM_MB" -le 0 ]]; then
    # Detection failed; fall back to a safe small budget.
    CODEQL_USABLE_MEM_MB=0
    CODEQL_RAM=4096
  else
    usable=$((DOCKER_MEM_MB * 70 / 100))
    CODEQL_USABLE_MEM_MB="$usable"
    per_ram=$((usable / n))
    ((per_ram > 32768)) && per_ram=32768
    ((per_ram < 2048)) && per_ram=2048
    CODEQL_RAM="$per_ram"
  fi

  per_threads=$((cores / n))
  ((per_threads < 1)) && per_threads=1
  ((per_threads > 20)) && per_threads=20
  CODEQL_THREADS="$per_threads"
}

prepare_codeql_args() {
  local n="$1"
  local requested_mb

  if [[ ${codeql_enabled:-0} -eq 0 ]]; then
    codeql_args=()
    return 0
  fi

  compute_codeql_resources "$n"
  if [[ "$CODEQL_USABLE_MEM_MB" -gt 0 ]]; then
    requested_mb=$((CODEQL_RAM * n))
    if ((requested_mb > CODEQL_USABLE_MEM_MB)); then
      echo "CodeQL sizing would overcommit Docker memory: ${requested_mb} MB requested" >&2
      echo "for $n job(s), but only ${CODEQL_USABLE_MEM_MB} MB is reserved for analysis" >&2
      echo "(Docker memory: ${DOCKER_MEM_MB} MB). Lower --jobs or increase Docker memory." >&2
      exit 1
    fi
  fi

  codeql_args=(--codeql-ram "$CODEQL_RAM" --codeql-threads "$CODEQL_THREADS")
  echo "CodeQL sizing: ${CODEQL_RAM} MB RAM / ${CODEQL_THREADS} thread(s) per job" \
    "(Docker memory: ${DOCKER_MEM_MB} MB, jobs: $n)"
}

# Analyze a single project: skip when everything already completed, re-run only
# the failed tools when a partial report exists, otherwise run the full set.
# Honors the optional CodeQL overrides collected in codeql_args.
analyze_project() {
  local project_class="$1" project_name="$2" project_dir="$3" output_dir="$4"
  local report="$output_dir/report.json"

  if [[ $force -eq 0 && -f "$report" ]]; then
    local tools
    local failed_tools_status
    tools="$(failed_tools "$report")"
    failed_tools_status=$?
    if [[ $failed_tools_status -ne 0 ]]; then
      echo "[$project_class/$project_name] report.json is unreadable; re-running all tools"
      uv run static-analysis run "$project_dir/" --output "$output_dir" \
        ${codeql_args[@]+"${codeql_args[@]}"}
      return $?
    fi
    if [[ -z "$tools" ]]; then
      echo "[$project_class/$project_name] skipping (all tools completed)"
      return 0
    fi
    local tool_args=()
    local t
    for t in $tools; do
      tool_args+=(--tool "$t")
    done
    echo "[$project_class/$project_name] re-running failed tools: $tools"
    uv run static-analysis run "$project_dir/" --output "$output_dir" --merge \
      ${codeql_args[@]+"${codeql_args[@]}"} "${tool_args[@]}"
    return $?
  fi

  echo "[$project_class/$project_name] analyzing"
  uv run static-analysis run "$project_dir/" --output "$output_dir" \
    ${codeql_args[@]+"${codeql_args[@]}"}
  return $?
}

enabled_tool_args=()
codeql_enabled=0
enabled_tool_names="$(enabled_tools)"
enabled_tools_status=$?
if [[ $enabled_tools_status -ne 0 ]]; then
  echo "Unable to read enabled tools from config.toml" >&2
  exit "$enabled_tools_status"
fi
for tool in $enabled_tool_names; do
  enabled_tool_args+=("$tool")
  [[ "$tool" == "codeql" ]] && codeql_enabled=1
done
codeql_args=()

# ---------------------------------------------------------------------------
# Fix modes: report or re-run failed tools, then exit.
# ---------------------------------------------------------------------------
if [[ $report_failed -eq 1 || $rerun_failed -eq 1 ]]; then
  if [[ $report_failed -eq 1 ]]; then
    echo "== Failed-tool report =="
  else
    echo "== Re-running failed tools =="
    if ((jobs != 1)); then
      echo "Note: --rerun-failed runs sequentially; ignoring --jobs $jobs for execution." >&2
    fi
    prepare_codeql_args 1
  fi

  scanned=0
  with_failures=0
  rerun_status=0
  # Recovery targets collected during the scan (parallel arrays; bash 3.2 safe).
  # rr_tools[i] empty means "re-run all tools" (no/unreadable report.json).
  rr_label=()
  rr_pdir=()
  rr_odir=()
  rr_tools=()

  for output_dir in outputs/*/*; do
    [[ -d "$output_dir" ]] || continue
    report="$output_dir/report.json"
    project_name="$(basename "$output_dir")"
    project_class="$(basename "$(dirname "$output_dir")")"
    class_selected "$project_class" || continue

    project_dir="dataset/$project_class/$project_name"
    scanned=$((scanned + 1))

    tools="$(failed_tools "$report")"
    failed_tools_status=$?
    if [[ $failed_tools_status -ne 0 ]]; then
      with_failures=$((with_failures + 1))
      echo
      if [[ -f "$report" ]]; then
        echo "[$project_class/$project_name] failed: unreadable report.json"
      else
        echo "[$project_class/$project_name] failed: no report.json (never analyzed)"
      fi
      rr_label+=("$project_class/$project_name")
      rr_pdir+=("$project_dir")
      rr_odir+=("$output_dir")
      rr_tools+=("")
      continue
    fi
    [[ -z "$tools" ]] && continue
    with_failures=$((with_failures + 1))

    echo
    echo "[$project_class/$project_name] failed: $tools"
    rr_label+=("$project_class/$project_name")
    rr_pdir+=("$project_dir")
    rr_odir+=("$output_dir")
    rr_tools+=("$tools")
  done

  echo
  if [[ $scanned -eq 0 ]]; then
    echo "No project outputs found under outputs/ (run the pipeline first)" >&2
    exit 1
  fi
  echo "== Scanned $scanned project(s); $with_failures with failed tools =="

  if [[ $rerun_failed -eq 1 && ${#rr_label[@]} -gt 0 ]]; then
    rr_total=${#rr_label[@]}
    rr_done=0
    rr_start=$(date +%s)
    echo
    echo "== Re-running $rr_total recovery target(s) sequentially =="
    for i in "${!rr_label[@]}"; do
      label="${rr_label[$i]}"
      project_dir="${rr_pdir[$i]}"
      output_dir="${rr_odir[$i]}"
      tools="${rr_tools[$i]}"
      idx=$((i + 1))

      echo
      if [[ ! -d "$project_dir" ]]; then
        echo "[$label] cannot re-run: missing $project_dir" >&2
        rerun_status=1
        rr_done=$((rr_done + 1))
        continue
      fi

      suffix="$(progress_suffix "$rr_start" "$rr_done" $((rr_total - rr_done)))"
      if [[ -z "$tools" ]]; then
        echo "[$label] re-running: all tools ($idx/$rr_total recovery targets) $suffix"
        uv run static-analysis run "$project_dir/" --output "$output_dir" \
          ${codeql_args[@]+"${codeql_args[@]}"}
        status=$?
      else
        tool_args=()
        for t in $tools; do
          tool_args+=(--tool "$t")
        done
        echo "[$label] re-running: $tools ($idx/$rr_total recovery targets) $suffix"
        uv run static-analysis run "$project_dir/" --output "$output_dir" \
          --merge ${codeql_args[@]+"${codeql_args[@]}"} "${tool_args[@]}"
        status=$?
      fi
      if [[ $status -ne 0 ]]; then
        echo "[$label] re-run still failing (exit $status)" >&2
        rerun_status=1
      fi
      rr_done=$((rr_done + 1))
    done
    echo
    echo "== Recovery finished in $(fmt_hms $(( $(date +%s) - rr_start ))) =="
  fi

  exit "$rerun_status"
fi

# ---------------------------------------------------------------------------
# Normal pipeline: build dataset, analyze, synthesize.
# ---------------------------------------------------------------------------
if [[ $skip_dataset -eq 1 ]]; then
  echo "== Skipping dataset construction (--skip-dataset) =="
else
  echo "== Building dataset =="
  if ((${#classes[@]})); then
    uv run python dataset_construction/build_dataset.py --classes "${classes[@]}"
  else
    uv run python dataset_construction/build_dataset.py
  fi
  build_status=$?
  if [[ $build_status -ne 0 ]]; then
    echo "Dataset construction failed with exit code $build_status" >&2
    exit "$build_status"
  fi
fi

echo
echo "== Running static analysis =="
analysis_status=0
synthesis_status=0
found_projects=0
discovered_classes=()

# Size CodeQL to what Docker can actually give, split across the requested
# jobs. Applied for every run (not just parallel ones) so a single project can
# never ask CodeQL for more memory than the Docker daemon has — the cause of
# exit-137 OOM kills, especially inside the smaller Docker VM on macOS.
if ((jobs > 1)); then
  if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3))); then
    echo "--jobs > 1 requires bash 4.3+ for 'wait -n' (found ${BASH_VERSION})." >&2
    exit 1
  fi
fi
prepare_codeql_args "$jobs"
if ((jobs > 1)); then
  echo "Parallel mode: $jobs job(s)"
fi

# Per-project exit codes are written here so the parallel jobs can report
# failures back to the foreground without sharing variables.
status_dir="$(mktemp -d)"
trap 'rm -rf "$status_dir"' EXIT
status_files=()
status_labels=()
status_logs=()

# Block until fewer than $jobs background jobs are running.
wait_for_slot() {
  while (($(jobs -rp | wc -l) >= jobs)); do
    wait -n
  done
}

# Pre-count the selected projects so progress can show n/total and a rough ETA.
total_selected=0
for pre_dir in dataset/*/*; do
  [[ -d "$pre_dir" ]] || continue
  class_selected "$(basename "$(dirname "$pre_dir")")" || continue
  total_selected=$((total_selected + 1))
done
analysis_start=$(date +%s)
analysis_index=0
analysis_completed=0

for project_dir in dataset/*/*; do
  [[ -d "$project_dir" ]] || continue

  project_class="$(basename "$(dirname "$project_dir")")"
  project_name="$(basename "$project_dir")"
  class_selected "$project_class" || continue

  found_projects=1
  output_dir="outputs/$project_class/$project_name"
  remember_class "$project_class"
  analysis_index=$((analysis_index + 1))

  if ((jobs > 1)); then
    wait_for_slot
    status_file="$status_dir/${project_class}__${project_name}"
    status_files+=("$status_file")
    status_labels+=("$project_class/$project_name")
    status_logs+=("$output_dir/run.log")
    mkdir -p "$output_dir"
    # Parallel mode stays terse: per-tool detail goes to run.log, the terminal
    # only shows which project launched (n/total) plus elapsed so far.
    echo "[$project_class/$project_name] -> running ($analysis_index/$total_selected) | elapsed $(fmt_hms $(( $(date +%s) - analysis_start ))) (log: $output_dir/run.log)"
    {
      analyze_project "$project_class" "$project_name" "$project_dir" "$output_dir"
      echo $? >"$status_file"
    } >"$output_dir/run.log" 2>&1 &
  else
    echo
    pct=0
    ((total_selected > 0)) && pct=$((analysis_index * 100 / total_selected))
    echo "[$project_class/$project_name] analyzing ($analysis_index/$total_selected projects, ${pct}%) $(progress_suffix "$analysis_start" "$analysis_completed" $((total_selected - analysis_completed)))"
    analyze_project "$project_class" "$project_name" "$project_dir" "$output_dir"
    status=$?
    analysis_completed=$((analysis_completed + 1))
    if [[ $status -ne 0 ]]; then
      echo "[$project_class/$project_name] failed with exit code $status" >&2
      analysis_status=1
    fi
  fi
done

if ((jobs > 1)); then
  wait
  for i in "${!status_files[@]}"; do
    status_file="${status_files[$i]}"
    status_label="${status_labels[$i]}"
    status_log="${status_logs[$i]}"
    if [[ ! -f "$status_file" ]]; then
      echo "[$status_label] failed to report completion (see $status_log)" >&2
      analysis_status=1
      continue
    fi
    if [[ "$(cat "$status_file")" != "0" ]]; then
      echo "[$status_label] failed (see $status_log)" >&2
      analysis_status=1
    fi
  done
fi

if [[ $found_projects -eq 0 ]]; then
  if ((${#classes[@]})); then
    echo "No projects found for class(es): ${classes[*]}" >&2
  else
    echo "No projects found under dataset/<class>/<project>" >&2
  fi
  exit 1
fi

echo
echo "== Analyzed $total_selected project(s) in $(fmt_hms $(( $(date +%s) - analysis_start ))) =="

echo
echo "== Synthesizing results =="
for project_class in "${discovered_classes[@]}"; do
  echo
  echo "[$project_class] synthesizing"
  uv run python -m static_analysis.synthesis "$project_class"
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "[$project_class] synthesis failed with exit code $status" >&2
    synthesis_status=1
  fi
done

if [[ $analysis_status -ne 0 || $synthesis_status -ne 0 ]]; then
  exit 1
fi

exit 0

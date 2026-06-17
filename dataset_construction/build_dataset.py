"""Build the filtered C/C++ dataset used by the static analysis pipeline."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from static_analysis.ctags import CtagsResolutionError, resolve_universal_ctags

try:
    from .config import C_CPP_EXTENSIONS, EXCLUDED_DIRS
except ImportError:
    from config import C_CPP_EXTENSIONS, EXCLUDED_DIRS


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "dataset"
METADATA_DIR = ROOT / "dataset_construction" / "metadata"
SOURCE_DIR = ROOT / "dataset_construction" / "src"
STAGING_DIR = ROOT / "dataset_construction" / ".staging"
DEFAULT_CLONE_DEPTH = 1
PROJECT_CLASSES = ("kernel", "application")


@dataclass(frozen=True)
class Project:
    """Repository entry loaded from the source JSON files."""

    name: str
    url: str
    project_class: str
    folders: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectMetadata:
    """Metrics collected from a filtered project."""

    name: str
    url: str
    project_class: str
    source_files: int
    loc: int
    functions: int
    folders: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "url": self.url,
            "class": self.project_class,
            "source_files": self.source_files,
            "loc": self.loc,
            "functions": self.functions,
        }
        if self.folders:
            payload["folders"] = list(self.folders)
        return payload


class DatasetBuildError(RuntimeError):
    """Raised when a project cannot be built safely."""


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    ctags_bin = require_executable(args.ctags_bin)

    selected_classes = tuple(args.classes)
    metadata_by_class: dict[str, list[ProjectMetadata]] = {
        project_class: [] for project_class in selected_classes
    }

    for project_class in selected_classes:
        projects = load_projects(project_class)
        projects = filter_projects(projects, args.projects, args.limit)

        print(f"\n== Building {project_class}: {len(projects)} project(s) ==")
        for project in projects:
            try:
                metadata = build_project(project, args, ctags_bin)
            except DatasetBuildError as exc:
                print(f"[ERROR] {project_class}/{project.name}: {exc}", file=sys.stderr)
                if args.keep_going:
                    continue
                return 1
            metadata_by_class[project_class].append(metadata)

        write_class_metadata(
            project_class,
            metadata_by_class[project_class],
            args.metadata_dir.resolve(),
        )

    return 0


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Clone C/C++ GitHub projects, filter source files, count LOC/functions, "
            "and write dataset metadata."
        )
    )
    parser.add_argument(
        "--classes",
        nargs="+",
        choices=PROJECT_CLASSES,
        default=list(PROJECT_CLASSES),
        help="Dataset classes to build. Defaults to both kernel and application.",
    )
    parser.add_argument(
        "--project",
        dest="projects",
        action="append",
        default=[],
        help="Build only the named project. Can be passed multiple times.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Build only the first N projects from each selected class.",
    )
    parser.add_argument(
        "--clone-depth",
        type=int,
        default=DEFAULT_CLONE_DEPTH,
        help="Depth for shallow clones. Defaults to 1.",
    )
    parser.add_argument(
        "--ctags-bin",
        default="ctags",
        help="Universal Ctags executable name or path. Defaults to ctags.",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DATASET_DIR,
        help="Directory where filtered repositories are written.",
    )
    parser.add_argument(
        "--staging-dir",
        type=Path,
        default=STAGING_DIR,
        help="Temporary clone directory, removed per project unless --keep-staging is set.",
    )
    parser.add_argument(
        "--metadata-dir",
        type=Path,
        default=METADATA_DIR,
        help="Directory where class metadata JSON files are written.",
    )
    parser.add_argument(
        "--keep-staging",
        action="store_true",
        help="Keep cloned repositories in the staging directory after processing.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue with the next project when one project fails.",
    )
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be greater than or equal to zero")
    if args.clone_depth < 1:
        parser.error("--clone-depth must be greater than zero")
    return args


def require_executable(executable: str) -> str:
    try:
        return resolve_universal_ctags(executable)
    except CtagsResolutionError as exc:
        raise DatasetBuildError(str(exc)) from exc


def load_projects(project_class: str) -> list[Project]:
    path = SOURCE_DIR / f"{project_class}.json"
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    projects = []
    for entry in payload:
        folders = tuple(entry.get("folders", ()))
        projects.append(
            Project(
                name=entry["name"],
                url=entry["url"],
                project_class=project_class,
                folders=folders,
            )
        )
    return projects


def filter_projects(
    projects: Sequence[Project],
    selected_names: Sequence[str],
    limit: int | None,
) -> list[Project]:
    result = list(projects)
    if selected_names:
        selected = set(selected_names)
        result = [project for project in result if project.name in selected]
    if limit is not None:
        result = result[:limit]
    return result


def build_project(
    project: Project,
    args: argparse.Namespace,
    ctags_bin: str,
) -> ProjectMetadata:
    staging_root = args.staging_dir.resolve() / project.project_class
    clone_dir = staging_root / project.name
    target_dir = args.dataset_dir.resolve() / project.project_class / project.name

    print(f"\n[{project.project_class}/{project.name}] clone")
    remove_path(clone_dir)
    remove_path(target_dir)
    clone_project(project, clone_dir, args.clone_depth)

    try:
        print(f"[{project.project_class}/{project.name}] filter C/C++ sources")
        source_files = filter_source_tree(clone_dir, target_dir)

        print(f"[{project.project_class}/{project.name}] count LOC/functions")
        loc = count_loc(target_dir)
        functions = count_functions(target_dir, ctags_bin)

        return ProjectMetadata(
            name=project.name,
            url=project.url,
            project_class=project.project_class,
            source_files=source_files,
            loc=loc,
            functions=functions,
            folders=project.folders,
        )
    finally:
        if not args.keep_staging:
            print(f"[{project.project_class}/{project.name}] clean staging")
            remove_path(clone_dir)


def clone_project(project: Project, clone_dir: Path, clone_depth: int) -> None:
    clone_dir.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "git",
        "clone",
        "--depth",
        str(clone_depth),
        "--filter=blob:none",
        "--no-tags",
    ]

    if project.folders:
        command.append("--sparse")

    command.extend([project.url, str(clone_dir)])
    run_command(command, cwd=ROOT)

    if project.folders:
        run_command(
            ["git", "sparse-checkout", "set", "--cone", *project.folders],
            cwd=clone_dir,
        )


def filter_source_tree(source_dir: Path, target_dir: Path) -> int:
    target_dir.mkdir(parents=True, exist_ok=True)
    copied = 0

    for source_file in iter_source_files(source_dir):
        relative_path = source_file.relative_to(source_dir)
        destination = target_dir / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, destination, follow_symlinks=False)
        copied += 1

    if copied == 0:
        raise DatasetBuildError(f"No C/C++ source files found after filtering {source_dir}")
    return copied


def iter_source_files(root: Path) -> Iterable[Path]:
    excluded_dirs = {directory.lower() for directory in EXCLUDED_DIRS}
    extensions = {extension.lower() for extension in C_CPP_EXTENSIONS}

    for current_root_name, dirnames, filenames in os.walk(root):
        current_root = Path(current_root_name)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname.lower() not in excluded_dirs
        ]
        for filename in filenames:
            path = current_root / filename
            if path.suffix.lower() in extensions and path.is_file():
                yield path


def count_loc(root: Path) -> int:
    total = 0
    for source_file in iter_source_files(root):
        with source_file.open(encoding="utf-8", errors="ignore") as handle:
            total += sum(1 for line in handle if line.strip())
    return total


def count_functions(root: Path, ctags_bin: str) -> int:
    files = [str(path) for path in iter_source_files(root)]
    if not files:
        return 0

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        for source_file in files:
            handle.write(f"{source_file}\n")
        file_list = Path(handle.name)

    try:
        command = [
            ctags_bin,
            "--output-format=json",
            "--fields=+K",
            "--languages=C,C++",
            "-f",
            "-",
            "-L",
            str(file_list),
        ]
        result = run_command(command, cwd=root, capture_output=True)
    finally:
        remove_path(file_list)

    functions = 0
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("kind") == "function":
            functions += 1
    return functions


def write_class_metadata(
    project_class: str,
    metadata: Sequence[ProjectMetadata],
    metadata_dir: Path = METADATA_DIR,
) -> None:
    metadata_dir.mkdir(parents=True, exist_ok=True)
    path = metadata_dir / f"{project_class}_metadata.json"
    payload = {
        project.name: project.to_json()
        for project in sorted(metadata, key=lambda item: item.name)
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"\nmetadata written: {path}")


def remove_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def run_command(
    command: Sequence[str],
    cwd: Path,
    *,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            text=True,
            capture_output=capture_output,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        stdout = exc.stdout.strip() if exc.stdout else ""
        details = stderr or stdout or str(exc)
        raise DatasetBuildError(f"Command failed: {' '.join(command)}\n{details}") from exc


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DatasetBuildError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)

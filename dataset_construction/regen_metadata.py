"""Regenerate class metadata from the already-built dataset/ tree.

Unlike build_dataset.py this never clones: it recomputes source_files/loc/
functions directly from the filtered projects already present under dataset/
<class>/<project>, and looks up url/folders from dataset_construction/src/
<class>.json. Use it to repair metadata that drifted out of sync with the
dataset on disk (e.g. after a partial build or a --skip-dataset run).
"""

from __future__ import annotations

import sys

from build_dataset import (
    DATASET_DIR,
    METADATA_DIR,
    PROJECT_CLASSES,
    ProjectMetadata,
    count_functions,
    count_loc,
    iter_source_files,
    load_projects,
    require_executable,
    write_class_metadata,
)


def main() -> int:
    ctags_bin = require_executable("ctags")

    for project_class in PROJECT_CLASSES:
        class_dir = DATASET_DIR / project_class
        if not class_dir.is_dir():
            print(f"[skip] no dataset dir for class '{project_class}'")
            continue

        configs = {project.name: project for project in load_projects(project_class)}
        metadata: list[ProjectMetadata] = []

        for project_dir in sorted(p for p in class_dir.iterdir() if p.is_dir()):
            name = project_dir.name
            config = configs.get(name)
            if config is None:
                print(f"[warn] {project_class}/{name}: not in src/{project_class}.json; url/folders blank")

            source_files = sum(1 for _ in iter_source_files(project_dir))
            loc = count_loc(project_dir)
            functions = count_functions(project_dir, ctags_bin)

            print(f"[{project_class}/{name}] files={source_files} loc={loc} functions={functions}")
            metadata.append(
                ProjectMetadata(
                    name=name,
                    url=config.url if config else "",
                    project_class=project_class,
                    source_files=source_files,
                    loc=loc,
                    functions=functions,
                    folders=config.folders if config else (),
                )
            )

        write_class_metadata(project_class, metadata, METADATA_DIR)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

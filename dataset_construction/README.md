# Dataset Construction

This module downloads C/C++ repositories, filters relevant source files, and writes the resulting dataset to `dataset/<class>/<project>/`.

## Module Structure

```text
dataset_construction/
├── README.md
├── build_dataset.py        # dataset construction entrypoint
├── config.py               # C/C++ extensions and excluded directories
├── git_operations.py       # Git helper functions
├── remove_comments.py      # source cleanup utility
├── src/                    # project definitions by class
└── metadata/               # generated metadata by class
```

## Requirements

- Git
- Universal Ctags (`ctags --version` should report Universal Ctags)
  - macOS: `brew install universal-ctags`
- Python dependencies installed with `uv sync --dev`

## Build The Full Dataset

From the repository root:

```bash
uv run python dataset_construction/build_dataset.py
```

By default, this builds all configured project classes: `kernel` and `application`.

## Build A Partial Dataset

Build only one class:

```bash
uv run python dataset_construction/build_dataset.py --classes kernel
uv run python dataset_construction/build_dataset.py --classes application
```

Build only one project:

```bash
uv run python dataset_construction/build_dataset.py --classes kernel --project serenityos
```

Limit the number of projects per selected class:

```bash
uv run python dataset_construction/build_dataset.py --limit 2
```

Continue with the next project when one project fails:

```bash
uv run python dataset_construction/build_dataset.py --keep-going
```

Use a specific Universal Ctags binary:

```bash
uv run python dataset_construction/build_dataset.py --ctags-bin /path/to/ctags
```

## Staging And Output

Generated files are written to:

- filtered source trees: `dataset/<class>/<project>/`
- metadata files: `dataset_construction/metadata/<class>_metadata.json`
- temporary clones: `dataset_construction/.staging/`

The staging directory is normally cleaned after each project. Keep it for inspection with:

```bash
uv run python dataset_construction/build_dataset.py --keep-staging
```

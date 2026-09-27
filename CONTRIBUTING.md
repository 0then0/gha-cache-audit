# Contributing

## Development setup

Python 3.11+ and `uv` are required. Install the locked development environment:

```sh
uv sync --locked
```

Run the checks used by CI:

```sh
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync python -m unittest discover -s tests -v
```

To reproduce the example finding:

```sh
uv run --no-sync gha-cache-audit examples/demo
```

Ruff is the only additional development dependency. Apply formatting with
`uv run --no-sync ruff format .`; fix supported lint issues with
`uv run --no-sync ruff check --fix .`.

Tests use the standard library and the runtime YAML parser. Fixtures cover
positive and negative rules, aliases, built-in caches, matrix correlations,
malformed workflows, multiple cache blocks, suppressions, CLI behavior, and
SARIF. When adding inference behavior, include a minimal positive fixture and a
nearby negative case. Keep rule IDs stable, explain confidence, and avoid
guessing about commands the analyzer cannot model.

## Releasing

Update the version in `pyproject.toml`, `uv.lock`, and
`src/gha_cache_audit/__init__.py`. Run the checks above, commit the version
change to `main` and push it. Then create an annotated tag at that commit with
the same version:

```sh
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

The tag must match `[project].version` in `pyproject.toml`. GitHub Actions runs
the tests and Action smoke checks before building the wheel and source
distribution. It then publishes the distributions to PyPI with Trusted
Publishing and creates a GitHub Release with SHA-256 checksums and generated
release notes.

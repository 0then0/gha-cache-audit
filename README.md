# GHA Cache Auditor

[![PyPI version](https://img.shields.io/pypi/v/gha-cache-auditor)](https://pypi.org/project/gha-cache-auditor/)

GHA Cache Auditor statically checks GitHub Actions workflows for cache keys and
restore prefixes that may reuse incompatible files. It does not run workflows,
access GitHub, or modify your repository.

## Install

Python 3.11 or newer is required.

```sh
uv tool install gha-cache-auditor
```

Or install it into the active Python environment:

```sh
python -m pip install gha-cache-auditor
```

## Quick start

Run the auditor from the repository root:

```sh
gha-cache-audit .
```

For example, this cache key hashes the lockfile but does not distinguish Node.js
versions in the matrix:

```yaml
jobs:
  test:
    strategy:
      matrix:
        node: [22, 24]
    steps:
      - uses: actions/setup-node@v6
        with:
          node-version: ${{ matrix.node }}
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: deps-${{ hashFiles('package-lock.json') }}
```

The auditor reports that `matrix.node` is missing from the cache identity. A
safer key for this example is:

```yaml
key: deps-${{ runner.os }}-${{ matrix.node }}-${{ hashFiles('package-lock.json') }}
```

## What it checks

- **GHA-CACHE-001**: installed dependencies shared across runtimes or
  architectures.
- **GHA-CACHE-002**: installed dependencies shared across operating systems or
  missing an explicitly configured artifact input.
- **GHA-CACHE-003**: installed dependencies whose key does not hash the local
  lockfile or requirements file.
- **GHA-CACHE-004**: build outputs whose key omits relevant source or
  configuration inputs.
- **GHA-CACHE-005**: restore prefixes that omit runtime or platform dimensions
  used by the primary key.

The default minimum confidence is `high`. Use `--min-confidence medium` to
include medium-confidence findings. Choose text, JSON, or SARIF output with
`--format text`, `--format json`, or `--format sarif`.

## GitHub Action

Use a release tag in your workflow:

```yaml
steps:
  - uses: actions/checkout@v5
  - uses: 0then0/gha-cache-audit@vX.Y.Z
    with:
      format: sarif
      min-confidence: high
```

Replace `vX.Y.Z` with a published release tag. The Action returns a nonzero
status when it finds an issue. Its `report` output points to the generated
report file, which can be uploaded in a following step.

## Documentation

- [User guide](https://github.com/0then0/gha-cache-audit/blob/main/docs/guide.md):
  supported workflows, rule details, configuration, output, and limitations.
- [Contributing](https://github.com/0then0/gha-cache-audit/blob/main/CONTRIBUTING.md):
  development checks, tests, and release process.

Licensed under Apache-2.0; see the [LICENSE](https://github.com/0then0/gha-cache-audit/blob/main/LICENSE).

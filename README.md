# GHA Cache Auditor

Find GitHub Actions cache keys that miss inputs affecting cached artifacts.
A YAML linter can validate this workflow, while the same `node_modules` cache
is still shared by two different Node.js runtimes:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
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

```text
$ gha-cache-audit .
GHA-CACHE-001  HIGH
Potential cross-runtime cache reuse

.github/workflows/test.yml:15 (job: test)

Cache path:
  node_modules
Cache key:
  deps-${{ hashFiles('package-lock.json') }}

node_modules can be restored across different runtime or architecture configurations.
Those configurations vary in this job, but neither the key nor cache path distinguishes them.

Missing key dependency:
  matrix.node

Suggested:
  Include ${{ matrix.node }} in the cache key.
```

An appropriate key for this example is
`deps-${{ runner.os }}-${{ matrix.node }}-${{ hashFiles('package-lock.json') }}`.

## Install and run

Python 3.11+ is required. This repository is an initial MVP, not a published PyPI
release. Install from a local checkout:

```sh
uv tool install .
gha-cache-audit .
gha-cache-audit .github/workflows --format json
gha-cache-audit --workflow-dir ./ci --format json
gha-cache-audit . --format sarif > cache-audit.sarif
gha-cache-audit . --min-confidence medium
```

`pip install .` also installs the CLI. No token, GitHub App, workflow execution,
or network access is needed during analysis. The auditor never modifies workflows.
It scans immediate `.yml`/`.yaml` children of `.github/workflows`, a supplied
workflow file, or an explicitly supplied workflow directory using
`--workflow-dir`. A positional directory is treated as a repository root or the
conventional `.github/workflows` directory. File paths in reports are relative
to the inferred repository root. Dependency files are checked there, not
relative to the workflow YAML. Monorepo installed directories are associated
with dependency files in their own parent directory.

Exit codes: **0** no findings at the selected confidence, **1** findings,
**2** parse/configuration errors or explicitly unsupported workflow structures.
Diagnostics are included in JSON and SARIF, including when findings also exist.
Default confidence is `high`; `medium` includes both levels.

## Rules and confidence

- **GHA-CACHE-001**: installed dependencies shared across varying runtime or
  architecture inputs established by `setup-node` / `setup-python`. High.
- **GHA-CACHE-002**: installed dependencies lack OS partitioning in an observed
  multi-OS matrix, or omit an explicitly configured artifact input. Linux/macOS
  variation and explicitly enabled cross-OS archives are high; Windows mixing
  without that flag is medium because archive versions can partition caches.
  A single fixed OS without `runner.os` is medium because a later workflow
  revision can move the job to another OS while preserving its key.
- **GHA-CACHE-003**: an installed dependency directory has one identifiable local
  lockfile/requirements file and the key does not hash it. High when the
  platform is known; medium when unknown runner OS makes case-only hash matching
  ambiguous. Competing lockfiles are ambiguous and skipped. A package manifest
  is not a lockfile. `requirements.txt` is considered only when an install
  command explicitly names it.
  An explicit npm install without package-lock use is not charged with a
  `package-lock.json` dependency.
- **GHA-CACHE-004**: `dist`/`build`, a build command in the same directory and
  existing `src` or known configuration files not fully hashed by the key. For
  `.next/cache`, only an identifiable build configuration file is checked.
  Medium: the tool cannot prove whether later commands rebuild the output.
- **GHA-CACHE-005**: a restore prefix drops runtime/platform partitioning retained
  by the primary key. Medium: later installation might repair restored files.
  Dropping only the lockfile hash is deliberately not reported.

Recognized installed artifacts: `node_modules`, `.venv`, `venv`, including nested
paths. Dependency files: npm, pnpm, yarn, pip requirements, uv, Poetry and Pipenv.
Runtime axes are inferred from setup configuration, not guessed from matrix names.
A single fixed OS does not establish cross-platform cache reuse.

## Analysis model

The parser records cache definitions, source lines, commands, setup inputs,
matrix rows and environment aliases. An expression tokenizer distinguishes
references, string literals, function calls and `hashFiles` patterns. Artifact
classification supplies relevant runtime, platform and dependency-file inputs.
The analyzer compares those inputs with key and path dependencies, checking
whether two static matrix rows can differ in a required input while all known
key inputs remain unchanged. Correlated `matrix.include` rows are therefore not
mistaken for independent dimensions. `exclude` removes rows before comparison.

Workflow/job/step env aliases, bracket notation such as `matrix['node']`, and
setup runtime outputs are understood. Static matrix expansion is capped at 256
rows. Workflow files are capped at 2 MB. Input code is never evaluated.

The cache service also uses paths and archive properties in a hidden cache
version, so a key string alone is not the whole cache identity.
[actions/cache documentation](https://github.com/actions/cache#cache-version).

## Setup actions and intentional non-findings

Explicit built-in caching in `actions/setup-node` and `actions/setup-python` is
inventoried in JSON as an implicit cache with a managed key. The MVP trusts these
actions' cache implementations and does not reverse-engineer their key for an
arbitrary pinned revision. setup-node caches package downloads, not
`node_modules`; Node version sharing is expected. setup-python's pip key includes
OS, architecture and Python version.
[setup-node](https://github.com/actions/setup-node#caching-global-packages-data),
[setup-python implementation](https://github.com/actions/setup-python/blob/main/src/cache-distributions/pip-cache.ts).

Package download stores (`~/.npm`, pnpm store, pip/uv cache) are intentionally
not treated as installed dependency trees. Their own content/version addressing
makes unconditional runtime/lockfile warnings misleading. `.next/cache` is
incremental and can be useful after source changes, so this rule does not require
its key to hash every source file.

Limitations prioritize fewer false positives over coverage:

- Dynamic matrices in cache-bearing jobs and reusable workflow **calls** are
  reported as incomplete; reusable workflow files with ordinary jobs can be
  analyzed directly. Inputs and secrets are not resolved across callers.
- Unknown key references (including arbitrary step outputs), conditional or
  multiple runtime setup steps, conditional jobs with caches, conditional cache
  steps, and opaque paths are conservatively skipped with a diagnostic and exit
  code 2. Deep or repeatedly expanded environment aliases are also bounded and
  reported as incomplete. Statically `true`, `false` and `always()` conditions
  are handled directly.
- No shell interpretation, transitive task graph, remote actions, containers,
  arbitrary package-manager scripts or dynamic `GITHUB_ENV` evaluation.
- An expression dependency is not proof of an injective expression. Complex
  expressions may hide a collision that this tool misses.
- File glob support is a conservative approximation, not full `@actions/glob`.
  Ordered positive patterns and `!` exclusions are recognized; unusual patterns
  can be missed. Windows drive-qualified and UNC `hashFiles` patterns are reported
  as incomplete. A leading `/` is treated as repository-root-relative, as GitHub
  Actions does. Runtime version files and arbitrary configuration-file build
  graphs are not inferred. Use explicit artifact inputs where necessary.
- Cache paths that resolve outside the repository root are reported as incomplete
  and skipped; the auditor does not scan files outside the checkout.
- No finding does not prove a cache is safe. Findings describe potential reuse,
  not proof that a cached directory necessarily contains incompatible files.

## Configuration and suppressions

Optional `.gha-cache-audit.toml` at repository root (or `--config PATH`):

```toml
[[artifacts]]
path = ".cache/custom-compiler"
depends-on = ["runner.os", "matrix.compiler", "compiler.lock"]

[[suppressions]]
rule = "GHA-CACHE-005"
file = ".github/workflows/test.yml"
path = "node_modules"
reason = "Installation always repairs a partial cache match."
```

Artifact paths match exactly. Suppression file/path fields accept shell-style
globs and default to `*`; each suppression requires a non-empty reason.
Suppressions filter findings, never parsing diagnostics. Rule IDs are stable.
JSON includes compact cache inventories, evidence, missing inputs and optional
suggestions. Raw commands and environment mappings are excluded from the
inventory so multiple caches do not duplicate large job bodies.
SARIF 2.1.0 includes rules, locations, confidence and diagnostic notifications.

## GitHub Action

The composite `action.yml` installs this checkout and runs the same CLI. It uses
a temporary virtual environment and the existing Python 3.11+ on the runner;
provision Python first on self-hosted runners. No repository files are edited.

```yaml
steps:
  - uses: actions/checkout@v5
  - uses: ./ # auditor repository checkout; for consumers use OWNER/REPO@REF
    with:
      path: .
      # Optional: set this when workflows live outside .github/workflows.
      # workflow-dir: ./ci
      format: text
      min-confidence: high
```

For consumers, replace `./` with the published repository and a reviewed commit
or release tag. No official `v1` release has been published by this scaffold.
The Action returns the CLI's nonzero exit status so findings fail the job.
With `format: sarif`, its `report` output is a file in the runner's temporary
directory. Upload it in a following `if: always()` step using
`github/codeql-action/upload-sarif` and the required `security-events: write`
permission. Upload and permissions remain controlled by the caller.

## Demo and development

`examples/demo` is a small repository-shaped fixture with unsafe Node.js caching.
Run `gha-cache-audit examples/demo` to reproduce the high-confidence finding.

```sh
uv sync --locked
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync python -m unittest discover -s tests -v
```

Ruff is the only additional development dependency: it checks Python errors,
sorts imports and formats code. To apply formatting, run
`uv run --no-sync ruff format .`; to fix supported lint issues, run
`uv run --no-sync ruff check --fix .`. CI runs the same checks using the lockfile.

Tests use only the standard library plus the runtime YAML parser. Fixtures cover
positive and negative rules, aliases, built-in caches, matrix correlations,
malformed workflows, multiple cache blocks, suppressions, CLI and SARIF.
Contributions should include a minimal positive fixture and a nearby negative
case, especially when introducing a new inference. Keep rule IDs stable, explain
confidence and avoid guesses about commands that the analyzer cannot model.

Licensed under Apache-2.0; see [LICENSE](LICENSE).

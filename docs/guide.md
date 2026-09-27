# User guide

GHA Cache Auditor statically analyzes GitHub Actions workflow files to find
cache keys and restore prefixes that may allow incompatible cached files to be
reused. It does not evaluate expressions or run workflows. Findings describe
potential reuse, not proof that a cache contains incompatible files.

## Installation and invocation

Install from PyPI with Python 3.11 or newer:

```sh
uv tool install gha-cache-auditor
```

Or install into the active Python environment:

```sh
python -m pip install gha-cache-auditor
```

Run the CLI from the repository root to scan `.yml` and `.yaml` files directly
under `.github/workflows`:

```sh
gha-cache-audit .
```

The positional path can also be a workflow file or a workflow directory:

```sh
gha-cache-audit .github/workflows/test.yml
gha-cache-audit .github/workflows --format json
```

Use `--workflow-dir` when workflows are outside the conventional directory. In
that mode, the positional path is the repository root:

```sh
gha-cache-audit . --workflow-dir ./ci --format json
```

For a standalone workflow file outside a checkout, pass `--root` if the
repository root cannot be inferred from the current directory:

```sh
gha-cache-audit ./ci/test.yml --root . --format sarif > cache-audit.sarif
```

File paths in reports are relative to the inferred repository root. Dependency
files are resolved from that root, not from the workflow file. In a monorepo,
installed directories are associated with dependency files in their own parent
directory.

### Output and exit status

The default output is human-readable text. Use `--format json` for cache
inventories, findings and diagnostics, or `--format sarif` for SARIF 2.1.0.
Diagnostics are included even when findings are present.

Exit codes:

- `0`: no findings at the selected confidence.
- `1`: findings were reported.
- `2`: parse/configuration error or an unsupported workflow structure prevented
  complete analysis.

The default minimum confidence is `high`. `--min-confidence medium` includes
both high- and medium-confidence findings.

## Rules and confidence

- **GHA-CACHE-001, high**: installed dependencies are shared across runtime or
  architecture inputs established by `setup-node` or `setup-python`.
- **GHA-CACHE-002**: installed dependencies lack OS partitioning in an observed
  multi-OS matrix, or omit an explicitly configured artifact input. Linux/macOS
  variation and explicitly enabled cross-OS archives are high confidence.
  Windows mixing without that flag is medium confidence because archive
  versions can partition caches. A single fixed OS without `runner.os` is also
  medium confidence: a later workflow change could move the job to another OS
  without changing its key.
- **GHA-CACHE-003**: an installed dependency directory has one identifiable
  local lockfile or requirements file that the key does not hash. This is high
  confidence when the platform is known and medium when an unknown runner OS
  makes case-only hash matching ambiguous. Competing lockfiles are ambiguous
  and skipped. A package manifest is not a lockfile. `requirements.txt` is
  considered only when an install command explicitly names it. An explicit npm
  install that does not use a package lock is not charged with a
  `package-lock.json` dependency.
- **GHA-CACHE-004**: `dist` or `build` is cached, a build command runs in that
  directory, and existing `src` or known configuration files are not fully
  hashed by the key. For `.next/cache`, only an identifiable build configuration
  file is checked. Confidence is medium because the tool cannot prove whether
  later commands rebuild the output.
- **GHA-CACHE-005, medium**: a restore prefix drops runtime or platform
  partitioning retained by the primary key. Later installation might repair
  restored files. Dropping only the lockfile hash is deliberately not reported.

Recognized installed artifacts include `node_modules`, `.venv`, and `venv`,
including nested paths. Recognized dependency files include npm, pnpm, yarn, pip
requirements, uv, Poetry, and Pipenv. Runtime axes are inferred from setup
configuration, not guessed from matrix names. A single fixed OS does not prove
cross-platform cache reuse.

### Setup actions and intentional non-findings

Explicit built-in caching in `actions/setup-node` and `actions/setup-python` is
inventoried in JSON as an implicit cache with a managed key. The auditor trusts
these actions' cache implementations and does not reverse-engineer keys for
arbitrary pinned revisions. `setup-node` caches package downloads, not
`node_modules`; sharing Node.js versions there is expected. `setup-python`'s pip
key includes OS, architecture, and Python version.

Package download stores such as `~/.npm`, the pnpm store, and pip/uv caches are
not treated as installed dependency trees. Their own content/version addressing
makes unconditional runtime or lockfile warnings misleading. `.next/cache` is
incremental and can be useful after source changes, so its key is not required
to hash every source file.

## Configuration and suppressions

An optional `.gha-cache-audit.toml` at the repository root can define custom
artifacts and suppressions. Use `--config PATH` to select a different file.

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

Artifact paths match exactly. Suppression file and path fields accept
shell-style globs and default to `*`. Every suppression requires a non-empty
reason. Suppressions filter findings, never parsing diagnostics. Rule IDs are
stable.

## GitHub Action

The composite Action installs this checkout in a temporary virtual environment
and runs the same CLI. It uses Python 3.11+ already on the runner; provision
Python first on self-hosted runners. The Action does not edit repository files.

```yaml
steps:
  - uses: actions/checkout@v5
  - uses: 0then0/gha-cache-audit@vX.Y.Z
    with:
      # Optional when workflows are outside .github/workflows.
      # workflow-dir: ./ci
      format: sarif
      min-confidence: high
```

Replace `vX.Y.Z` with a published release tag. The Action returns the CLI's
nonzero status when it finds issues. Its `report` output points to a temporary
file containing the generated report, including when findings cause a failure.
To upload SARIF, add a following `if: always()` step using
`github/codeql-action/upload-sarif` and grant the caller's workflow the required
`security-events: write` permission. Upload and permissions remain controlled
by the caller.

## Analysis model and limitations

The parser records cache definitions, source lines, commands, setup inputs,
matrix rows, and environment aliases. An expression tokenizer distinguishes
references, string literals, function calls, and `hashFiles` patterns. The
analyzer compares key and path dependencies against artifact inputs and checks
whether two static matrix rows can differ in a required input while all known
key inputs remain unchanged. Correlated `matrix.include` rows are not treated
as independent dimensions, and `exclude` removes rows before comparison.

Workflow/job/step environment aliases, bracket notation such as
`matrix['node']`, and setup runtime outputs are understood. Static matrix
expansion is capped at 256 rows. Workflow files are capped at 2 MB. Input code
is never evaluated.

The cache service also uses paths and archive properties in a hidden cache
version, so the key string alone is not the whole cache identity. See the
[actions/cache documentation](https://github.com/actions/cache#cache-version).

The analyzer prioritizes fewer false positives over coverage:

- Dynamic matrices in cache-bearing jobs and reusable workflow **calls** are
  reported as incomplete. Reusable workflow files with ordinary jobs can be
  analyzed directly. Inputs and secrets are not resolved across callers.
- Unknown key references, including arbitrary step outputs; conditional or
  multiple runtime setup steps; conditional jobs with caches; conditional cache
  steps; and opaque paths are conservatively skipped with a diagnostic and exit
  code `2`. Deep or repeatedly expanded environment aliases are also bounded
  and reported as incomplete. Statically `true`, `false`, and `always()`
  conditions are handled directly.
- Shell interpretation, transitive task graphs, remote actions, containers,
  arbitrary package-manager scripts, and dynamic `GITHUB_ENV` evaluation are
  not modeled.
- An expression dependency is not proof of an injective expression. Complex
  expressions may hide a collision.
- File glob support is a conservative approximation, not full `@actions/glob`.
  Ordered positive patterns and `!` exclusions are recognized; unusual patterns
  can be missed. Windows drive-qualified and UNC `hashFiles` patterns are
  reported as incomplete. A leading `/` is treated as repository-root-relative,
  as GitHub Actions does. Runtime version files and arbitrary configuration
  file build graphs are not inferred. Use explicit artifact inputs when
  necessary.
- Cache paths resolving outside the repository root are reported as incomplete
  and skipped; the auditor does not scan files outside the checkout.

No finding does not prove that a cache is safe. Findings identify potential
reuse, not proof that cached files are incompatible.

"""Artifact dependencies compared with key inputs; no workflow execution."""

import re
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from .expressions import dependencies
from .model import RULES, Cache, Finding

LOCKS = {
    "node": ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"),
    "python": ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"),
}
BUILD_CONFIGS = (
    "package.json",
    "tsconfig.json",
    "webpack.config.js",
    "vite.config.js",
    "vite.config.ts",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
)
MATRIX_EVIDENCE_MAX_VALUES = 10
MATRIX_EVIDENCE_MAX_VALUE_LENGTH = 120


def scalar(value):
    """Values interpolated into action inputs and cache keys are strings."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def summarize_matrix(rows, dimensions):
    """Return bounded examples for matrix dimensions relevant to a finding."""
    summary = {}
    for dimension in sorted(dimensions):
        values = sorted({scalar(row.get(dimension)) for row in rows})
        examples = [
            value
            if len(value) <= MATRIX_EVIDENCE_MAX_VALUE_LENGTH
            else value[: MATRIX_EVIDENCE_MAX_VALUE_LENGTH - 3] + "..."
            for value in values[:MATRIX_EVIDENCE_MAX_VALUES]
        ]
        summary[dimension] = {
            "distinct_values": len(values),
            "examples": examples,
            "truncated": len(values) > len(examples)
            or any(len(value) > MATRIX_EVIDENCE_MAX_VALUE_LENGTH for value in values),
        }
    return summary


def matches(path: str, pattern: str, ignore_case: bool = False) -> bool:
    if pattern.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[/\\]", pattern):
        return False
    parts = path.replace("\\", "/").lstrip("/").split("/")
    glob = pattern.removeprefix("./").strip("/").split("/")
    if ignore_case:
        parts = [part.lower() for part in parts]
        glob = [part.lower() for part in glob]
    positions = {0}
    for segment in glob:
        if segment == "**":
            positions = set(range(min(positions), len(parts) + 1))
        else:
            positions = {
                index + 1
                for index in positions
                if index < len(parts) and fnmatchcase(parts[index], segment)
            }
        if not positions:
            return False
    return bool(positions)


def hashed(path: str, pattern_groups: list[tuple[str, ...]], ignore_case=False) -> bool:
    for patterns in pattern_groups:
        included = False
        for pattern in patterns:
            bangs = len(pattern) - len(pattern.lstrip("!"))
            if matches(path, pattern[bangs:], ignore_case):
                included = bangs % 2 == 0
        if included:
            return True
    return False


def classify(path: str):
    normalized = path.replace("\\", "/").removeprefix("./").rstrip("/")
    if "${{" in normalized or any(c in normalized for c in "*?~"):
        return None
    name = PurePosixPath(normalized).name
    if name == "node_modules":
        return "node", normalized
    if name in {".venv", "venv"}:
        return "python", normalized
    if name in {"dist", "build"}:
        return "build", normalized
    if normalized.endswith("/.next/cache") or normalized == ".next/cache":
        return "incremental", normalized
    return None


def varying(rows):
    names = set().union(*(r.keys() for r in rows)) if rows else set()
    return {name for name in names if len({scalar(r.get(name)) for r in rows}) > 1}


def platform(row, runner, aliases):
    runner_refs = dependencies(runner, aliases)
    refs = [r for r in runner_refs.refs if r.startswith("matrix.")]
    labels = (
        [str(row.get(r[7:], "")).lower() for r in refs]
        if refs
        else [runner.lower()]
        if isinstance(runner, str)
        else []
    )
    for label in labels:
        if label.startswith("ubuntu-"):
            return "linux"
        if label.startswith("macos-"):
            return "macos"
        if label.startswith("windows-"):
            return "windows"
    return None


def collision(rows, required, covered, runner="", aliases=None):
    """Correlated include rows may be separated by a different matrix input."""
    names = {r[7:] for r in covered if r.startswith("matrix.")}
    for i, left in enumerate(rows):
        for right in rows[i + 1 :]:
            if "runner.os" in covered:
                a, b = platform(left, runner, aliases), platform(right, runner, aliases)
                if a is not None and b is not None and a != b:
                    continue
            if scalar(left.get(required)) != scalar(right.get(required)) and all(
                scalar(left.get(n)) == scalar(right.get(n)) for n in names
            ):
                return True
    return False


def platform_pairs(rows, covered, runner, aliases):
    if "runner.os" in covered:
        return set()
    names = {r[7:] for r in covered if r.startswith("matrix.")}
    pairs = set()
    for index, left in enumerate(rows):
        for right in rows[index + 1 :]:
            a, b = platform(left, runner, aliases), platform(right, runner, aliases)
            if (
                a is not None
                and b is not None
                and a != b
                and all(scalar(left.get(n)) == scalar(right.get(n)) for n in names)
            ):
                pairs.add(frozenset((a, b)))
    return pairs


def local_files(root: Path, parent: str, names):
    return [
        str(PurePosixPath(parent) / n) for n in names if (root / parent / n).is_file()
    ]


def npm_ignores_lock(commands, npmrc: Path) -> bool:
    installs = []
    for command in commands:
        for line in str(command.get("run", "")).splitlines():
            line = line.strip()
            if re.search(r"(?:^|&&|\|\||[;|])\s*npm\s+ci\b", line):
                return False
            if re.match(r"^npm\s+(?:install|i)\b", line):
                if any(operator in line for operator in ("&&", ";", "|")):
                    return False
                installs.append(line)
    if not installs:
        return False
    if all(
        re.search(r"(?:--no-package-lock\b|--package-lock=false\b)", line)
        for line in installs
    ):
        return True
    return (
        npmrc.is_file()
        and not any("--package-lock=true" in line for line in installs)
        and bool(
            re.search(
                r"(?m)^\s*package-lock\s*=\s*false\s*$",
                npmrc.read_text(encoding="utf-8"),
            )
        )
    )


def analyze(cache: Cache, root: Path, overrides=(), source_cache=None) -> list[Finding]:
    findings = []
    key = dependencies(cache.key, cache.aliases)
    if cache.implicit or cache.uncertain or key.opaque:
        return findings
    revision_key = bool(key.refs & {"github.sha", "github.run_id", "github.run_number"})
    dimensions = varying(cache.matrix)
    ignore_case = any(
        platform(row, cache.runner, cache.aliases) not in {"linux", "macos"}
        for row in cache.matrix
    )
    path_inputs = dependencies("\n".join(cache.paths), cache.aliases)
    # Different cache paths contribute to the service's hidden cache version.
    covered = key.refs | path_inputs.refs
    runner_inputs = dependencies(cache.runner, cache.aliases)
    for original_path in cache.paths:
        kind_path = classify(original_path)
        custom = next((o for o in overrides if o["path"] == original_path), None)
        if not kind_path and not custom:
            continue
        kind, path = kind_path or ("custom", original_path)
        parent = str(PurePosixPath(path).parent)
        required = set()
        runtime = dependencies(cache.runtimes.get(kind, ""), cache.aliases)
        if not runtime.opaque:
            required.update(runtime.refs)
        if kind in {"node", "python"}:
            required.update(
                dependencies(cache.runtimes.get(kind + ".arch", ""), cache.aliases).refs
            )
        if custom:
            for dependency in custom.get("depends-on", []):
                if dependency.startswith(("matrix.", "runner.", "env.")):
                    resolved = dependencies("${{ " + dependency + " }}", cache.aliases)
                    other_refs = resolved.refs - {dependency.lower()}
                    required.update(other_refs or {dependency.lower()})
        runtime_missing = sorted(
            r
            for r in required
            if r.startswith("matrix.")
            and r[7:] in dimensions
            and collision(cache.matrix, r[7:], covered, cache.runner, cache.aliases)
        )

        def add(rule, confidence, missing, explanation, suggestion=None, evidence=None):
            findings.append(
                Finding(
                    rule,
                    confidence,
                    cache.file,
                    cache.line,
                    cache.job,
                    original_path,
                    cache.key,
                    RULES[rule],
                    explanation,
                    missing,
                    suggestion,
                    evidence or {},
                )
            )

        if runtime_missing:
            add(
                "GHA-CACHE-001",
                "high",
                runtime_missing,
                f"{original_path} can be restored across different runtime or architecture configurations. "
                "Those configurations vary in this job, but neither the key nor cache path distinguishes them.",
                "Include "
                + ", ".join("${{ " + r + " }}" for r in runtime_missing)
                + " in the cache key.",
                {
                    "matrix": summarize_matrix(
                        cache.matrix, {ref[7:] for ref in runtime_missing}
                    ),
                    "runtime_inputs": sorted(required),
                    "key_inputs": sorted(key.refs),
                },
            )
        platform_refs = {
            r
            for r in runner_inputs.refs
            if r.startswith("matrix.") and r[7:] in dimensions
        }
        platform_missing = [
            r
            for r in platform_refs
            if collision(cache.matrix, r[7:], covered, cache.runner, cache.aliases)
        ]
        if kind in {"node", "python"} and "runner.os" not in key.refs:
            crossing = platform_pairs(
                cache.matrix, covered, cache.runner, cache.aliases
            )
            if platform_missing and crossing:
                confidence = (
                    "high"
                    if cache.cross_os or frozenset(("linux", "macos")) in crossing
                    else "medium"
                )
                add(
                    "GHA-CACHE-002",
                    confidence,
                    ["runner.os"],
                    f"{original_path} may contain platform-specific installed files, while the job runs on multiple operating systems. "
                    "The key does not distinguish these platforms. Cache archive compatibility may also limit reuse.",
                    "Include ${{ runner.os }} in the cache key.",
                )
            elif (
                not platform_refs
                and not revision_key
                and not hashed(cache.file, key.files, ignore_case)
                and platform({}, cache.runner, cache.aliases)
            ):
                add(
                    "GHA-CACHE-002",
                    "medium",
                    ["runner.os"],
                    f"{original_path} is installed on a fixed runner platform, but its key has no OS input. "
                    "Changing runs-on in a later workflow revision may reuse an older platform's cache.",
                    "Include ${{ runner.os }} in the cache key.",
                )
        expected = local_files(root, parent, LOCKS.get(kind, ()))
        if (
            kind == "node"
            and any(PurePosixPath(f).name == "package-lock.json" for f in expected)
            and npm_ignores_lock(cache.commands, root / parent / ".npmrc")
        ):
            expected = [
                f for f in expected if PurePosixPath(f).name != "package-lock.json"
            ]
        if custom:
            expected += [
                d
                for d in custom.get("depends-on", [])
                if not d.startswith(("matrix.", "runner.", "env."))
            ]
        # Multiple competing managers in one directory are ambiguous.
        missing_files = (
            [f for f in expected if not hashed(f, key.files, ignore_case)]
            if custom or len(expected) == 1
            else []
        )
        if missing_files and not revision_key:
            add(
                "GHA-CACHE-003",
                "high",
                missing_files,
                f"{original_path} depends on files not hashed by its key: {', '.join(missing_files)}. "
                "Changing that dependency file can leave the same cache key.",
                "Include ${{ hashFiles("
                + ", ".join("'" + f.replace("'", "''") + "'" for f in missing_files)
                + ") }} in the cache key.",
            )
        if custom:
            missing = sorted(
                r for r in required if not r.startswith("matrix.") and r not in covered
            )
            if missing:
                add(
                    "GHA-CACHE-002",
                    "high",
                    missing,
                    "The cache key omits explicitly configured artifact inputs.",
                )
        if kind in {"build", "incremental"}:
            project = (
                str(PurePosixPath(path).parent.parent)
                if kind == "incremental"
                else parent
            )
            build_commands = [
                c
                for c in cache.commands
                if str(c.get("working-directory", ".")).removeprefix("./").rstrip("/")
                == project
                and re.search(
                    r"\b(?:npm run build|pnpm (?:run )?build|yarn (?:run )?build|next build)\b",
                    str(c.get("run", "")),
                )
            ]
            missing_build = []
            if kind == "build":
                sources = None if source_cache is None else source_cache.get(project)
                if sources is None:
                    source_root = root / project / "src"
                    sources = (
                        [
                            f.relative_to(root).as_posix()
                            for f in source_root.rglob("*")
                            if f.is_file()
                        ]
                        if source_root.is_dir()
                        else []
                    )
                    if source_cache is not None:
                        source_cache[project] = sources
                if sources and not all(
                    hashed(f, key.files, ignore_case) for f in sources
                ):
                    missing_build.append(str(PurePosixPath(project) / "src/**"))
            configs = local_files(root, project, BUILD_CONFIGS)
            missing_build.extend(
                f for f in configs if not hashed(f, key.files, ignore_case)
            )
            if not revision_key and build_commands and missing_build:
                add(
                    "GHA-CACHE-004",
                    "medium",
                    missing_build,
                    f"A build command runs in {project}, but {original_path}'s key does not hash these source/configuration inputs. "
                    "Restored output may be stale if a later step consumes it without a complete rebuild.",
                )
        if kind in {"node", "python"}:
            protected = required | platform_refs
            for prefix in cache.restore_keys:
                partial = dependencies(prefix, cache.aliases)
                if partial.opaque:
                    continue
                missing = sorted(
                    r
                    for r in protected
                    if r in covered
                    and r not in partial.refs
                    and r.startswith("matrix.")
                    and r[7:] in dimensions
                    and collision(
                        cache.matrix,
                        r[7:],
                        partial.refs | path_inputs.refs,
                        cache.runner,
                        cache.aliases,
                    )
                )
                if "runner.os" in key.refs and platform_pairs(
                    cache.matrix,
                    partial.refs | path_inputs.refs,
                    cache.runner,
                    cache.aliases,
                ):
                    missing.append("runner.os")
                if missing:
                    add(
                        "GHA-CACHE-005",
                        "medium",
                        sorted(set(missing)),
                        f"Restore prefix {prefix!r} drops configuration inputs retained by the primary key. "
                        "A partial match can restore incompatible installed dependencies unless a later step repairs them.",
                        evidence={"restore_key": prefix},
                    )
    return findings

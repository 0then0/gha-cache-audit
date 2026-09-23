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


def matches(path: str, pattern: str) -> bool:
    pattern = pattern.removeprefix("./")
    return fnmatchcase(path, pattern) or (
        pattern.startswith("**/") and fnmatchcase(path, pattern[3:])
    )


def hashed(path: str, patterns: set[str]) -> bool:
    return any(matches(path, p) for p in patterns if not p.startswith("!")) and not any(
        matches(path, p[1:]) for p in patterns if p.startswith("!")
    )


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
    return None


def varying(rows):
    names = set().union(*(r.keys() for r in rows)) if rows else set()
    return {name for name in names if len({repr(r.get(name)) for r in rows}) > 1}


def platform(row, runner, aliases):
    runner_refs = dependencies(runner, aliases)
    refs = [r for r in runner_refs.refs if r.startswith("matrix.")]
    labels = (
        [str(row.get(r[7:], "")).lower() for r in refs]
        if refs
        else [str(runner).lower()]
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
            if left.get(required) != right.get(required) and all(
                left.get(n) == right.get(n) for n in names
            ):
                return True
    return False


def platform_collision(rows, covered, runner, aliases):
    if "runner.os" in covered:
        return False
    names = {r[7:] for r in covered if r.startswith("matrix.")}
    for index, left in enumerate(rows):
        for right in rows[index + 1 :]:
            a, b = platform(left, runner, aliases), platform(right, runner, aliases)
            if (
                a is not None
                and b is not None
                and a != b
                and all(left.get(n) == right.get(n) for n in names)
            ):
                return True
    return False


def local_files(root: Path, parent: str, names):
    return [
        str(PurePosixPath(parent) / n) for n in names if (root / parent / n).is_file()
    ]


def analyze(cache: Cache, root: Path, overrides=()) -> list[Finding]:
    findings = []
    key = dependencies(cache.key, cache.aliases)
    if cache.implicit or cache.uncertain or key.opaque:
        return findings
    revision_key = bool(key.refs & {"github.sha", "github.run_id", "github.run_number"})
    dimensions = varying(cache.matrix)
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
                    required.update(
                        dependencies("${{ " + dependency + " }}", cache.aliases).refs
                    )
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
                    "matrix": cache.matrix,
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
        if (
            kind in {"node", "python"}
            and platform_missing
            and not key.refs & {"runner.os"}
        ):
            # OS differences must be observed, not merely a differently named runner.
            values = {
                str(row.get(r[7:], "")).lower()
                for row in cache.matrix
                for r in platform_missing
            }
            systems = {
                "linux"
                if v.startswith("ubuntu-")
                else "macos"
                if v.startswith("macos-")
                else "windows"
                if v.startswith("windows-")
                else "unknown"
                for v in values
            }
            if len(systems - {"unknown"}) > 1:
                confidence = (
                    "high"
                    if cache.cross_os or {"linux", "macos"} <= systems
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
        expected = local_files(root, parent, LOCKS.get(kind, ()))
        if custom:
            expected += [
                d
                for d in custom.get("depends-on", [])
                if not d.startswith(("matrix.", "runner.", "env."))
            ]
        # Multiple competing managers in one directory are ambiguous.
        missing_files = (
            [f for f in expected if not hashed(f, key.files)]
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
        if kind == "build":
            build_commands = [
                c
                for c in cache.commands
                if str(c.get("working-directory", ".")).removeprefix("./").rstrip("/")
                == parent
                and re.search(
                    r"\b(?:npm run build|pnpm (?:run )?build|yarn (?:run )?build)\b",
                    str(c.get("run", "")),
                )
            ]
            sources = (
                [
                    f.relative_to(root).as_posix()
                    for f in (root / parent / "src").rglob("*")
                    if f.is_file()
                ]
                if (root / parent / "src").is_dir()
                else []
            )
            if (
                not revision_key
                and build_commands
                and sources
                and not any(hashed(f, key.files) for f in sources)
            ):
                add(
                    "GHA-CACHE-004",
                    "medium",
                    [str(PurePosixPath(parent) / "src/**")],
                    f"A build command runs in {parent} and source files exist, but {original_path}'s key hashes none of them. "
                    "This matters if restored output is consumed without a complete rebuild.",
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
                if "runner.os" in key.refs and platform_collision(
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

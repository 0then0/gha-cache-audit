"""Filesystem-only CLI. Exit codes: 0 clean, 1 findings, 2 incomplete analysis."""

import argparse
import sys
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path

from . import __version__
from .analysis import analyze
from .model import RULES, Diagnostic
from .report import render
from .workflow import parse


def discover(target):
    target = target.absolute()
    if target.is_file():
        root = (
            target.parent.parent.parent
            if target.parent.name == "workflows"
            and target.parent.parent.name == ".github"
            else target.parent
        )
        root = root.resolve()
        resolved_target = target.resolve()
        if not resolved_target.is_relative_to(root):
            raise ValueError(
                f"workflow path resolves outside the repository root: {target}"
            )
        return root, [resolved_target]
    if not target.is_dir():
        raise ValueError(f"path does not exist: {target}")
    target = target.resolve()
    if target.name == "workflows" and target.parent.name == ".github":
        root, directory = target.parent.parent, target
    else:
        root, directory = target, target / ".github/workflows"
        # A repository root means its conventional workflow directory. Do not
        # interpret unrelated YAML (for example compose.yml) as a workflow.
        if not directory.is_dir():
            repository_markers = (
                ".git",
                ".github",
                "pyproject.toml",
                "package.json",
                "package-lock.json",
                "requirements.txt",
                "Cargo.toml",
                "go.mod",
            )
            yaml_files = [
                p
                for p in target.iterdir()
                if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
            ]
            if yaml_files and (
                "workflow" in target.name.lower()
                or not any((target / marker).exists() for marker in repository_markers)
            ):
                directory = target
            else:
                return root, []
    root = root.resolve()
    paths = sorted(
        p
        for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
    )
    for path in paths:
        if not path.resolve().is_relative_to(root):
            raise ValueError(
                f"workflow path resolves outside the repository root: {path}"
            )
    return root, paths


def configuration(path):
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(data) - {"suppressions", "artifacts"}:
        raise ValueError("unknown configuration key")
    for section in ("suppressions", "artifacts"):
        if not isinstance(data.get(section, []), list) or any(
            not isinstance(v, dict) for v in data.get(section, [])
        ):
            raise ValueError(f"{section} must be an array of tables")
    for item in data.get("suppressions", []):
        if (
            set(item) - {"rule", "file", "path", "reason"}
            or item.get("rule") not in RULES
            or not isinstance(item.get("reason"), str)
            or not item["reason"].strip()
        ):
            raise ValueError("suppressions require a known rule and a non-empty reason")
        if any(not isinstance(item.get(k, "*"), str) for k in ("file", "path")):
            raise ValueError("suppression file and path must be strings")
    for item in data.get("artifacts", []):
        if (
            set(item) - {"path", "depends-on"}
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("depends-on"), list)
            or any(not isinstance(d, str) or not d for d in item["depends-on"])
        ):
            raise ValueError("artifacts require path and a depends-on string list")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Find potentially incomplete GitHub Actions cache keys."
    )
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--min-confidence", choices=("high", "medium"), default="high")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    caches, findings, diagnostics = [], [], []
    source_cache = {}
    try:
        root, paths = discover(Path(args.path))
        if args.config and not args.config.is_file():
            raise ValueError(f"configuration does not exist: {args.config}")
        config_path = args.config or root / ".gha-cache-audit.toml"
        if not args.config and not config_path.resolve().is_relative_to(root):
            raise ValueError(
                "default configuration resolves outside the repository root"
            )
        config = configuration(config_path)
        if not paths:
            diagnostics.append(
                Diagnostic(str(args.path), 1, "no workflow YAML files found")
            )
        for path in paths:
            found, errors = parse(path, root)
            caches.extend(found)
            diagnostics.extend(errors)
            for cache in found:
                for finding in analyze(
                    cache, root, config.get("artifacts", []), source_cache
                ):
                    if args.min_confidence == "high" and finding.confidence != "high":
                        continue
                    if any(
                        finding.rule_id == s["rule"]
                        and fnmatchcase(finding.file, s.get("file", "*"))
                        and fnmatchcase(finding.cache_path, s.get("path", "*"))
                        for s in config.get("suppressions", [])
                    ):
                        continue
                    findings.append(finding)
    except (OSError, UnicodeError, ValueError) as exc:
        diagnostics.append(Diagnostic(str(args.path), 1, str(exc)))
    print(render(findings, diagnostics, caches, args.format))
    return 2 if diagnostics else 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

"""Filesystem-only CLI. Exit codes: 0 clean, 1 findings, 2 incomplete analysis."""

import argparse
import os
import sys
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path

from . import __version__
from .analysis import analyze
from .model import RULES, Diagnostic
from .report import render
from .workflow import parse


def discover(target, workflow_directory=False):
    input_path = target.absolute()
    target = Path(os.path.normpath(input_path))
    if workflow_directory:
        if not input_path.is_dir():
            raise ValueError(f"workflow directory does not exist: {target}")
        checkout = next(
            (
                parent
                for parent in (target, *target.parents)
                if (parent / ".git").exists()
            ),
            None,
        )
        root = (
            target.parent.parent
            if target.name == "workflows" and target.parent.name == ".github"
            else checkout or target
        ).resolve()
        directory = input_path.resolve()
        if not directory.is_relative_to(root):
            raise ValueError(
                f"workflow directory resolves outside the repository root: {target}"
            )
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
    if input_path.is_file():
        root = (
            target.parent.parent.parent
            if target.parent.name == "workflows"
            and target.parent.parent.name == ".github"
            else target.parent
        )
        root = root.resolve()
        resolved_target = input_path.resolve()
        if not resolved_target.is_relative_to(root):
            raise ValueError(
                f"workflow path resolves outside the repository root: {target}"
            )
        return root, [resolved_target]
    if not input_path.is_dir():
        raise ValueError(f"path does not exist: {target}")
    resolved_target = input_path.resolve()
    if target.name == "workflows" and target.parent.name == ".github":
        root, directory = target.parent.parent.resolve(), resolved_target
    else:
        root, directory = resolved_target, resolved_target / ".github/workflows"
        if not directory.is_dir():
            return root, []
    if not directory.resolve().is_relative_to(root):
        raise ValueError(
            f"workflow directory resolves outside the repository root: {directory}"
        )
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
    parser.add_argument(
        "--workflow-dir",
        type=Path,
        help="analyze this directory as workflows instead of a repository root",
    )
    args = parser.parse_args(argv)
    caches, findings, diagnostics = [], [], []
    source_cache = {}
    try:
        root, paths = discover(
            args.workflow_dir or Path(args.path),
            workflow_directory=args.workflow_dir is not None,
        )
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

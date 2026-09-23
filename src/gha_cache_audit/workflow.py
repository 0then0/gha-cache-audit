"""Safe YAML loading, static matrix expansion and cache discovery."""

import itertools
import math
import re
from pathlib import Path

import yaml

from .expressions import dependencies
from .model import Cache, Diagnostic


class Mapping(dict):
    line = 1


class Loader(yaml.SafeLoader):
    pass


# GitHub workflows use YAML 1.2 booleans: `on` must remain a string.
Loader.yaml_implicit_resolvers = {
    key: [
        (tag, pattern)
        for tag, pattern in values
        if tag not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp"}
    ]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"),
    list("tTfF"),
)


def mapping(loader, node):
    result = Mapping()
    result.line = node.start_mark.line + 1
    loader.flatten_mapping(node)
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool)):
            raise ValueError(
                f"line {node.start_mark.line + 1}: unsupported mapping key"
            )
        if key in result:
            raise ValueError(
                f"line {key_node.start_mark.line + 1}: duplicate mapping key {key!r}"
            )
        result[key] = loader.construct_object(value_node, deep=True)
    return result


Loader.add_constructor("tag:yaml.org,2002:map", mapping)


def as_map(value):
    return value if isinstance(value, dict) else {}


def lines(value):
    return [line.strip() for line in str(value or "").splitlines() if line.strip()]


def matrix_rows(value):
    if value is None:
        return [{}], False
    if not isinstance(value, dict):
        return [], True
    dimensions = {
        str(k).lower(): v for k, v in value.items() if k not in {"include", "exclude"}
    }
    if any(
        not isinstance(v, list)
        or any(isinstance(x, (dict, list)) or "${{" in str(x) for x in v)
        for v in dimensions.values()
    ):
        return [], True
    count = 1
    for values in dimensions.values():
        count *= len(values)
    include, exclude = value.get("include", []), value.get("exclude", [])
    if count > 256 or not isinstance(include, list) or not isinstance(exclude, list):
        return [], True
    if any(
        not isinstance(row, dict)
        or any(isinstance(v, (dict, list)) or "${{" in str(v) for v in row.values())
        for row in include + exclude
    ):
        return [], True
    include = [{str(k).lower(): v for k, v in r.items()} for r in include]
    exclude = [{str(k).lower(): v for k, v in r.items()} for r in exclude]
    original = (
        [
            dict(zip(dimensions, values))
            for values in itertools.product(*dimensions.values())
        ]
        if dimensions
        else []
    )
    original = [
        r
        for r in original
        if not any(all(r.get(k) == v for k, v in e.items()) for e in exclude)
    ]
    rows = [dict(r) for r in original]
    for extra in include:
        matched = False
        for index, base in enumerate(original):
            if all(k not in base or base[k] == v for k, v in extra.items()):
                rows[index].update(extra)
                matched = True
        if not matched:
            rows.append(extra)
    return (rows, False) if len(rows) <= 256 else ([], True)


def validate_data(value, active=None, depth=0):
    """Reject YAML-only values and cycles before they enter JSON reports."""
    active = set() if active is None else active
    if depth > 100 or id(value) in active:
        raise ValueError("workflow contains a cyclic or deeply nested YAML structure")
    if isinstance(value, (dict, list)):
        active.add(id(value))
        for child in value.values() if isinstance(value, dict) else value:
            validate_data(child, active, depth + 1)
        active.remove(id(value))
    elif (
        not isinstance(value, (str, int, float, bool, type(None)))
        or isinstance(value, float)
        and not math.isfinite(value)
    ):
        raise ValueError("workflow contains an unsupported YAML value")


def parse(path: Path, root: Path):
    name = (
        path.relative_to(root).as_posix()
        if path.is_relative_to(root)
        else path.as_posix()
    )
    try:
        if path.stat().st_size > 2_000_000:
            raise ValueError("workflow exceeds the 2 MB analysis limit")
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader)
        validate_data(data)
        if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
            raise ValueError("expected a workflow mapping with jobs")
    except (OSError, UnicodeError, ValueError, yaml.YAMLError, RecursionError) as exc:
        mark = getattr(exc, "problem_mark", None)
        return [], [Diagnostic(name, mark.line + 1 if mark else 1, str(exc))]
    caches, diagnostics = [], []
    for job_id, job in data["jobs"].items():
        if not isinstance(job, dict):
            diagnostics.append(Diagnostic(name, 1, f"job {job_id}: expected a mapping"))
            continue
        if "uses" in job:
            diagnostics.append(
                Diagnostic(
                    name,
                    getattr(job, "line", 1),
                    f"job {job_id}: reusable workflow call is not expanded",
                )
            )
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list) or any(not isinstance(s, dict) for s in steps):
            diagnostics.append(
                Diagnostic(
                    name,
                    getattr(job, "line", 1),
                    f"job {job_id}: expected a list of step mappings",
                )
            )
            continue
        rows, dynamic = matrix_rows(as_map(job.get("strategy")).get("matrix"))
        if dynamic:
            diagnostics.append(
                Diagnostic(
                    name,
                    getattr(job, "line", 1),
                    f"job {job_id}: dynamic or oversized matrix; cache analysis skipped",
                )
            )
        aliases = {
            "env." + str(k).lower(): v
            for scope in (data, job)
            for k, v in as_map(scope.get("env")).items()
        }
        runtimes, setups = {}, {}
        commands = []
        for step in steps:
            action = str(step.get("uses", "")).split("@")[0].lower()
            inputs = as_map(step.get("with"))
            kind = {"actions/setup-node": "node", "actions/setup-python": "python"}.get(
                action
            )
            if kind:
                setups.setdefault(kind, []).append(step)
            if "run" in step:
                command = dict(step)
                command.setdefault(
                    "working-directory",
                    as_map(as_map(job.get("defaults")).get("run")).get(
                        "working-directory",
                        as_map(as_map(data.get("defaults")).get("run")).get(
                            "working-directory", "."
                        ),
                    ),
                )
                commands.append(command)
        uncertain = dynamic or "if" in job
        for kind, candidates in setups.items():
            if len(candidates) != 1 or "if" in candidates[0]:
                uncertain = True
                continue
            setup = candidates[0]
            inputs = as_map(setup.get("with"))
            value = inputs.get(f"{kind}-version", "")
            # Resolve setup-local env aliases before using its runtime input.
            setup_env = {
                "env." + str(k).lower(): v for k, v in as_map(setup.get("env")).items()
            }
            deps = dependencies(value, aliases | setup_env)
            runtimes[kind] = (
                " ".join("${{ " + r + " }}" for r in deps.refs)
                if not deps.opaque
                else "${{ unknown.runtime }}"
            )
            arch = dependencies(inputs.get("architecture", ""), aliases | setup_env)
            runtimes[kind + ".arch"] = (
                " ".join("${{ " + r + " }}" for r in arch.refs)
                if not arch.opaque
                else "${{ unknown.arch }}"
            )
            if setup.get("id"):
                aliases[f"steps.{str(setup['id']).lower()}.outputs.{kind}-version"] = (
                    runtimes[kind]
                )
        for step in steps:
            action = str(step.get("uses", "")).split("@")[0].lower()
            inputs = as_map(step.get("with"))
            implicit = action in {
                "actions/setup-node",
                "actions/setup-python",
            } and bool(inputs.get("cache"))
            if (
                action
                not in {"actions/cache", "actions/cache/restore", "actions/cache/save"}
                and not implicit
            ):
                continue
            if "if" in step:
                continue
            if str(inputs.get("lookup-only", "false")).lower() == "true":
                continue
            env = aliases | {
                "env." + str(k).lower(): v for k, v in as_map(step.get("env")).items()
            }
            paths = (
                lines(inputs.get("path"))
                if not implicit
                else [f"<{action}: {inputs['cache']} package cache>"]
            )
            key = (
                str(inputs.get("key", ""))
                if not implicit
                else "<managed by setup action>"
            )
            if not paths or not key:
                diagnostics.append(
                    Diagnostic(
                        name,
                        getattr(step, "line", 1),
                        "cache definition requires non-empty path and key",
                    )
                )
                continue
            caches.append(
                Cache(
                    name,
                    getattr(inputs, "line", getattr(step, "line", 1)),
                    str(job_id),
                    action,
                    paths,
                    key,
                    lines(inputs.get("restore-keys")),
                    env,
                    runtimes,
                    rows,
                    job.get("runs-on", ""),
                    commands,
                    str(inputs.get("enableCrossOsArchive", "false")).lower() == "true",
                    implicit,
                    uncertain,
                )
            )
    return caches, diagnostics

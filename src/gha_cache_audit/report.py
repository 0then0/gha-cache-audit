"""Stable machine reports and readable console output."""

import json
from dataclasses import asdict
from urllib.parse import quote

from . import __version__
from .model import RULES


def cache_summary(cache):
    return {
        "file": cache.file,
        "line": cache.line,
        "job": cache.job,
        "action": cache.action,
        "paths": cache.paths,
        "key": cache.key,
        "restore_keys": cache.restore_keys,
        "implicit": cache.implicit,
        "uncertain": cache.uncertain,
    }


def render(findings, diagnostics, caches, output_format):
    if output_format == "json":
        return json.dumps(
            {
                "version": __version__,
                "findings": [asdict(f) for f in findings],
                "diagnostics": [asdict(d) for d in diagnostics],
                "caches": [cache_summary(c) for c in caches],
            },
            indent=2,
        )
    if output_format == "sarif":
        rules = [
            {"id": key, "shortDescription": {"text": title}}
            for key, title in RULES.items()
        ]
        results = []
        for f in findings:
            message = f.explanation + (
                " Suggested: " + f.suggestion if f.suggestion else ""
            )
            results.append(
                {
                    "ruleId": f.rule_id,
                    "ruleIndex": list(RULES).index(f.rule_id),
                    "level": "warning",
                    "message": {"text": message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": quote(f.file, safe="/")},
                                "region": {"startLine": f.line},
                            }
                        }
                    ],
                    "properties": {
                        "confidence": f.confidence,
                        "cachePath": f.cache_path,
                        "cacheKey": f.cache_key,
                        "missing": f.missing,
                    },
                }
            )
        return json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "GHA Cache Auditor",
                                "version": __version__,
                                "rules": rules,
                            }
                        },
                        "results": results,
                        "invocations": [
                            {
                                "executionSuccessful": not diagnostics,
                                "toolExecutionNotifications": [
                                    {
                                        "level": "warning",
                                        "message": {
                                            "text": f"{d.file}:{d.line}: {d.message}"
                                        },
                                    }
                                    for d in diagnostics
                                ],
                            }
                        ],
                    }
                ],
            },
            indent=2,
        )
    blocks = []
    for f in findings:
        block = (
            f"{f.rule_id}  {f.confidence.upper()}\n{f.title}\n\n{f.file}:{f.line} (job: {f.job})\n\nCache path:\n  {f.cache_path}\nCache key:\n  {f.cache_key}\n\n{f.explanation}\n\nMissing key dependency:\n  "
            + "\n  ".join(f.missing)
        )
        if f.suggestion:
            block += "\n\nSuggested:\n  " + f.suggestion
        blocks.append(block)
    blocks += [
        f"Analysis diagnostic: {d.file}:{d.line}: {d.message}" for d in diagnostics
    ]
    return (
        "\n\n".join(blocks)
        if blocks
        else f"No findings ({len(caches)} cache definitions analyzed)."
    )

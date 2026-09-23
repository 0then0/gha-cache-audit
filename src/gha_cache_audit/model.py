"""Serializable analysis records shared by the parser, rules and reporters."""

from dataclasses import dataclass, field
from typing import Any

RULES = {
    "GHA-CACHE-001": "Potential cross-runtime cache reuse",
    "GHA-CACHE-002": "Missing platform dependency",
    "GHA-CACHE-003": "Missing dependency-file invalidation",
    "GHA-CACHE-004": "Potential stale build output",
    "GHA-CACHE-005": "Potential cross-configuration partial match",
}


@dataclass
class Cache:
    file: str
    line: int
    job: str
    action: str
    paths: list[str]
    key: str
    restore_keys: list[str]
    aliases: dict[str, Any] = field(default_factory=dict)
    runtimes: dict[str, Any] = field(default_factory=dict)
    matrix: list[dict[str, Any]] = field(default_factory=list)
    runner: Any = ""
    commands: list[dict[str, Any]] = field(default_factory=list)
    cross_os: bool = False
    implicit: bool = False
    uncertain: bool = False


@dataclass
class Finding:
    rule_id: str
    confidence: str
    file: str
    line: int
    job: str
    cache_path: str
    cache_key: str
    title: str
    explanation: str
    missing: list[str]
    suggestion: str | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class Diagnostic:
    file: str
    line: int
    message: str

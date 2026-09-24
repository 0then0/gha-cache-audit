"""Tokenize expressions and follow static aliases without running workflow code.

Dependencies describe possible inputs, not proof that an expression is injective.
Unknown references propagate opacity so opaque keys never become definite errors.
"""

import re
from dataclasses import dataclass, field

TOKEN = re.compile(
    r"\s+|(?P<string>'(?:''|[^'])*')|(?P<name>[A-Za-z_][A-Za-z_0-9-]*)|(?P<number>\d+(?:\.\d+)?)|(?P<symbol>.)",
    re.DOTALL,
)
MAX_ALIAS_DEPTH = 100
MAX_ALIAS_EXPANSIONS = 1000
MAX_EXPANDED_CHARS = 2_000_000


@dataclass
class Inputs:
    refs: set[str] = field(default_factory=set)
    files: list[tuple[str, ...]] = field(default_factory=list)
    opaque: bool = False

    def merge(self, other: "Inputs") -> None:
        self.refs.update(other.refs)
        self.files.extend(other.files)
        self.opaque |= other.opaque


def bodies(text: str):
    """Find expression delimiters outside single-quoted expression literals."""
    start = 0
    while (start := text.find("${{", start)) >= 0:
        pos, quoted = start + 3, False
        begin = pos
        while pos < len(text):
            if text[pos] == "'":
                if quoted and text[pos : pos + 2] == "''":
                    pos += 2
                    continue
                quoted = not quoted
            if not quoted and text[pos : pos + 2] == "}}":
                yield text[begin:pos]
                start = pos + 2
                break
            pos += 1
        else:
            yield None
            return


def dependencies(value, aliases=None, seen=frozenset(), budget=None) -> Inputs:
    aliases = aliases or {}
    result = Inputs()
    if not isinstance(value, (str, int, float, bool, type(None))):
        result.opaque = True
        return result
    budget = [MAX_ALIAS_EXPANSIONS, MAX_EXPANDED_CHARS] if budget is None else budget
    text = str(value)
    budget[0] -= 1
    budget[1] -= len(text)
    if len(seen) >= MAX_ALIAS_DEPTH or budget[0] < 0 or budget[1] < 0:
        result.opaque = True
        return result
    for body in bodies(text):
        if body is None:
            result.opaque = True
            continue
        tokens = [
            (m.lastgroup, m.group())
            for m in TOKEN.finditer(body)
            if not m.group().isspace()
        ]
        i = 0
        while i < len(tokens):
            kind, name = tokens[i]
            if kind != "name":
                i += 1
                continue
            name = name.lower()
            i += 1
            if i < len(tokens) and tokens[i][1] == "(":
                if name == "hashfiles":
                    j = i + 1
                    patterns = []
                    while j < len(tokens) and tokens[j][1] != ")":
                        if tokens[j][0] == "string":
                            pattern = tokens[j][1][1:-1].replace("''", "'")
                            relative = pattern.strip().lstrip("!").strip()
                            if relative.startswith(("/", "\\")) or re.match(
                                r"^[A-Za-z]:[/\\]", relative
                            ):
                                result.opaque = True
                            patterns.append(pattern)
                        elif tokens[j][1] != ",":
                            result.opaque = True
                        j += 1
                    if j == len(tokens):
                        result.opaque = True
                    result.files.append(tuple(patterns))
                elif name not in {
                    "format",
                    "join",
                    "contains",
                    "startswith",
                    "endswith",
                    "tojson",
                    "fromjson",
                }:
                    result.opaque = True
                continue
            while i < len(tokens):
                if (
                    tokens[i][1] == "."
                    and i + 1 < len(tokens)
                    and tokens[i + 1][0] == "name"
                ):
                    name += "." + tokens[i + 1][1].lower()
                    i += 2
                elif (
                    tokens[i][1] == "["
                    and i + 2 < len(tokens)
                    and tokens[i + 1][0] == "string"
                    and tokens[i + 2][1] == "]"
                ):
                    name += "." + tokens[i + 1][1][1:-1].replace("''", "'").lower()
                    i += 3
                else:
                    break
            if name in aliases:
                if name in seen:
                    result.opaque = True
                else:
                    if name.startswith("env."):
                        result.refs.add(name)
                    result.merge(
                        dependencies(aliases[name], aliases, seen | {name}, budget)
                    )
            elif name.startswith(("matrix.", "runner.")) or name in {
                "github.sha",
                "github.run_id",
                "github.run_number",
                "github.ref",
                "github.ref_name",
            }:
                result.refs.add(name)
            elif name not in {"true", "false", "null"}:
                result.opaque = True
    return result

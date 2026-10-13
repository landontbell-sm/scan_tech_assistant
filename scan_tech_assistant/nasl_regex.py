"""Regular expressions and parsing helpers for Nessus NASL scripts."""

import re
from dataclasses import dataclass, field
from typing import Callable

# NASL double-quoted strings are pure: no escape sequences, so they can't contain a '"'
SCRIPT_ID_REGEX = re.compile(r"script_id\(\s*(\d+)\s*\)")
SCRIPT_NAME_REGEX = re.compile(
    r"""script_name\(\s*(\w+)\s*:\s*(?:"([^"]*)"|'((?:[^'\\]|\\.)*)')"""
)
# Older plugins assign the name first: name["english"] = "..."; script_name(english:name["english"]);
NAME_VAR_REGEX = re.compile(r'\bname\[\s*["\']english["\']\s*\]\s*=\s*"([^"]*)"')
ATTRIBUTE_TEMPLATE = (
    r'script_set_attribute\(\s*attribute\s*:\s*"{name}"\s*,\s*value\s*:\s*"([^"]*)"\s*\)\s*;'
)
PLUGIN_ID_RE = re.compile(r"^\s*(\d+)\s*$")
INCLUDE_REGEX = re.compile(r"""include\(\s*['"]([^'"]+\.inc)['"]\s*\)""")
CALL_REGEX = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
FUNCTION_DEF_TEMPLATE = r"^[ \t]*(?:(?:public|private)[ \t]+)?function\s+{name}\s*\("
NASL_KEYWORDS = frozenset(
    {"if", "while", "for", "foreach", "return", "function", "include", "else", "repeat", "until"}
)
MAX_FUNCTION_CHARS = 4000


@dataclass
class PluginDetails:
    """The plugin metadata shown in the UI summary and used to scope web_fetch."""

    name: str | None = None
    risk_factor: str | None = None
    description: str | None = None
    solution: str | None = None
    see_also: list[str] = field(default_factory=list)


@dataclass
class IncludeFunction:
    """A function body extracted from one of the plugin's direct includes."""

    name: str
    file: str
    body: str


def parse_name(content: str) -> str | None:
    """Parses the script_name from the given NASL content, preferring the English one."""
    names = [(lang, double or single) for lang, double, single in SCRIPT_NAME_REGEX.findall(content)]
    for lang, text in names:
        if lang.lower() == "english":
            return text
    if match := NAME_VAR_REGEX.search(content):
        return match.group(1)
    return names[0][1] if names else None


def parse_attributes(content: str, name: str) -> list[str]:
    """Parses every value of the named script_set_attribute from the given NASL content."""
    pattern = re.compile(ATTRIBUTE_TEMPLATE.format(name=re.escape(name)))
    return pattern.findall(content)


def parse_attribute(content: str, name: str) -> str | None:
    """Parses the first value of the named script_set_attribute, or None."""
    values = parse_attributes(content, name)
    return values[0] if values else None


def parse(content: str) -> PluginDetails:
    """Parses the given NASL content and returns a PluginDetails object."""
    return PluginDetails(
        name=parse_name(content),
        risk_factor=parse_attribute(content, "risk_factor"),
        description=parse_attribute(content, "description"),
        solution=parse_attribute(content, "solution"),
        see_also=parse_attributes(content, "see_also"),
    )


def resolve_direct_includes(
    content: str, find_include: Callable[[str], str | None]
) -> tuple[dict[str, str], list[str]]:
    """
    Resolves only the include() calls in the given content (no transitive includes) and
    returns ({include_name: path}, [unresolved include names]).
    """
    resolved: dict[str, str] = {}
    unresolved: list[str] = []
    for name in dict.fromkeys(INCLUDE_REGEX.findall(content)):
        path = find_include(name)
        if path:
            resolved[name] = path
        else:
            unresolved.append(name)
    return resolved, unresolved


def _code_chars(source: str, start: int):
    """Yields (index, char) for characters outside strings and # comments, from start."""
    i, n = start, len(source)
    while i < n:
        c = source[i]
        if c == '"':
            end = source.find('"', i + 1)
            if end == -1:
                return
            i = end + 1
        elif c == "'":
            # Single-quoted strings support backslash escapes
            i += 1
            while i < n and source[i] != "'":
                i += 2 if source[i] == "\\" else 1
            i += 1
        elif c == "#":
            end = source.find("\n", i)
            if end == -1:
                return
            i = end + 1
        else:
            yield i, c
            i += 1


def called_names(content: str) -> set[str]:
    """
    Returns the names of everything the given NASL content calls, ignoring strings,
    comments and NASL keywords.
    """
    code = []
    last = -1
    for i, c in _code_chars(content, 0):
        if i != last + 1:
            # Keep tokens on either side of a removed string or comment apart
            code.append(" ")
        code.append(c)
        last = i
    return {
        name for name in CALL_REGEX.findall("".join(code)) if name not in NASL_KEYWORDS
    }


def extract_function(source: str, name: str) -> str | None:
    """
    Returns the full definition of function `name` from the given NASL source, brace-matched
    and capped at MAX_FUNCTION_CHARS, or None if it isn't defined there.
    """
    match = re.search(FUNCTION_DEF_TEMPLATE.format(name=re.escape(name)), source, re.MULTILINE)
    if not match:
        return None
    depth = 0
    for i, c in _code_chars(source, match.end()):
        if c == "{":
            depth += 1
        elif c == "}" and depth:
            depth -= 1
            if depth == 0:
                body = source[match.start() : i + 1].strip()
                break
    else:
        return None
    if len(body) > MAX_FUNCTION_CHARS:
        omitted = len(body) - MAX_FUNCTION_CHARS
        body = f"{body[:MAX_FUNCTION_CHARS]}\n# [truncated: {omitted} more characters]"
    return body


def extract_include_functions(content: str, include_paths: dict[str, str]) -> list[IncludeFunction]:
    """
    Returns the bodies of functions the plugin body calls directly that are defined in one of
    its direct include files. Functions the plugin defines itself are skipped.
    """
    include_sources = {}
    for include_name, path in include_paths.items():
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            include_sources[include_name] = f.read()

    functions = []
    for name in sorted(called_names(content)):
        if extract_function(content, name) is not None:
            continue
        for include_name, source in include_sources.items():
            body = extract_function(source, name)
            if body is not None:
                functions.append(IncludeFunction(name=name, file=include_name, body=body))
                break
    return functions

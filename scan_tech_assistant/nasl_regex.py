"""Regular expressions and parsing helpers for Nessus NASL scripts."""

import re
from typing import Callable
from pydantic import BaseModel, Field

SCRIPT_ID_REGEX = re.compile(r"script_id\(\s*(\d+)\s*\)")
SCRIPT_VERSION_REGEX = re.compile(r'script_version\(\s*"([^"]+)"\s*\)')
CVE_ID_ARGS_REGEX = re.compile(r"script_cve_id\((.*?)\)", re.DOTALL)
QUOTED_STRING_REGEX = re.compile(r'"([^"]*)"')
SCRIPT_NAME_REGEX = re.compile(r'script_name\(\s*(\w+)\s*:\s*"((?:[^"\\]|\\.)*)"')
SCRIPT_FAMILY_REGEX = re.compile(r'script_family\(\s*english\s*:\s*"((?:[^"\\]|\\.)*)"')
CVSS_VECTOR_REGEX = re.compile(
    r'script_set_cvss(\d*)_(base|temporal)_vector\(\s*"([^"]+)"\s*\)'
)
PLUGIN_ID_RE = re.compile(r"^\s*(\d+)\s*$")
INCLUDE_REGEX = re.compile(r"""include\(\s*['"]([^'"]+\.inc)['"]\s*\)""")
ATTRIBUTE_TEMPLATE = (
    r'script_set_attribute\(\s*attribute\s*:\s*"{name}"\s*,\s*value\s*:\s*'
    r'"((?:[^"\\]|\\.)*)"\s*\)\s*;'
)
CALL_REGEX = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
FUNCTION_DEF_TEMPLATE = r"^[ \t]*function\s+{name}\s*\("
NASL_KEYWORDS = frozenset(
    {"if", "while", "for", "foreach", "return", "function", "include", "else", "repeat", "until"}
)
MAX_FUNCTION_CHARS = 4000


class PluginDetails(BaseModel):
    """Represents the details of a Nessus plugin."""

    plugin_id: str | None = None
    version: str | None = None
    name: str | None = None
    family: str | None = None
    risk_factor: str | None = None
    cves: list[str] = Field(default_factory=list)
    cvss_vectors: dict[str, str] = Field(default_factory=dict)
    synopsis: str | None = None
    description: str | None = None
    solution: str | None = None
    see_also: list[str] = Field(default_factory=list)


def parse_script_id(content: str) -> str | None:
    """Parses the script_id from the given NASL content."""
    match = SCRIPT_ID_REGEX.search(content)
    return match.group(1) if match else None


def parse_version(content: str) -> str | None:
    """Parses the script_version from the given NASL content."""
    match = SCRIPT_VERSION_REGEX.search(content)
    return match.group(1) if match else None


def parse_cves(content: str) -> list[str]:
    """Parses the CVE IDs from the given NASL content."""
    match = CVE_ID_ARGS_REGEX.search(content)
    if not match:
        return []
    return QUOTED_STRING_REGEX.findall(match.group(1))


def parse_name(content: str) -> str | None:
    """Parses the script_name from the given NASL content."""
    matches = SCRIPT_NAME_REGEX.findall(content)
    if not matches:
        return None
    for lang, text in matches:
        if lang.lower() == "english":
            return text
    return matches[0][1]


def parse_attribute(content: str, name: str) -> str | None:
    """Parses a specific script_set_attribute from the given NASL content."""
    pattern = re.compile(ATTRIBUTE_TEMPLATE.format(name=re.escape(name)), re.DOTALL)
    match = pattern.search(content)
    return match.group(1) if match else None


def parse_see_also(content: str) -> list[str]:
    """Parses the script_set_attribute for 'see_also' from the given NASL content."""
    pattern = re.compile(ATTRIBUTE_TEMPLATE.format(name="see_also"), re.DOTALL)
    return pattern.findall(content)


def parse_family(content: str) -> str | None:
    """Parses the script_family from the given NASL content."""
    match = SCRIPT_FAMILY_REGEX.search(content)
    return match.group(1) if match else None


def parse_cvss_vectors(content: str) -> dict[str, str]:
    """Parses the CVSS vectors from the given NASL content."""
    vectors: dict[str, str] = {}
    for version, kind, vector in CVSS_VECTOR_REGEX.findall(content):
        vectors[f"cvss{version or '2'}_{kind}"] = vector
    return vectors


def parse(content: str) -> PluginDetails:
    """Parses the given NASL content and returns a PluginDetails object."""
    return PluginDetails(
        plugin_id=parse_script_id(content),
        version=parse_version(content),
        name=parse_name(content),
        family=parse_family(content),
        risk_factor=parse_attribute(content, "risk_factor"),
        cves=parse_cves(content),
        cvss_vectors=parse_cvss_vectors(content),
        synopsis=parse_attribute(content, "synopsis"),
        description=parse_attribute(content, "description"),
        solution=parse_attribute(content, "solution"),
        see_also=parse_see_also(content),
    )


def parse_file(path: str) -> PluginDetails:
    """Parses the given NASL file and returns a PluginDetails object."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return parse(content)


class IncludeFunction(BaseModel):
    """A function body extracted from one of the plugin's direct includes."""

    name: str
    file: str
    body: str


def called_names(content: str) -> set[str]:
    """Returns the names of everything the given NASL content calls, minus NASL keywords."""
    return {name for name in CALL_REGEX.findall(content) if name not in NASL_KEYWORDS}


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
            # NASL double-quoted strings have no escape sequences
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

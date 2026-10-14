"""Regular expressions and parsing helpers for Nessus NASL scripts."""

import re
from dataclasses import dataclass

# NASL double-quoted strings are pure: no escape sequences, so they can't contain a '"'
SCRIPT_ID_REGEX = re.compile(r"script_id\(\s*(\d+)\s*\)")
SCRIPT_NAME_REGEX = re.compile(
    r"""script_name\(\s*(\w+)\s*:\s*(?:"([^"]*)"|'((?:[^'\\]|\\.)*)')"""
)
# Older plugins assign the name first: name["english"] = "..."; script_name(english:name["english"]);
NAME_VAR_REGEX = re.compile(r'\bname\[\s*["\']english["\']\s*\]\s*=\s*"([^"]*)"')
ATTRIBUTE_TEMPLATE = r'script_set_attribute\(\s*attribute\s*:\s*"{name}"\s*,\s*value\s*:\s*"([^"]*)"\s*\)\s*;'
PLUGIN_ID_RE = re.compile(r"^\s*(\d+)\s*$")


@dataclass
class PluginDetails:
    """The plugin metadata shown in the UI summary."""

    name: str | None = None
    risk_factor: str | None = None
    description: str | None = None
    solution: str | None = None


def parse_name(content: str) -> str | None:
    """Parses the script_name from the given NASL content, preferring the English one."""
    names = [
        (lang, double or single)
        for lang, double, single in SCRIPT_NAME_REGEX.findall(content)
    ]
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
    )

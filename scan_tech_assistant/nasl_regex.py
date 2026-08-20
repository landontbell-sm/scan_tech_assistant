import re
from pydantic import BaseModel, Field

SCRIPT_ID_REGEX = re.compile(r"script_id\(\s*(\d+)\s*\)")
SCRIPT_VERSION_REGEX = re.compile(r'script_version\(\s*"([^"]+)"\s*\)')
CVE_ID_ARGS_REGEX = re.compile(r"script_cve_id\((.*?)\)", re.DOTALL)
QUOTED_STRING_REGEX = re.compile(r'"([^"]*)"')
SCRIPT_NAME_REGEX = re.compile(r'script_name\(\s*(\w+)\s*:\s*"((?:[^"\\]|\\.)*)"')
SCRIPT_FAMILY_REGEX = re.compile(r'script_family\(\s*english\s*:\s*"((?:[^"\\]|\\.)*)"')
CVSS_VECTOR_REGEX = re.compile(r'script_set_cvss(\d*)_(base|temporal)_vector\(\s*"([^"]+)"\s*\)')
PLUGIN_ID_RE = re.compile(r"^\s*(\d+)\s*$")
INCLUDE_REGEX = re.compile(r"""include\(\s*['"]([^'"]+\.inc)['"]\s*\)""")
ATTRIBUTE_TEMPLATE = (
    r'script_set_attribute\(\s*attribute\s*:\s*"{name}"\s*,\s*value\s*:\s*'
    r'"((?:[^"\\]|\\.)*)"\s*\)\s*;'
)


class PluginDetails(BaseModel):
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
    match = SCRIPT_ID_REGEX.search(content)
    return match.group(1) if match else None

def parse_version(content: str) -> str | None:
    match = SCRIPT_VERSION_REGEX.search(content)
    return match.group(1) if match else None

def parse_cves(content: str) -> list[str]:
    match = CVE_ID_ARGS_REGEX.search(content)
    if not match:
        return []
    return QUOTED_STRING_REGEX.findall(match.group(1))

def parse_name(content: str) -> str | None:
    matches = SCRIPT_NAME_REGEX.findall(content)
    if not matches:
        return None
    for lang, text in matches:
        if lang.lower() == "english":
            return text
    return matches[0][1]

def parse_attribute(content: str, name: str) -> str | None:
    pattern = re.compile(ATTRIBUTE_TEMPLATE.format(name=re.escape(name)), re.DOTALL)
    match = pattern.search(content)
    return match.group(1) if match else None

def parse_see_also(content: str) -> list[str]:
    pattern = re.compile(ATTRIBUTE_TEMPLATE.format(name="see_also"), re.DOTALL)
    return pattern.findall(content)

def parse_family(content: str) -> str | None:
    match = SCRIPT_FAMILY_REGEX.search(content)
    return match.group(1) if match else None

def parse_cvss_vectors(content: str) -> dict[str, str]:
    vectors: dict[str, str] = {}
    for version, kind, vector in CVSS_VECTOR_REGEX.findall(content):
        vectors[f"cvss{version or '2'}_{kind}"] = vector
    return vectors

def parse(content: str) -> PluginDetails:
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
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return parse(content)

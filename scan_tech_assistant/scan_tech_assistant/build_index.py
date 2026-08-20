"""Indexing helpers for Nessus plugins and includes."""

import json
import subprocess
import re
from pathlib import Path

INCLUDE_REGEX = re.compile(r"""include\(\s*['"]([^'"]+\.inc)['"]\s*\)""")
SCRIPT_ID_REGEX = re.compile(r"script_id\(\s*(\d+)\s*\)")


def index_plugins(plugin_dir: str):
    """
    Indexes all Nessus plugins in the given directory and returns a dictionary mapping
    plugin IDs to file paths.
    """
    plugin_index = {}
    process = subprocess.run(
        ["rg", "--json", "-g", "*.nasl", r"script_id\(\s*\d+\s*\)", str(plugin_dir)],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode > 1:
        raise RuntimeError(f"rg failed (exit {process.returncode}): {process.stderr}")

    for line in process.stdout.splitlines():
        record = json.loads(line)
        if record.get("type") == "match":
            match = SCRIPT_ID_REGEX.search(record["data"]["lines"]["text"])
            if match:
                plugin_index[match.group(1)] = record["data"]["path"]["text"]
    return plugin_index


def index_includes(plugins_dir: str):
    """
    Indexes all Nessus include files in the given directory and returns a dictionary mapping
    include names to file paths.
    """
    return {path.name: str(path) for path in Path(plugins_dir).rglob("*.inc")}


def load_index():
    """Loads the plugin index from the plugin_index.json file."""
    with open("plugin_index.json", "r", encoding="utf-8") as f:
        return json.load(f)


def find_plugin(plugin_id: str):
    """Return the path to the plugin file for the given plugin_id, or None if not found."""
    index = load_index()
    return index["plugins"].get(plugin_id)


def find_include(include_name: str):
    """Return the path to the include file for the given include_name, or None if not found."""
    index = load_index()
    return index["includes"].get(include_name)


def resolve_includes(content: str):
    """Resolve all include statements in the given content and return the full content with includes resolved."""
    # The .inc files can include other .inc files, so we need to resolve them recursively.
    parts = [content]
    unresolved = []
    seen = set()
    queue = INCLUDE_REGEX.findall(content)
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        path = find_include(name)
        if not path:
            unresolved.append(name)
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            include_content = f.read()
        parts.append(f"\n# --- include: {name} ---\n{include_content}")
        queue.extend(INCLUDE_REGEX.findall(include_content))
    return "\n".join(parts), unresolved


if __name__ == "__main__":
    plugins_index = index_plugins("/opt/nessus/lib/nessus/plugins/")
    includes_index = index_includes("/opt/nessus/lib/nessus/plugins/")

    index_data = {"plugins": plugins_index, "includes": includes_index}

    with open("plugin_index.json", "w", encoding="utf-8") as json_f:
        json.dump(index_data, json_f, indent=4)

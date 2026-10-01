"""Indexing helpers for Nessus plugins and includes."""

import json
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from scan_tech_assistant.nasl_regex import INCLUDE_REGEX, SCRIPT_ID_REGEX

INDEX_PATH = Path(__file__).parent / "plugin_index.json"


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


@lru_cache(maxsize=1)
def load_index():
    """Loads the plugin index from the plugin_index.json file."""
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def find_plugin(plugin_id: str):
    """Return the path to the plugin file for the given plugin_id, or None if not found."""
    index = load_index()
    return index["plugins"].get(plugin_id)


def find_include(include_name: str):
    """Return the path to the include file for the given include_name, or None if not found."""
    index = load_index()
    return index["includes"].get(include_name)


if __name__ == "__main__":
    plugins_dir = sys.argv[1] if len(sys.argv) > 1 else "/opt/nessus/lib/nessus/plugins/"
    plugins_index = index_plugins(plugins_dir)
    includes_index = index_includes(plugins_dir)

    index_data = {"plugins": plugins_index, "includes": includes_index}

    with open(INDEX_PATH, "w", encoding="utf-8") as json_f:
        json.dump(index_data, json_f, indent=4)

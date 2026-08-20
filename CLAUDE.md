# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Chainlit chat app that helps SecurityMetrics scan technicians validate
disputed Nessus findings from a terminal, often while a customer is on the
phone. A tech enters a numeric Nessus plugin ID; the app locates that
plugin's NASL source in a local mirror of the Nessus plugin archive, parses
its deterministic metadata, and sends the metadata plus the full resolved
source to Claude, which returns a JSON procedure of concrete terminal
commands (curl, nc, dig, smbclient, etc.) the tech can review and run by
hand to confirm or refute the finding. **The app never touches a customer
environment and never executes anything itself** — every command is read
and run manually by the tech.

## Commands

There is no test suite, linter, or CI config in this repo — verification is
manual (run the app, submit a plugin ID, read the output).

**Docker (primary path):** the image bundles a mirror of the Nessus plugin
archive and builds the plugin index at build time, so no external plugin
source is needed at runtime.

```bash
docker build -t scan_tech_assistant:latest .
docker run -d -p 8000:8000 -e ANTHROPIC_API_KEY="your-api-key" scan_tech_assistant:latest
```

(The README's build command references an `apps/scan_tech_assistant` path
from this repo's original monorepo location — in this standalone checkout
the Dockerfile is at the repo root, so build context is `.`.)

**Running locally without Docker** requires a local mirror of NASL plugins
(`*.nasl`/`*.inc` files) and `ripgrep` (`rg`) installed, since
`build_index.py` shells out to it:

```bash
pip install -r requirements.txt
cd scan_tech_assistant
python build_index.py            # writes plugin_index.json; edit the
                                  # hardcoded /opt/nessus/lib/nessus/plugins/
                                  # path in build_index.py's __main__ block
                                  # to point at a local mirror
ANTHROPIC_API_KEY=... chainlit run app.py --host 0.0.0.0 --port 8000
```

`app.py` must be run with its own directory as the working directory (as
the Dockerfile's `WORKDIR /app/scan_tech_assistant` does) — it uses bare
imports (`from nasl_regex import ...`) and opens `prompts/` and
`plugin_index.json` with relative paths.

### Configuration

| Variable            | Description                                       | Default                                        |
| ------------------- | ------------------------------------------------- | ---------------------------------------------- |
| `ANTHROPIC_API_KEY` | Required. API key for the Claude API.             | _(empty — app raises at import time if unset)_ |
| `MODEL`             | Claude model used to generate testing procedures. | `claude-sonnet-5`                              |

## Architecture

### Two-phase indexing/lookup split

`build_index.py` serves two different roles depending on when it runs:

- **Build time** (`python build_index.py`, run once in the Dockerfile):
  shells out to `rg --json` to find every `script_id(...)` across the
  plugin mirror and every `.inc` file, and writes the result to
  `plugin_index.json` — a flat `{plugin_id: path}` / `{include_name: path}`
  lookup table. This is what lets runtime lookups be a dict read instead of
  a filesystem/grep scan.
- **Runtime** (imported by `app.py`): `find_plugin()` and `find_include()`
  read that prebuilt `plugin_index.json`; `resolve_includes()` recursively
  inlines any `.inc` files an `include()` call in the plugin references
  (tracking cycles via a `seen` set) and returns both the concatenated
  source and a list of any includes it couldn't resolve.

### Request flow (`app.py`)

1. `PLUGIN_ID_RE` (from `nasl_regex.py`) validates the user's message is a
   bare number.
2. `find_plugin()` resolves it to a `.nasl` file path via the prebuilt
   index.
3. `nasl_regex.parse_file()` regex-parses the plugin source into a
   `PluginDetails` pydantic model (CVEs, CVSS vectors, synopsis,
   description, solution, see_also, etc.) — this is the **deterministic
   facts** layer, treated as ground truth the model must not contradict or
   regenerate.
4. `resolve_includes()` builds the **full source** layer (plugin body +
   inlined includes).
5. A plugin-summary message is sent to the user immediately, before the
   Claude call, so the tech has something to read while the model thinks.
   The full resolved source is also shown in a collapsed `cl.Step`.
6. `deterministic_facts.md.j2` and `plugin_source.md.j2` render the two
   layers into a single user message; the source block is marked
   `cache_control: ephemeral` since it's the large, reusable part.
7. Claude is called with the `system_prompt.md` system prompt (also
   ephemeral-cached), a `web_search` tool, `thinking: adaptive`, and a
   forced `json_schema` output matching `ProcedureResponse`
   (`models.py`) — a list of `Step`s (title, explanation, command,
   `payload_origin`: `"plugin"` vs `"model_designed"`, and branching
   `Outcome`s) plus an optional `note`.
8. The validated `ProcedureResponse` is rendered via `steps.md.j2` into the
   final chat message.

### The `<TARGET>` convention

Commands never contain a real hostname/IP/URL — the model is instructed
(in `system_prompt.md`) to use a single literal `<TARGET>` placeholder for
whatever address or request the finding refers to, and the tech fills it in
by hand. `steps.md.j2` only shows the "fill in `<TARGET>`" legend when at
least one rendered step actually contains that token.

### `system_prompt.md` is load-bearing

Most of the actual behavior of this tool — how to tell a genuine finding
from a false positive, when a check isn't remotely reproducible at all,
how `<TARGET>` should be interpreted for a given plugin class, command
quoting/encoding rules, when to use `see_also` lookups — lives in
`scan_tech_assistant/prompts/system_prompt.md`, not in Python. Read it
before changing anything about output shape, the Claude call's parameters,
or `models.py`'s schema, since those three have to stay in sync with what
the prompt promises the model it can/must do.

### Compliance/output framing

This is a QSA firm's internal tool: outputs are explicitly framed as a
"research aid, not a compliance determination" (see the footer in
`steps.md.j2` and the "Ground rules" section of `system_prompt.md`) — the
model is instructed never to state a finding is or isn't a real
vulnerability in absolute terms, only to describe what the evidence shows.
Preserve that framing in any prompt or template changes.

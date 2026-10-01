"""Entry point for Scan Tech Assistant App"""

import ipaddress
import os
from pathlib import Path
from urllib.parse import urlparse
import anthropic
import chainlit as cl
from anthropic import AsyncAnthropic, transform_schema
from chainlit.utils import utc_now
from jinja2 import Environment, FileSystemLoader
from scan_tech_assistant.nasl_regex import (
    parse,
    PLUGIN_ID_RE,
    resolve_direct_includes,
    extract_include_functions,
)
from scan_tech_assistant.build_index import find_plugin, find_include
from scan_tech_assistant.models import ProcedureResponse

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if ANTHROPIC_API_KEY:
    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
else:
    raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")
MODEL = os.environ.get("MODEL", "claude-sonnet-5-5")
PROMPTS_DIR = Path(__file__).parent / "prompts"

# Structured outputs reject minLength/maxLength/numeric constraints; pydantic still validates.
PROCEDURE_SCHEMA = transform_schema(ProcedureResponse.model_json_schema())

WEB_FETCH_TOOL_TYPE = "web_fetch_20260318"
WEB_FETCH_FALLBACK_TOOL_TYPE = "web_fetch_20250910"
WEB_FETCH_MAX_USES = 3
WEB_FETCH_MAX_CONTENT_TOKENS = 4000
MAX_ALLOWED_DOMAINS = 64
# Server tools can return pause_turn; resume at most this many requests in total.
MAX_ROUNDS = 3

with open(PROMPTS_DIR / "system_prompt.md", "r", encoding="utf-8") as f:
    SYSTEM_PROMPT = f.read()

templates = Environment(
    loader=FileSystemLoader(PROMPTS_DIR),
    trim_blocks=True,
    lstrip_blocks=True,
)


def see_also_hostnames(see_also: list[str]) -> list[str]:
    """De-duplicated hostnames from the plugin's see_also URLs that web_fetch will accept."""
    hostnames = []
    for value in see_also:
        # A single see_also attribute can hold several whitespace-separated URLs
        for url in value.split():
            hostname = urlparse(url).hostname
            if not hostname or "." not in hostname or hostname in hostnames:
                continue
            try:
                # IP literals are rejected in allowed_domains
                ipaddress.ip_address(hostname)
                continue
            except ValueError:
                hostnames.append(hostname)
    return hostnames[:MAX_ALLOWED_DOMAINS]


def web_fetch_tools(see_also: list[str], tool_type: str) -> list[dict] | None:
    """The web_fetch tool scoped to the plugin's see_also hosts, or None if there are none."""
    hostnames = see_also_hostnames(see_also)
    if not hostnames:
        return None
    # citations is deliberately left unset: citations plus structured outputs returns a 400.
    return [
        {
            "type": tool_type,
            "name": "web_fetch",
            "allowed_domains": hostnames,
            "max_uses": WEB_FETCH_MAX_USES,
            "max_content_tokens": WEB_FETCH_MAX_CONTENT_TOKENS,
        }
    ]


def open_step(name: str, step_type: str, parent_id: str) -> cl.Step:
    """Creates a progress step under the given parent; caller must send() it."""
    step = cl.Step(name=name, type=step_type, parent_id=parent_id)
    step.start = utc_now()
    return step


async def close_step(step: cl.Step, output: str = "", is_error: bool = False):
    """Marks a manually opened progress step as finished."""
    step.end = utc_now()
    step.output = output
    step.is_error = is_error
    await step.update()


async def stream_round(messages: list, tools: list[dict] | None, parent_id: str):
    """Runs one streamed request, surfacing thinking and web_fetch progress as steps."""
    request = {
        "model": MODEL,
        "max_tokens": 20000,
        "system": [
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        "thinking": {"type": "adaptive"},
        "output_config": {
            "effort": "medium",
            "format": {"type": "json_schema", "schema": PROCEDURE_SCHEMA},
        },
        "messages": messages,
    }
    if tools:
        request["tools"] = tools

    thinking_steps: dict[int, cl.Step] = {}
    fetch_steps: dict[str, cl.Step] = {}
    try:
        async with client.messages.stream(**request) as stream:
            async for event in stream:
                if event.type == "content_block_start":
                    block = event.content_block
                    if block.type == "thinking":
                        step = open_step("Thinking…", "llm", parent_id)
                        thinking_steps[event.index] = step
                        await step.send()
                    elif block.type == "server_tool_use" and block.name == "web_fetch":
                        step = open_step("Fetching advisory…", "tool", parent_id)
                        fetch_steps[block.id] = step
                        await step.send()
                    elif block.type == "web_fetch_tool_result":
                        step = fetch_steps.pop(block.tool_use_id, None)
                        if step:
                            result = block.content
                            if result.type == "web_fetch_tool_result_error":
                                await close_step(step, f"Fetch failed: {result.error_code}", True)
                            else:
                                await close_step(step, f"Fetched {result.url}")
                elif event.type == "content_block_stop":
                    step = thinking_steps.pop(event.index, None)
                    if step:
                        await close_step(step)
            return await stream.get_final_message()
    finally:
        for step in [*thinking_steps.values(), *fetch_steps.values()]:
            await close_step(step)


@cl.on_chat_start
async def start():
    """Welcome message when the chat starts."""
    await cl.Message(
        content="**Scan Agent:** Enter a numeric Nessus plugin ID and I'll pull the "
        "plugin details and walk through how to validate it by hand."
    ).send()


@cl.on_message
async def main(message: cl.Message):
    """Main plugin processing function, triggered when the user sends a Nessus plugin ID."""
    # pylint: disable=too-many-locals,too-many-return-statements
    match = PLUGIN_ID_RE.match(message.content)
    if not match:
        await cl.Message(
            content="Please enter a valid Nessus plugin ID (a number)."
        ).send()
        return
    plugin_id = match.group(1)
    plugin_path = find_plugin(plugin_id)
    if not plugin_path:
        await cl.Message(content=f"Plugin ID {plugin_id} not found.").send()
        return

    try:
        with open(plugin_path, "r", encoding="utf-8", errors="replace") as plugin_f:
            raw_content = plugin_f.read()
        plugin_details = parse(raw_content)
        include_paths, unresolved_includes = resolve_direct_includes(raw_content, find_include)
        include_functions = extract_include_functions(raw_content, include_paths)

        # Render the plugin summary immediately, before the model call returns
        summary = templates.get_template("plugin_summary.md.j2").render(
            plugin_id=plugin_details.plugin_id,
            name=plugin_details.name,
            family=plugin_details.family,
            risk_factor=plugin_details.risk_factor,
            cves=plugin_details.cves,
            cvss_vectors=plugin_details.cvss_vectors,
            synopsis=plugin_details.synopsis,
            description=plugin_details.description,
            solution=plugin_details.solution,
            see_also=plugin_details.see_also,
            unresolved_includes=unresolved_includes,
        )
        await cl.Message(content=summary).send()

        # synopsis/description/solution are already in the plugin source; see_also must stay
        # here because web_fetch can only fetch URLs that appear in a user message.
        facts_block = templates.get_template("deterministic_facts.md.j2").render(
            facts_json=plugin_details.model_dump_json(
                indent=2, exclude={"synopsis", "description", "solution"}
            ),
            unresolved_includes=unresolved_includes,
        )
        functions_block = templates.get_template("include_functions.md.j2").render(
            functions=include_functions,
        )
        source_block = templates.get_template("plugin_source.md.j2").render(
            plugin_path=plugin_path,
            plugin_source=raw_content,
        )

        # Show exactly the source context the model receives
        async with cl.Step(
            name=os.path.basename(plugin_path),
            type="tool",
            language="nasl",
            default_open=False,
        ) as source_step:
            source_step.output = f"{functions_block}\n{source_block}"

        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": facts_block},
                    {"type": "text", "text": functions_block},
                    {
                        "type": "text",
                        "text": source_block,
                        "cache_control": {"type": "ephemeral"},
                    },
                ],
            }
        ]

        tools = web_fetch_tools(plugin_details.see_also, WEB_FETCH_TOOL_TYPE)
        async with cl.Step(name="Building testing procedure", type="tool") as procedure_step:
            for _ in range(MAX_ROUNDS):
                try:
                    response = await stream_round(messages, tools, procedure_step.id)
                except anthropic.BadRequestError as e:
                    # Fall back to the older web_fetch version if this one isn't accepted
                    if (
                        not tools
                        or tools[0]["type"] != WEB_FETCH_TOOL_TYPE
                        or WEB_FETCH_TOOL_TYPE not in str(e)
                    ):
                        raise
                    tools = web_fetch_tools(plugin_details.see_also, WEB_FETCH_FALLBACK_TOOL_TYPE)
                    response = await stream_round(messages, tools, procedure_step.id)
                if response.stop_reason != "pause_turn":
                    break
                messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "refusal":
            category = getattr(getattr(response, "stop_details", None), "category", None)
            await cl.Message(
                content="Claude declined to answer for this plugin "
                f"(safety refusal, category: {category or 'unspecified'})."
            ).send()
            return
        if response.stop_reason == "max_tokens":
            await cl.Message(
                content="The model ran out of output tokens before finishing, so this "
                "procedure may be incomplete and was not shown. Try submitting the plugin again."
            ).send()
            return
        if response.stop_reason == "pause_turn":
            await cl.Message(
                content=f"The model was still working after {MAX_ROUNDS} rounds of advisory "
                "lookups and didn't produce a procedure. Try submitting the plugin again."
            ).send()
            return
        # With server tools the model may write text before a fetch; the JSON answer is last
        text_block = next((b for b in reversed(response.content) if b.type == "text"), None)
        if text_block is None:
            await cl.Message(
                content=f"No answer produced (stop_reason={response.stop_reason})."
            ).send()
            return
        procedure = ProcedureResponse.model_validate_json(text_block.text)

        show_target_legend = any(
            step.command and "<TARGET>" in step.command for step in procedure.steps
        )
        content = templates.get_template("steps.md.j2").render(
            steps=procedure.steps,
            note=procedure.note,
            show_target_legend=show_target_legend,
        )
        await cl.Message(content=content).send()
    # Errors are caught and reported to the user, but not re-raised, so that the chat can continue.
    # pylint: disable=broad-exception-caught
    except Exception as e:
        await cl.Message(content=f"Error: {e}").send()

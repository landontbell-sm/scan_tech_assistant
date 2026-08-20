"""Entry point for Scan Tech Assistant App"""

import os
import chainlit as cl
from anthropic import AsyncAnthropic
from jinja2 import Environment, FileSystemLoader
from scan_tech_assistant.nasl_regex import parse_file, PLUGIN_ID_RE
from scan_tech_assistant.build_index import find_plugin, resolve_includes
from scan_tech_assistant.models import ProcedureResponse

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if ANTHROPIC_API_KEY:
    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
else:
    raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")
MODEL = os.environ.get("MODEL", "claude-sonnet-5")

with open("prompts/system_prompt.md", "r", encoding="utf-8") as f:
    SYSTEM_PROMPT = f.read()

templates = Environment(
    loader=FileSystemLoader("prompts"),
    trim_blocks=True,
    lstrip_blocks=True,
)


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
    # pylint: disable=too-many-locals
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
        plugin_details = parse_file(plugin_path)
        with open(plugin_path, "r", encoding="utf-8", errors="replace") as plugin_f:
            raw_content = plugin_f.read()
        full_context, unresolved_includes = resolve_includes(raw_content)

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

        async with cl.Step(
            name=os.path.basename(plugin_path),
            type="tool",
            language="nasl",
            default_open=False,
        ) as source_step:
            source_step.output = full_context

        facts_block = templates.get_template("deterministic_facts.md.j2").render(
            facts_json=plugin_details.model_dump_json(indent=2),
            unresolved_includes=unresolved_includes,
        )
        source_block = templates.get_template("plugin_source.md.j2").render(
            plugin_path=plugin_path,
            full_context=full_context,
        )
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": facts_block},
                    {
                        "type": "text",
                        "text": source_block,
                        "cache_control": {"type": "ephemeral"},
                    },
                ],
            }
        ]

        async with cl.Step(name="Building testing procedure", type="tool"):
            async with client.messages.stream(
                model=MODEL,
                max_tokens=64000,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                tools=[{"type": "web_search_20260209", "name": "web_search"}],
                thinking={"type": "adaptive"},
                output_config={
                    "effort": "medium",
                    "format": {
                        "type": "json_schema",
                        "schema": ProcedureResponse.model_json_schema(),
                    },
                },
                messages=messages,
            ) as stream:
                response = await stream.get_final_message()

        if response.stop_reason == "refusal":
            await cl.Message(
                content="Claude declined to answer for this plugin (safety refusal)."
            ).send()
            return
        text_block = next((b for b in response.content if b.type == "text"), None)
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

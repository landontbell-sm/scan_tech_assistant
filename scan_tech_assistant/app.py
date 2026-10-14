"""Entry point for Scan Tech Assistant App"""

import os
import chainlit as cl
from anthropic import AsyncAnthropic
from anthropic.types import WebFetchTool20260209Param
from jinja2 import Environment, FileSystemLoader
from scan_tech_assistant.build_index import find_plugin
from scan_tech_assistant.nasl_regex import PLUGIN_ID_RE, parse

client = AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MODEL = os.environ.get("MODEL", "claude-sonnet-5-5")
FALLBACK_MODEL = "claude-sonnet-5"
with open("prompts/system.md", encoding="utf-8") as f:
    SYSTEM_PROMPT = f.read()
templates = Environment(loader=FileSystemLoader("."))
WEB_FETCH: WebFetchTool20260209Param = {
    "type": "web_fetch_20260209",
    "name": "web_fetch",
    "max_uses": 3,
    "max_content_tokens": 4000,
}


def render(name: str, **context) -> str:
    """Renders a template from prompts/ or templates/."""
    return templates.get_template(name).render(**context)


class Refusal(Exception):
    """The model declined to answer."""


async def stream_response(model: str, messages: list, answer: cl.Message):
    """Sends one request, streaming its text into `answer` and showing each web fetch as a step."""
    async with client.messages.stream(
        model=model,
        max_tokens=20000,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=[WEB_FETCH],
        thinking={"type": "adaptive"},
        output_config={"effort": "medium"},
        cache_control={"type": "ephemeral"},
        messages=messages,
    ) as stream:
        async for event in stream:
            if event.type == "content_block_delta" and event.delta.type == "text_delta":
                await answer.stream_token(event.delta.text)
            elif event.type == "content_block_start":
                block = event.content_block
                if block.type == "text" and answer.content:
                    # Text after a fetch would otherwise run into the line before it
                    await answer.stream_token("\n\n")
                elif block.type == "web_fetch_tool_result":
                    async with cl.Step(name="Web fetch", type="tool") as step:
                        if block.content.type == "web_fetch_tool_result_error":
                            step.output = f"Failed: {block.content.error_code}"
                            step.is_error = True
                        else:
                            step.output = block.content.url
        return await stream.get_final_message()


async def stream_turn(model: str, messages: list, answer: cl.Message):
    """Runs one turn on `model`, resuming pause_turn, and adds the reply to `messages`."""
    async with cl.Step(name="Thinking...", type="tool") as step:
        for _ in range(3):
            response = await stream_response(model, messages, answer)
            messages.append({"role": "assistant", "content": response.content})
            if response.stop_reason != "pause_turn":
                break
        step.name = "Thought"
    if response.stop_reason == "refusal":
        raise Refusal(f"{model} declined to answer: {response.stop_details}")
    if response.stop_reason != "end_turn" or not answer.content:
        raise RuntimeError(
            f"Claude stopped without answering ({response.stop_reason}). Try again."
        )


async def run_turn(chat: dict) -> cl.Message:
    """
    Streams Claude's reply to the last message in the chat and adds it to the history. If the
    model refuses, the turn is retried on FALLBACK_MODEL, which the chat keeps from then on. A
    failed turn is removed from both the history and the screen, so the next message picks up
    from the last good turn. The caller sends the returned message.
    """
    messages = chat["messages"]
    user_turn = len(messages) - 1
    while True:
        answer = cl.Message(content="")
        try:
            await stream_turn(chat["model"], messages, answer)
            return answer
        except Exception as e:
            del messages[user_turn + 1 :]
            if answer.content:
                await answer.remove()
            if isinstance(e, Refusal) and chat["model"] != FALLBACK_MODEL:
                chat["model"] = FALLBACK_MODEL
                continue
            del messages[user_turn]
            raise


@cl.on_chat_start
async def start():
    """Shows the welcome message."""
    await cl.Message(content=render("templates/welcome.md")).send()


@cl.on_message
async def main(message: cl.Message):
    """The first message picks the plugin; later ones are follow-up questions about it."""
    chat = cl.user_session.get("chat")
    match = PLUGIN_ID_RE.match(message.content)
    try:
        if chat is None:
            await start_plugin(match)
        elif match and find_plugin(match.group(1)):
            await cl.Message(
                content=f"This chat is about plugin {chat['plugin_id']}. "
                "Start a new chat to look up another plugin."
            ).send()
        else:
            chat["messages"].append({"role": "user", "content": message.content})
            answer = await run_turn(chat)
            await answer.send()
    except Exception as e:
        await cl.Message(content=f"Error: {e}").send()


async def start_plugin(match):
    """Shows the plugin's summary and source, then asks Claude how to verify the finding."""
    if not match:
        await cl.Message(
            content="Start by entering a Nessus plugin ID (a number)."
        ).send()
        return
    plugin_id = match.group(1)
    plugin_path = find_plugin(plugin_id)
    if not plugin_path:
        await cl.Message(content=f"Plugin ID {plugin_id} not found.").send()
        return

    with open(plugin_path, encoding="utf-8", errors="replace") as f:
        source = f.read()
    summary = render(
        "templates/plugin_summary.md.j2", plugin_id=plugin_id, plugin=parse(source)
    )
    await cl.Message(content=summary).send()
    async with cl.Step(
        name=os.path.basename(plugin_path), type="tool", language="nasl"
    ) as step:
        step.output = source

    prompt = render(
        "prompts/plugin.md.j2",
        plugin_id=plugin_id,
        plugin_path=plugin_path,
        plugin_source=source,
    )
    chat = {
        "plugin_id": plugin_id,
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
            }
        ],
    }
    answer = await run_turn(chat)
    await answer.send()
    cl.user_session.set("chat", chat)

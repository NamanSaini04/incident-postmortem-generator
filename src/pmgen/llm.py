"""LLM clients. The rest of the code only sees `generate_json(system, user, schema)`.

AnthropicClient  real API; JSON parsed from the reply (default) or structured outputs (opt-in).
FakeClient       returns scripted replies (or raises scripted errors); used by tests.
"""
from __future__ import annotations

import copy
import json
import os
import re
from typing import Protocol

DEFAULT_MODEL = os.environ.get("PMGEN_MODEL", "claude-sonnet-5-5")


class LLMError(RuntimeError):
    pass


class LLMOutputError(LLMError):
    """The model answered, but the reply could not be parsed. Worth a retry."""


OUTPUT_MODE = os.environ.get("PMGEN_OUTPUT_MODE", "prompt")  # "prompt" (default) or "structured"


def extract_json(text: str) -> dict:
    """Pull the JSON object out of a reply: <json>...</json> tags first, then a
    ```json fence, then the outermost {...}."""
    m = re.search(r"<json>\s*(.*?)\s*</json>", text, re.DOTALL)
    if m:
        body = m.group(1)
    else:
        f = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if f:
            body = f.group(1)
        else:
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end <= start:
                raise LLMOutputError("reply contained no JSON object")
            body = text[start:end + 1]
    try:
        out = json.loads(body)
    except json.JSONDecodeError as e:
        raise LLMOutputError(f"reply JSON could not be parsed: {e}") from e
    if not isinstance(out, dict):
        raise LLMOutputError("reply JSON was not an object")
    return out


def schema_instructions(schema: dict) -> str:
    compact = json.dumps(inline_refs(schema), separators=(",", ":"))
    return ("Return ONLY one JSON object that matches this JSON Schema, wrapped in <json> and </json> tags. "
            "No other text.\nJSON SCHEMA:\n" + compact)


class LLMClient(Protocol):
    model: str

    def generate_json(self, system: str, user: str, schema: dict) -> dict: ...


def inline_refs(schema: dict) -> dict:
    """Replace $ref/$defs with the referenced definitions (simpler for tool schemas)."""
    defs = schema.get("$defs", {})

    def walk(node):
        if isinstance(node, dict):
            if "$ref" in node:
                target = copy.deepcopy(defs[node["$ref"].split("/")[-1]])
                extra = {k: v for k, v in node.items() if k != "$ref"}
                return walk({**target, **extra})
            return {k: walk(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return walk(schema)


def strict_schema(schema: dict) -> dict:
    """Prepare a Pydantic JSON schema for structured outputs.

    Structured outputs accept only part of JSON Schema: refs are inlined,
    unsupported constraints (minimum, maxLength...) are moved into descriptions
    and additionalProperties:false is added (via the SDK's transform_schema), and
    every property is made required, because the API limits optional fields
    (24 per request) and keeps schema order only for required ones.
    """
    from anthropic import transform_schema

    out = transform_schema(inline_refs(schema))

    def require_all(node):
        if isinstance(node, dict):
            if node.get("type") == "object" and "properties" in node:
                node["required"] = list(node["properties"].keys())
            for v in node.values():
                require_all(v)
        elif isinstance(node, list):
            for x in node:
                require_all(x)

    require_all(out)
    return out


class AnthropicClient:
    """Two output modes:

    prompt (default)  schema is given in the prompt; JSON is parsed from <json> tags.
                      Works with any schema size. Malformed replies raise
                      LLMOutputError, which the generator retries.
    structured        output_config.format (constrained decoding). Rejected for this
                      project's schema on claude-sonnet-5-5 with "compiled grammar is
                      too large" (seen 2026-11-23), so it is opt-in only.

    Forced tool calls (tool_choice "tool"/"any") are not used: current models
    such as claude-sonnet-5-5 reject them with a 400 error.
    """

    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = 16000, mode: str = OUTPUT_MODE):
        if mode not in ("prompt", "structured"):
            raise LLMError(f"unknown output mode {mode!r}; use 'prompt' or 'structured'")
        self.mode = mode
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise LLMError("ANTHROPIC_API_KEY is not set. See README, 'Running the LLM step'.")
        try:
            import anthropic
        except ImportError as e:
            raise LLMError('anthropic package missing: python -m pip install ".[llm]"') from e
        self._client = anthropic.Anthropic()
        self.model, self.max_tokens = model, max_tokens
        self.last_usage: dict | None = None

    def generate_json(self, system: str, user: str, schema: dict) -> dict:
        kwargs = dict(model=self.model, max_tokens=self.max_tokens, system=system)
        if self.mode == "structured":
            kwargs["output_config"] = {"format": {"type": "json_schema", "schema": strict_schema(schema)}}
            kwargs["messages"] = [{"role": "user", "content": user}]
        else:
            kwargs["messages"] = [{"role": "user", "content": user + "\n\n" + schema_instructions(schema)}]
        resp = self._client.messages.create(**kwargs)
        usage = getattr(resp, "usage", None)
        self.last_usage = {"input_tokens": getattr(usage, "input_tokens", None),
                           "output_tokens": getattr(usage, "output_tokens", None)}
        if resp.stop_reason == "refusal":
            raise LLMError("the model declined this request (stop_reason=refusal); see the request in the Console logs")
        if resp.stop_reason == "max_tokens":
            raise LLMError(f"reply cut off at max_tokens={self.max_tokens}; raise it or shorten the evidence")
        text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", None) == "text")
        if not text.strip():
            raise LLMOutputError(f"model returned no text (stop_reason={resp.stop_reason})")
        return extract_json(text)


class FakeClient:
    """Returns each scripted reply in turn; records the prompts it was given."""

    def __init__(self, replies: list[dict], model: str = "fake"):
        self.replies, self.model = list(replies), model
        self.calls: list[tuple[str, str]] = []

    def generate_json(self, system: str, user: str, schema: dict) -> dict:
        self.calls.append((system, user))
        if not self.replies:
            raise LLMError("FakeClient ran out of scripted replies")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

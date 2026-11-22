"""LLM clients. The rest of the code only sees `generate_json(system, user, schema)`.

AnthropicClient  real API; forces a tool call so the reply is JSON matching the schema.
FakeClient       returns scripted replies; used by tests (no network, no cost).
"""
from __future__ import annotations

import copy
import os
from typing import Protocol

DEFAULT_MODEL = os.environ.get("PMGEN_MODEL", "claude-sonnet-5-5")
TOOL_NAME = "submit_postmortem"


class LLMError(RuntimeError):
    pass


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


class AnthropicClient:
    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = 8000):
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
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            tools=[{"name": TOOL_NAME, "description": "Submit the incident postmortem draft.",
                    "input_schema": inline_refs(schema)}],
            tool_choice={"type": "tool", "name": TOOL_NAME},
            messages=[{"role": "user", "content": user}],
        )
        usage = getattr(resp, "usage", None)
        self.last_usage = {"input_tokens": getattr(usage, "input_tokens", None),
                           "output_tokens": getattr(usage, "output_tokens", None)}
        if resp.stop_reason == "max_tokens":
            raise LLMError(f"reply cut off at max_tokens={self.max_tokens}; raise it or shorten the evidence")
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use" and block.name == TOOL_NAME:
                return dict(block.input)
        raise LLMError("model did not return the structured draft")


class FakeClient:
    """Returns each scripted reply in turn; records the prompts it was given."""

    def __init__(self, replies: list[dict], model: str = "fake"):
        self.replies, self.model = list(replies), model
        self.calls: list[tuple[str, str]] = []

    def generate_json(self, system: str, user: str, schema: dict) -> dict:
        self.calls.append((system, user))
        if not self.replies:
            raise LLMError("FakeClient ran out of scripted replies")
        return self.replies.pop(0)

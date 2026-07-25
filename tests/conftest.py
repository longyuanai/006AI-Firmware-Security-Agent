"""Shared pytest fixtures for AI-Firmware-Security-Agent tests.

Per the v0.1 contract (`000shared-llm-core/docs/v0.1-contract.md` §5), every
downstream project must expose a ``stub_router`` fixture in ``conftest.py``
so that integration tests can stand in for ``shared_llm_core.LLMRouter`` without
hitting a real provider.

This product has two calling conventions for the stub router:

1. **Direct chat**: ``router.chat(tier, request)`` (used by analyzer tests)
2. **Factory + context-manager**: ``LLMRouter.from_env()`` returns a stub
   that is used as a context manager (used by CLI tests via monkeypatch).

Both are covered here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from shared_llm_core import ChatChoice, ChatMessage, ChatRequest, ChatResponse, ChatUsage


@dataclass
class StubRouter:
    """Minimal in-memory replacement for ``shared_llm_core.LLMRouter``.

    Records every ``chat()`` invocation and returns a fixed ``ChatResponse``
    whose message content is ``json.dumps(reply)``.

    Also implements the context-manager protocol so it can be returned from
    ``LLMRouter.from_env()`` for the CLI test path.
    """

    reply: dict = field(default_factory=dict)
    calls: list[ChatRequest] = field(default_factory=list)

    def chat(self, tier: Any, req: ChatRequest) -> ChatResponse:  # noqa: ARG002
        self.calls.append(req)
        return ChatResponse(
            id="stub",
            model="stub",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=json.dumps(self.reply)),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(),
        )

    def set_reply(self, reply: dict) -> None:
        self.reply = reply

    # Context-manager protocol so this stub can stand in for
    # `LLMRouter.from_env()` in CLI tests that use `with` blocks.
    def __enter__(self) -> "StubRouter":
        return self

    def __exit__(self, *_: Any) -> None:
        return None


@pytest.fixture
def stub_router() -> StubRouter:
    """Module-level fixture: a fresh StubRouter per test (direct-chat mode)."""
    return StubRouter(reply={})


@pytest.fixture
def stub_router_with():
    """Factory fixture: ``stub_router_with(reply)`` returns a configured stub.

    Usage::

        def test_x(stub_router_with):
            router = stub_router_with({"severity": "high"})
            ...
    """

    def _make(reply: dict | None = None) -> StubRouter:
        return StubRouter(reply=reply or {})

    return _make


@pytest.fixture
def stub_router_factory(monkeypatch):
    """Patch ``LLMRouter.from_env`` so CLI tests get a stub via monkeypatch.

    Usage::

        def test_cli(stub_router_factory):
            router = stub_router_factory(reply={"x": 1})
            with router as r:
                ...  # exercises the CLI path
    """

    def _make(reply: dict | None = None) -> StubRouter:
        from shared_llm_core.router import LLMRouter

        stub = StubRouter(reply=reply or {})
        monkeypatch.setattr(LLMRouter, "from_env", classmethod(lambda cls: stub))
        return stub

    return _make
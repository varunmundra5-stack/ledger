"""Where the decision is made — in-process, or over MCP.

The gate's value does not depend on being importable. `energy_orchestrator` ships an
MCP server (`mcp_gate.serve`) exposing the same packs as tools, so a harness that
cannot import Python — a TypeScript agent, someone else's product, a harness we never
forked — can reach the identical decision over stdio.

Two implementations of one seam, so that claim is testable rather than asserted:

    InProcessGate()   import the pack and call it          (fast; the default)
    McpGate()         spawn `mcp_gate.serve` and call it   (proves harness-independence)

`tests/test_mcp_gateway.py` runs the same decisions through both and asserts they
agree. If they ever diverge, the deploy-anywhere claim is false and the build says so.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Protocol


class Gate(Protocol):
    """Decide `request` against a named EBRM pack."""

    def decide(self, pack: str, request: dict) -> dict:
        """Returns `{"status", "destination", "reason"}`."""


def _verdict(status: str, destination: str | None, reason: str | None) -> dict:
    return {"status": status, "destination": destination, "reason": reason}


@dataclass
class InProcessGate:
    """The default: import the pack and call it directly."""

    sink: object = None

    def decide(self, pack: str, request: dict) -> dict:
        from energy_orchestrator.domain_pack import get
        from energy_orchestrator.domains.packs import register_default_packs

        try:
            domain_pack = get(pack)
        except KeyError:
            register_default_packs()
            domain_pack = get(pack)

        resolution = domain_pack.solve(request, sink=self.sink)
        if resolution.status != "ok":
            return _verdict("refused", None, resolution.refusal_reason)
        content = resolution.answer.content
        return _verdict("ok", content.get("destination"), None)


SERVER_BOOTSTRAP = (
    "from energy_orchestrator.mcp_gate import serve; "
    "from energy_orchestrator.domains.packs import register_default_packs; "
    "register_default_packs(); serve(sink_path={sink!r})"
)


@dataclass
class McpGate:
    """The same decision, taken by a separate process over MCP stdio.

    Nothing about the decision changes — it is the same pack, reached through the
    transport the agent-tooling ecosystem converged on. Data never leaves the machine:
    the server runs locally over stdio and returns a verdict plus a fingerprint, never
    the payload.
    """

    sink_path: str = "ebrm-provenance.jsonl"
    python: str = sys.executable

    def decide(self, pack: str, request: dict) -> dict:
        import anyio

        return anyio.run(self._decide, pack, request)

    async def _decide(self, pack: str, request: dict) -> dict:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=self.python,
            args=["-c", SERVER_BOOTSTRAP.format(sink=self.sink_path)],
            env={**os.environ, "OPENHANDS_SUPPRESS_BANNER": "1"},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "ebrm_solve", {"pack": pack, "request": request}
                )
                return self._parse(result)

    @staticmethod
    def _parse(result) -> dict:
        """Map the server's record back to a verdict.

        The server returns a fingerprint instead of the answer for payload packs, and
        the decision itself for decision-shaped ones (EBRM's `answer_is_decision`) —
        so the destination arrives without any content ever crossing the boundary.
        """
        import json

        payload = getattr(result, "structuredContent", None)
        if payload is None:
            blocks = getattr(result, "content", []) or []
            text = next((getattr(b, "text", "") for b in blocks), "{}")
            payload = json.loads(text or "{}")

        record = payload.get("record") or {}
        if payload.get("error"):
            return _verdict("refused", None, payload["error"])
        if record.get("status") != "ok":
            return _verdict("refused", None, record.get("refusal_reason"))
        decision = payload.get("decision") or {}
        return _verdict("ok", decision.get("destination"), None)


__all__ = ["Gate", "InProcessGate", "McpGate", "SERVER_BOOTSTRAP"]

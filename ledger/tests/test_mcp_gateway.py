"""M4 — the deploy-anywhere proof.

The gate's value must not depend on being importable. These tests take the same
decisions twice: once in-process, once through a real MCP server running in a separate
process, and assert they agree. If they diverge, "any harness can call this" is false.

Marked slow because each MCP case spawns an interpreter.
"""

from __future__ import annotations

import pytest
from ledger.gateway import InProcessGate, McpGate


POLICY = {
    "hard": [{"label": "sovereign", "deny": ["cloud"]}],
    "prefer": {"default": "cloud", "when": {"sovereign": "local"}},
}


def request(labels, candidates=("local", "cloud")):
    return {
        "candidates": list(candidates),
        "classification": {"labels": list(labels), "sources": []},
        "policy": POLICY,
    }


CASES = [
    ("clean payload", request([]), "ok", "cloud"),
    ("sovereign payload", request(["sovereign"]), "ok", "local"),
    ("no permitted destination", request(["sovereign"], ("cloud",)), "refused", None),
]


class TestInProcess:
    @pytest.mark.parametrize("name,req,status,destination", CASES)
    def test_decides(self, name, req, status, destination) -> None:
        verdict = InProcessGate().decide("routing_policy", req)
        assert verdict["status"] == status, name
        assert verdict["destination"] == destination, name


@pytest.mark.slow
class TestOverMcp:
    @pytest.mark.parametrize("name,req,status,destination", CASES)
    def test_same_decision_out_of_process(
        self, name, req, status, destination, tmp_path
    ) -> None:
        gate = McpGate(sink_path=str(tmp_path / "provenance.jsonl"))
        verdict = gate.decide("routing_policy", req)
        assert verdict["status"] == status, name
        assert verdict["destination"] == destination, name

    def test_agrees_with_the_in_process_gate(self, tmp_path) -> None:
        mcp = McpGate(sink_path=str(tmp_path / "p.jsonl"))
        local = InProcessGate()
        for _, req, _, _ in CASES:
            assert mcp.decide("routing_policy", req) == local.decide(
                "routing_policy", req
            )

    def test_the_server_never_returns_payload_content(self, tmp_path) -> None:
        """A payload pack must expose only a fingerprint, even over the wire."""
        import json

        from ledger.gateway import SERVER_BOOTSTRAP

        assert "decision" not in SERVER_BOOTSTRAP  # nothing special-cased client-side
        fact = {"subject": "sky", "predicate": "colour", "object": "blue"}
        gate = McpGate(sink_path=str(tmp_path / "p.jsonl"))
        verdict = gate.decide("memory", {"fact": fact, "existing": []})
        # memory is a payload pack: ok, but no decision content comes back
        assert verdict["status"] == "ok"
        assert verdict["destination"] is None
        assert "blue" not in json.dumps(verdict)

"""A live end-to-end run against a real model — no cloud key required.

Everything else in this package is unit-tested or replayed. This drives a real
`Conversation`: a real agent loop, with real SDK `Message` objects reaching
`select_llm` through the SDK's own call path rather than ours. It is the run that
catches integration mistakes the replay harness cannot.

**Honest labelling — read this before believing the output.**

  * With no cloud credentials available, *both* lanes are local Ollama endpoints; the
    "cloud" lane is a stand-in distinguished by name and usage_id. Every routing
    decision and receipt below is genuine, but no byte actually crosses a network to a
    third party. Point the cloud lane at a real provider (see `sovereign_demo.py`) and
    nothing else changes.
  * Sovereign content arrives here **in the user's own message**, the way someone
    pastes a config file into a chat. A 3B local model will not reliably call tools on
    an 8GB machine, so a tool-driven read cannot be demonstrated at this size — but the
    gate acts on the payload, not on how the payload reached the payload, so the
    routing decision being exercised is the real one.

    ollama serve &
    python -m ledger.demo.live_local
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

from pydantic import SecretStr


os.environ.setdefault("OPENHANDS_SUPPRESS_BANNER", "1")
logging.getLogger("openhands").setLevel(logging.ERROR)
logging.getLogger("litellm").setLevel(logging.ERROR)

from ledger.analyzer import EBRMSecurityAnalyzer  # noqa: E402
from ledger.classify import Governance, LabelIndex  # noqa: E402
from ledger.harness.workspace import SOVEREIGN_KEYS, build_workspace  # noqa: E402
from ledger.receipts import ChainedJsonlSink, format_tail  # noqa: E402
from ledger.router import SovereignEgressRefused, SovereignRouter  # noqa: E402
from openhands.sdk import LLM, Agent, Conversation, Tool  # noqa: E402
from openhands.sdk.security import ConfirmRisky  # noqa: E402
from openhands.tools.file_editor import FileEditorTool  # noqa: E402
from openhands.tools.terminal import TerminalTool  # noqa: E402


MODEL = os.environ.get("LOCAL_MODEL", "ollama/llama3.2:3b")
BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

# The default preset also loads the browser toolset, whose schema alone overwhelms a 3B
# model's context window.
TOOLS = [Tool(name=TerminalTool.name), Tool(name=FileEditorTool.name)]

PASTED_SECRET = SOVEREIGN_KEYS[1]  # the postgres connection string

SCENARIOS = [
    (
        "clean question",
        "What does the word 'widget' mean here? One sentence.",
        ("local", "cloud"),
        "expect: routed to cloud — nothing sensitive in the payload",
    ),
    (
        "sovereign content pasted in",
        f"Here is our connection string: {PASTED_SECRET}\nWhich host does it name?",
        ("local", "cloud"),
        "expect: routed to LOCAL — sovereign content may not egress",
    ),
    (
        "sovereign, cloud-only deployment",
        f"Here is our connection string: {PASTED_SECRET}\nWhich host does it name?",
        ("cloud",),
        "expect: REFUSED — no permitted destination, never a silent fallback",
    ),
]


def lane(name: str) -> LLM:
    # reasoning_effort defaults to "high", which makes the SDK send a `thinking`
    # parameter that small Ollama models reject outright.
    return LLM(
        usage_id=name,
        model=MODEL,
        base_url=BASE_URL,
        api_key=SecretStr("ollama"),
        reasoning_effort="none",
    )


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="ledger-live-"))
    workspace = build_workspace(root / "workspace")
    governance = Governance.load(workspace)
    index = LabelIndex.build(workspace, governance)
    sink = ChainedJsonlSink(workspace / ".ebrm" / "receipts.jsonl")

    print(f"model:     {MODEL} (both lanes — see module docstring)")
    print(f"workspace: {workspace}\n")

    for name, prompt, lanes, expectation in SCENARIOS:
        router = SovereignRouter.build(
            workspace=str(workspace),
            llms={n: lane(n) for n in lanes},
            governance=governance,
            index=index,
            sink=sink,
        )
        analyzer = EBRMSecurityAnalyzer.build(
            workspace=str(workspace), index=index, sink=sink
        )
        conversation = Conversation(
            agent=Agent(llm=router, tools=TOOLS),
            workspace=str(workspace),
            callbacks=[analyzer.callback()],
        )
        conversation.set_security_analyzer(analyzer)
        conversation.set_confirmation_policy(ConfirmRisky(threshold="HIGH"))

        print(f"── {name}  (lanes: {', '.join(lanes)})")
        print(f"   {expectation}")
        refused = None
        try:
            conversation.send_message(prompt)
            conversation.run()
        except SovereignEgressRefused as exc:
            refused = str(exc)
        except Exception as exc:  # noqa: BLE001 — a small local model failing is not our bug
            refused = str(exc) if "SovereignEgressRefused" in repr(exc) else None
            if refused is None:
                print(f"   (model/loop error: {type(exc).__name__})")

        for decision in router.decisions:
            labels = ",".join(decision["classification"]["labels"]) or "-"
            verdict = decision["destination"] or "REFUSED"
            print(f"   RESULT  {verdict:<8} labels={labels}")
        if refused:
            print(f"   refusal: {refused[:100]}")
        if analyzer.tainted_labels:
            print(f"   session taint: {','.join(analyzer.tainted_labels)}")
        print()

    print(f"── receipts\n{format_tail(sink.path, 40)}")
    shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

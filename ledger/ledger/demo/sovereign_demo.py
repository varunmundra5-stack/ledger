"""Wire the gate into a real Conversation.

This is the reference wiring a deployer copies. It needs live models, so it is not
part of the test suite — `python -m ledger.harness` proves the gate with no keys.

    export LLM_API_KEY=...            # Moonshot / NVIDIA NIM / any litellm provider
    export LLM_MODEL=moonshot/kimi-k2-0905-preview
    ollama serve &                    # the local lane
    python -m ledger.demo.sovereign_demo /path/to/workspace

Four wiring points, all public SDK seams:

  1. `SovereignRouter` as the agent's LLM   — governs where each call goes
  2. `set_security_analyzer(...)`           — governs what may be committed
  3. `ConfirmRisky(threshold=HIGH)`         — a denial pauses instead of executing
  4. `callbacks=[analyzer.callback()]`      — keeps session taint current

The driver auto-rejects whatever the analyzer denies, so a refusal is a refusal
rather than a prompt. Swap in a human prompt here if you want approvals instead.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from pydantic import SecretStr

from ledger.analyzer import EBRMSecurityAnalyzer
from ledger.classify import Governance, LabelIndex
from ledger.receipts import ChainedJsonlSink, format_tail
from ledger.router import SovereignEgressRefused, SovereignRouter
from openhands.sdk import LLM, Agent, Conversation
from openhands.sdk.security import ConfirmRisky
from openhands.tools.preset.default import get_default_tools


def build_conversation(workspace: str):
    """Assemble a governed conversation over `workspace`."""
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        raise SystemExit(
            "set LLM_API_KEY (Moonshot, NVIDIA NIM, or any litellm provider)"
        )

    governance = Governance.load(workspace)
    index = LabelIndex.build(workspace, governance)
    sink = ChainedJsonlSink(Path(workspace) / ".ebrm" / "receipts.jsonl")

    router = SovereignRouter.build(
        workspace=workspace,
        llms={
            "cloud": LLM(
                usage_id="cloud",
                model=os.environ.get("LLM_MODEL", "moonshot/kimi-k2-0905-preview"),
                base_url=os.environ.get("LLM_BASE_URL"),
                api_key=SecretStr(api_key),
            ),
            "local": LLM(
                usage_id="local",
                model=os.environ.get("LOCAL_MODEL", "ollama/qwen3:1.7b"),
                base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
                api_key=SecretStr("ollama"),
            ),
        },
        governance=governance,
        index=index,
        sink=sink,
    )

    analyzer = EBRMSecurityAnalyzer.build(workspace=workspace, index=index, sink=sink)
    agent = Agent(llm=router, tools=get_default_tools())
    conversation = Conversation(
        agent=agent, workspace=workspace, callbacks=[analyzer.callback()]
    )
    conversation.set_security_analyzer(analyzer)
    conversation.set_confirmation_policy(ConfirmRisky(threshold="HIGH"))
    return conversation, analyzer, router, sink


def main() -> int:
    workspace = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    prompt = sys.argv[2] if len(sys.argv) > 2 else "Summarise what this workspace does."

    conversation, analyzer, router, sink = build_conversation(workspace)
    conversation.send_message(prompt)
    try:
        conversation.run()
    except SovereignEgressRefused as refusal:
        print(f"\nREFUSED — {refusal}")

    print("\n--- routing decisions ---")
    for decision in router.decisions:
        labels = decision["classification"]["labels"] or ["(none)"]
        print(f"  {decision['destination'] or 'REFUSED':<8} labels={labels}")

    print("\n--- action verdicts ---")
    for verdict in analyzer.verdicts:
        state = "DENIED " if verdict["denied"] else "allowed"
        print(f"  {state} {verdict['tool']:<16} {verdict['violations'] or ''}")

    print(f"\n--- receipts ---\n{format_tail(sink.path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""The final-answer gate — governing what the agent commits as its answer.

Upstream exempts the finish step from analyzers outright: `Agent._requires_user_
confirmation` returns False for a lone `FinishAction`, so a `SecurityAnalyzerBase`
never sees the answer. That is a reasonable default for a coding agent and a hole for
a governed one, since the answer is the one artifact that always leaves the loop.

Patching the SDK would close it and forfeit the de-fork, so the gate lives here, on
the driver side, fed by a conversation callback. Same pack, same receipts as every
other decision.

**What is actually being decided.** An answer is a committed output with a
destination. Showing sovereign content to the operator who owns it is not a leak, so
the default answer destination is `local`. A deployment that ships transcripts
somewhere else — a hosted UI, a cloud logger, a ticket — declares that destination in
`.governance.yaml`, and then a sovereign-bearing answer is refused rather than
transmitted:

    answer_destination: cloud     # transcripts are shipped off-box

The gate withholds; it never edits. A redacted answer would be a silent, unverifiable
transformation — exactly the kind of plausible-but-unchecked behaviour this layer
exists to replace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ledger.classify import Governance, LabelIndex, event_text


DEFAULT_ANSWER_DESTINATION = "local"


def answer_destination(governance: Governance) -> str:
    """Where committed answers go. `local` (the operator's own screen) unless the
    deployment declares otherwise."""
    declared = governance.policy.get("answer_destination")
    if isinstance(declared, str) and declared:
        return declared
    return DEFAULT_ANSWER_DESTINATION


@dataclass
class FinalAnswerGate:
    """Gates the agent's final message before the driver releases it."""

    index: LabelIndex
    governance: Governance
    sink: Any = None
    verdicts: list = field(default_factory=list)

    @property
    def destination(self) -> str:
        return answer_destination(self.governance)

    def check(self, text: str) -> dict:
        """Decide whether this answer may be committed to its destination."""
        from energy_orchestrator.domains.routing_policy import routing_policy_pack

        classification = self.index.classify_text(text or "")
        resolution = routing_policy_pack().solve(
            {
                "candidates": [self.destination],
                "classification": classification,
                "policy": self.governance.policy,
            },
            sink=self.sink,
        )
        verdict = {
            "allowed": resolution.status == "ok",
            "labels": classification["labels"],
            "sources": classification["sources"],
            "destination": self.destination,
            "reason": resolution.refusal_reason,
        }
        self.verdicts.append(verdict)
        return verdict

    @property
    def withheld(self) -> list:
        return [v for v in self.verdicts if not v["allowed"]]

    def callback(self):
        """A conversation callback that gates every finish event.

        Matches on the action's class name rather than importing `FinishAction`, so the
        gate keeps working if upstream moves the symbol — and still fires for any future
        terminal action shaped the same way.
        """

        def _on_event(event) -> None:
            action = getattr(event, "action", None)
            if action is None or "finish" not in type(action).__name__.lower():
                return
            message = getattr(action, "message", None)
            self.check(message if isinstance(message, str) else event_text(event))

        return _on_event


def release(gate: FinalAnswerGate, text: str) -> tuple[bool, str]:
    """What the driver prints. Returns `(allowed, text_or_refusal)`."""
    verdict = gate.check(text)
    if verdict["allowed"]:
        return True, text
    return False, (
        "[withheld] the answer carries "
        f"{', '.join(verdict['labels'])} content, which may not go to "
        f"'{verdict['destination']}' — {verdict['reason']}"
    )


__all__ = [
    "DEFAULT_ANSWER_DESTINATION",
    "FinalAnswerGate",
    "answer_destination",
    "release",
]

"""EBRMSecurityAnalyzer — the exact commit gate.

Drops into the SDK's own extension seam (`conversation.set_security_analyzer(...)`), so
this is a plugin, not a patch. It replaces the upstream `LLMSecurityAnalyzer`'s
ask-the-model-to-rate-itself with an exact check against `action_policy`, and emits a
`DecisionRecord` for every verdict.

Two SDK behaviours make this safe by construction and are worth naming:

  * `analyze_pending_actions` catches exceptions from `security_risk` and **defaults to
    HIGH** — so a bug in our gate blocks the action rather than waving it through. Our
    own fail-closed design and the SDK's agree.
  * The check runs in `Agent.step` **before any tool executes**, so a HIGH verdict under
    `ConfirmRisky` stops the action rather than reporting on it afterwards.

Session taint is the reason this is an analyzer and not a stateless function: whether
`curl` is acceptable depends on whether sovereign content has entered the conversation.
`observe()` is fed by a conversation callback and accumulates that.
"""

from __future__ import annotations

from typing import Any

from pydantic import PrivateAttr

from ledger.classify import LabelIndex, event_text
from openhands.sdk.event import ActionEvent
from openhands.sdk.security import SecurityAnalyzerBase
from openhands.sdk.security.risk import SecurityRisk


def normalize_action(
    action_event: ActionEvent, index: LabelIndex | None = None
) -> dict:
    """Flatten an SDK `ActionEvent` into the shape `action_policy` rules over.

    Duck-typed across tools (terminal has `command`, the file editor has
    `command`/`path`/`file_text`) and defensive about unknown tools: anything we cannot
    read is reported as-is and the policy decides, rather than being assumed benign.
    """
    action = getattr(action_event, "action", None)
    tool_name = (getattr(action_event, "tool_name", "") or "").lower()
    get = lambda field: getattr(action, field, None)  # noqa: E731 — terse local accessor

    command = get("command")
    path = get("path") or ""
    text = " ".join(str(x) for x in (get("file_text"), get("new_str")) if x)

    # The file editor overloads `command` with an edit verb (view/create/str_replace);
    # only the terminal's `command` is a shell line.
    is_shell = "terminal" in tool_name or "bash" in tool_name or "execute" in tool_name
    edit_verbs = {"create", "write", "str_replace", "insert", "append"}
    kind = (
        "shell"
        if is_shell
        else "write"
        if (isinstance(command, str) and command in edit_verbs) or text
        else "read"
    )

    return {
        "tool": tool_name,
        "kind": kind,
        "command": command if is_shell and isinstance(command, str) else "",
        "edit_verb": "" if is_shell else (command if isinstance(command, str) else ""),
        "path": path,
        "carries_labels": bool(index and text and index.classify_text(text)["labels"]),
    }


class EBRMSecurityAnalyzer(SecurityAnalyzerBase):
    """Exact, receipted action gating. HIGH means the policy denied the action."""

    # NB: no `kind` field — `DiscriminatedUnionMixin` computes it from the class name,
    # and declaring it here collides with that computed field.
    workspace: str = ""

    _index: LabelIndex = PrivateAttr(default_factory=LabelIndex)
    _sink: Any = PrivateAttr(default=None)
    _tainted: set = PrivateAttr(default_factory=set)
    _verdicts: list = PrivateAttr(default_factory=list)

    @classmethod
    def build(
        cls, *, workspace: str, index: LabelIndex, sink=None
    ) -> EBRMSecurityAnalyzer:
        analyzer = cls(workspace=workspace)
        analyzer._index = index
        analyzer._sink = sink
        return analyzer

    # ── session taint ────────────────────────────────────────────────────────

    @property
    def tainted_labels(self) -> tuple[str, ...]:
        return tuple(sorted(self._tainted))

    @property
    def verdicts(self) -> list:
        return self._verdicts

    def observe(self, event) -> None:
        """Feed conversation events in. Any event whose text carries labelled content
        taints the session — regardless of which tool pulled it in. Taint is monotonic:
        once sovereign bytes are in the context they cannot be un-seen."""
        self._tainted.update(self._index.classify_text(event_text(event))["labels"])

    def callback(self):
        """A conversation callback that keeps taint current: `Conversation(...,
        callbacks=[analyzer.callback()])`."""

        def _on_event(event) -> None:
            self.observe(event)

        return _on_event

    # ── the gate ─────────────────────────────────────────────────────────────

    def security_risk(self, action: ActionEvent) -> SecurityRisk:
        from energy_orchestrator.domains.routing_policy import (
            routing_policy_pack,  # noqa: F401
        )

        from ledger.action_policy import action_policy_pack, violations

        normalized = normalize_action(action, self._index)
        request = {
            "action": normalized,
            "tainted_labels": self.tainted_labels,
            "workspace": self.workspace,
        }
        resolution = action_policy_pack().solve(request, sink=self._sink)
        denied = resolution.status != "ok"
        self._verdicts.append(
            {
                "tool": normalized["tool"],
                "kind": normalized["kind"],
                "denied": denied,
                "violations": violations(normalized, request),
                "tainted": self.tainted_labels,
            }
        )
        return SecurityRisk.HIGH if denied else SecurityRisk.LOW


__all__ = ["EBRMSecurityAnalyzer", "normalize_action"]

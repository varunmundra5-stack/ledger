"""SovereignRouter — the governed local-vs-cloud decision.

This is the direct counter to the hybrid orchestrator Perplexity shipped in July 2026,
where an on-device *model* decides, per sub-task, whether work stays local or goes to a
cloud frontier model. That makes an unverified learned classifier the thing standing
between your data and someone else's servers.

Here the same decision is an argmin over destinations under exact deny-rules
(`energy_orchestrator.domains.routing_policy`), taken on the **exact bytes about to
leave** rather than on a prediction about them, and it can **refuse**: when no permitted
destination is available the call raises instead of quietly picking the reachable one.
Every decision leaves a receipt.

    router = SovereignRouter.build(workspace=".", cloud=cloud_llm, local=local_llm)
    agent = Agent(llm=router, tools=tools)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ledger.classify import Governance, LabelIndex, message_text
from openhands.sdk.llm import LLM, Message
from openhands.sdk.llm.router import RouterLLM


GATE_ATTR = "_gate"


@dataclass
class _GateState:
    """The router's own state, held outside pydantic's private-attribute machinery.

    `RouterLLM.__getattr__` forwards *every* attribute miss to the fallback LLM without
    deferring to `BaseModel.__getattr__` first, which is where pydantic keeps
    `PrivateAttr` values — so a `PrivateAttr` on a RouterLLM subclass is unreadable
    and surfaces as a baffling `'LLM' object has no attribute '_index'`. Keeping our
    state in
    the instance `__dict__` (set via `object.__setattr__`) means normal lookup finds it
    and `__getattr__` never runs. Upstream quirk, worked around in our subclass — the
    de-fork rule forbids patching the SDK for it.
    """

    index: LabelIndex = field(default_factory=LabelIndex)
    governance: Governance = field(default_factory=Governance)
    sink: Any = None
    decisions: list = field(default_factory=list)


class SovereignEgressRefused(RuntimeError):
    """No permitted destination for this payload. Raised instead of routing.

    The refusal is the product: a silent fallback to a reachable destination is exactly
    the failure this layer exists to prevent.
    """


class SovereignRouter(RouterLLM):
    """Routes each LLM call to the destination the policy permits.

    `llms_for_routing` keys are destination names (`"local"`, `"cloud"`, …) and must
    match
    the destinations named in the governance policy.
    """

    router_name: str = "sovereign_router"

    @classmethod
    def build(
        cls,
        *,
        workspace: str,
        llms: dict[str, LLM],
        governance: Governance | None = None,
        index: LabelIndex | None = None,
        sink=None,
        usage_id: str = "sovereign-router",
        **kwargs,
    ) -> SovereignRouter:
        """Construct a router over `llms` (destination name -> LLM) for `workspace`."""
        governance = governance or Governance.load(workspace)
        router = cls(usage_id=usage_id, llms_for_routing=llms, **kwargs)
        object.__setattr__(
            router,
            GATE_ATTR,
            _GateState(
                index=index
                if index is not None
                else LabelIndex.build(workspace, governance),
                governance=governance,
                sink=sink,
            ),
        )
        return router

    @property
    def gate(self) -> _GateState:
        state = self.__dict__.get(GATE_ATTR)
        if state is None:
            # Constructed directly rather than through build(): fail closed. An
            # unconfigured gate must never route, since it would classify everything as
            # clean and send it to the default destination.
            raise SovereignEgressRefused(
                "SovereignRouter has no gate state — construct it with "
                "SovereignRouter.build(...)"
            )
        return state

    @property
    def decisions(self) -> list:
        """Every routing decision taken, for tests and the leak report."""
        return self.gate.decisions

    def classify(self, messages: list[Message]) -> dict:
        return self.gate.index.classify_text(message_text(messages))

    def select_llm(self, messages: list[Message]) -> str:
        from energy_orchestrator.domain_pack import get
        from energy_orchestrator.domains.routing_policy import routing_policy_pack

        gate = self.gate
        classification = self.classify(messages)
        candidates = gate.governance.destinations or list(self.llms_for_routing)
        # Only offer destinations we can actually reach; the policy then rules on those.
        offered = [d for d in candidates if d in self.llms_for_routing]

        try:
            pack = get("routing_policy")
        except KeyError:
            pack = routing_policy_pack()

        resolution = pack.solve(
            {
                "candidates": offered,
                "classification": classification,
                "policy": gate.governance.policy,
            },
            sink=gate.sink,
        )
        gate.decisions.append(
            {
                "status": resolution.status,
                "classification": classification,
                "offered": offered,
                "destination": (
                    resolution.answer.content["destination"]
                    if resolution.status == "ok"
                    else None
                ),
                "reason": resolution.refusal_reason,
            }
        )

        if resolution.status != "ok":
            raise SovereignEgressRefused(
                f"no permitted destination for labels={classification['labels']} "
                f"among {offered}: {resolution.refusal_reason}"
            )
        return resolution.answer.content["destination"]


__all__ = ["SovereignRouter", "SovereignEgressRefused"]

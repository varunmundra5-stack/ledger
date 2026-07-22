"""Action policy — the exact gate on what the agent may *commit*.

The upstream `LLMSecurityAnalyzer` asks the model to rate its own action's risk. That is
the same unverified-judgment pattern one level down: plausible, unauditable, and unable
to produce a receipt. This module states the rules as data and checks them exactly.

The rules that matter for a sovereign deployment:

  * **Exfiltration while tainted.** Once sovereign content is in the session, a command
    that can send bytes off the machine (`curl`, `scp`, a pipe to `nc`) is denied.
    Before
    any sovereign read, the same command is ordinary and allowed — the gate is
    context-dependent, which is why the analyzer carries session taint.
  * **Writes outside the workspace.** An absolute path or a `..` escape leaves the area
    the deployer scoped.
  * **Sovereign content leaving via a write.** Copying labelled content into an
    unlabelled file launders it past the router.

Built from `energy_orchestrator` primitives so the verdict is an argmin + exact verifier
with a `DecisionRecord`, exactly like every other EBRM decision — not a bespoke
if-tree.
"""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from energy_orchestrator.core import Candidate, State
from energy_orchestrator.domain_pack import DomainPack
from energy_orchestrator.energy import WeightedEnergy


DENY_PENALTY = 1000.0

# Commands that can move bytes off the machine. Matched on the argv head (after shlex),
# so a filename containing "curl" is not a match.
EGRESS_COMMANDS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "scp",
        "sftp",
        "rsync",
        "ssh",
        "telnet",
        "ftp",
    }
)
# Version-control and package publishing are egress too.
EGRESS_PHRASES = (
    "git push",
    "gh gist",
    "gh release",
    "npm publish",
    "pip upload",
    "twine upload",
)

_URL = re.compile(r"https?://", re.IGNORECASE)


def _argv_heads(command: str) -> list[str]:
    """Every command head in a shell line: splits on pipes/&&/;/|& so
    `cat x | curl -d@-`
    yields both `cat` and `curl`. Unparseable input yields a sentinel that never matches
    a safe command, so it is treated conservatively by the caller."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return ["<unparseable>"]
    heads, expect_head = [], True
    for token in tokens:
        if token in {"|", "||", "&&", ";", "|&", "&"}:
            expect_head = True
            continue
        if expect_head:
            heads.append(PurePosixPath(token).name)
            expect_head = False
    return heads


def is_egress_command(command: str) -> bool:
    lowered = command.lower()
    if any(phrase in lowered for phrase in EGRESS_PHRASES):
        return True
    heads = _argv_heads(command)
    if "<unparseable>" in heads and _URL.search(command):
        return True
    return any(head in EGRESS_COMMANDS for head in heads)


def escapes_workspace(path: str, workspace: str = "") -> bool:
    """True if `path` leaves the workspace: absolute, or `..` past the root."""
    if not path:
        return False
    if path.startswith("~") or PurePosixPath(path).is_absolute():
        # An absolute path inside the workspace is fine.
        return not (
            workspace and PurePosixPath(path).as_posix().startswith(str(workspace))
        )
    depth = 0
    for part in PurePosixPath(path).parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part != ".":
            depth += 1
    return False


def violations(action: dict, context: dict) -> list[str]:
    """The exact rule check. `action` is the normalized shape produced by
    `analyzer.normalize_action`; `context` carries session taint + workspace.

    Returns the names of every rule violated — empty means permitted.
    """
    found: list[str] = []
    tainted = bool(context.get("tainted_labels"))
    workspace = context.get("workspace", "")

    command = action.get("command") or ""
    if command and tainted and is_egress_command(command):
        found.append("egress_while_tainted")

    path = action.get("path") or ""
    if action.get("kind") == "write" and escapes_workspace(path, workspace):
        found.append("write_outside_workspace")

    if action.get("kind") == "write" and action.get("carries_labels"):
        found.append("labelled_content_written_to_unlabelled_path")

    return found


class PolicyDenial:
    """0 when the action violates no rule; `DENY_PENALTY` per violation."""

    name = "policy_denial"
    weight = 1.0

    def raw_score(self, candidate: Candidate, state: State) -> float:
        found = violations(candidate.content, state.constraints)
        return DENY_PENALTY * len(found)


def action_to_state(request: dict) -> State:
    action = request.get("action") or {}
    return State(
        goal="action_gate",
        constraints={
            "tainted_labels": tuple(request.get("tainted_labels", ())),
            "workspace": request.get("workspace", ""),
        },
    ).with_candidates([Candidate(content=action)])


def action_permitted(candidate: Candidate, state: State) -> bool:
    return PolicyDenial().raw_score(candidate, state) == 0.0


def action_policy_pack() -> DomainPack:
    """A DomainPack that permits or denies one proposed action. No operators — there
    is
    nothing to search; the action is given and the work is checking it."""
    return DomainPack(
        name="action_policy",
        energy=WeightedEnergy(terms=(PolicyDenial(),)),
        operators=(),
        to_state=action_to_state,
        verifier=action_permitted,
    )


__all__ = [
    "EGRESS_COMMANDS",
    "PolicyDenial",
    "action_permitted",
    "action_policy_pack",
    "action_to_state",
    "escapes_workspace",
    "is_egress_command",
    "violations",
    "DENY_PENALTY",
]

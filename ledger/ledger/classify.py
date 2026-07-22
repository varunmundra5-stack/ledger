"""Payload classification — what the governance decision is *about*.

The gate can only be exact if the classification is exact. Perplexity Computer's hybrid
orchestrator asks a model "should this stay local?"; here we answer a narrower question
that has a checkable answer: **does this payload contain content from a labelled file?**

Two mechanisms, deliberately layered:

  * **Declarative labels** (`.governance.yaml`) map glob patterns to labels —
    `sovereign: ["sovereign/**"]`. Cheap, legible, and the thing a deployer edits.
  * **Content fingerprints** are the *truth*. Every labelled file is shingled into
    normalized hashes; an outbound payload is classified by matching those hashes. This
    catches sovereign bytes no matter how they entered the context — read by the file
    tool, `cat`-ed by a shell command, pasted by the model, or summarized into a later
    turn — which a path-based tap alone would miss.

Nothing here decides anything. It produces the `{"labels": [...], "sources": [...]}`
classification that `energy_orchestrator`'s `routing_policy` pack then rules on.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml


CONFIG_NAME = ".governance.yaml"

# A shingle is 8 consecutive normalized words. Long enough that ordinary prose does not
# collide by chance, short enough to catch a quoted fragment of a labelled file.
SHINGLE_WORDS = 8
# Lines shorter than this are ignored as standalone fingerprints (`{`, `import os`, a
# bare number) — they appear in unlabelled files too and would fire constantly.
MIN_LINE_CHARS = 24
# A single token this long that also contains a non-letter is fingerprinted on its own.
# Found by a live run: a connection string pasted into a chat matched NOTHING, because a
# line fingerprint needs the whole line and a shingle needs eight consecutive words —
# a lone secret quoted into new surrounding prose satisfies neither. Requiring a
# non-letter keeps ordinary long words ("responsibilities") from ever qualifying, while
# catching every credential shape: URLs, keys, hashes, hyphenated codes.
TOKEN_MIN_CHARS = 16

_WS = re.compile(r"\s+")

DEFAULT_CONFIG: dict = {
    "labels": {"sovereign": ["sovereign/**"]},
    "destinations": ["local", "cloud"],
    "policy": {
        "hard": [{"label": "sovereign", "deny": ["cloud"]}],
        "prefer": {"default": "cloud", "when": {"sovereign": "local"}},
    },
}


def _normalize(text: str) -> str:
    return _WS.sub(" ", text).strip().lower()


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def is_distinctive_token(token: str) -> bool:
    """A token long enough, and irregular enough, to identify content on its own."""
    return len(token) >= TOKEN_MIN_CHARS and not token.isalpha()


def fingerprints(text: str) -> set[str]:
    """Content fingerprints for `text`, at three granularities — because leaked
    content takes three shapes: whole lines (a file copied verbatim), 8-word shingles
    (quoted or re-wrapped prose), and lone distinctive tokens (a credential lifted
    into new surrounding text)."""
    out: set[str] = set()
    for line in text.splitlines():
        normalized = _normalize(line)
        if len(normalized) >= MIN_LINE_CHARS:
            out.add(_digest(normalized))
    words = _normalize(text).split()
    for i in range(len(words) - SHINGLE_WORDS + 1):
        out.add(_digest(" ".join(words[i : i + SHINGLE_WORDS])))
    for word in words:
        stripped = word.strip(".,;:!?()[]{}\"'")
        if is_distinctive_token(stripped):
            out.add(_digest(stripped))
    return out


@dataclass(frozen=True)
class Governance:
    """The deployer's declarative governance config."""

    labels: dict[str, list[str]] = field(default_factory=dict)
    destinations: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict) -> Governance:
        return cls(
            labels={k: list(v) for k, v in (raw.get("labels") or {}).items()},
            destinations=list(raw.get("destinations") or []),
            policy=raw.get("policy") or {},
        )

    @classmethod
    def load(cls, workspace: str | Path) -> Governance:
        """Load `<workspace>/.governance.yaml`, falling back to a sovereign/ default.

        A config that exists but cannot be parsed raises: a deployer who wrote
        governance must never have it silently ignored. (A *missing* config is
        different — that is
        an undeclared deployment, and the default is the conservative one.)
        """
        path = Path(workspace) / CONFIG_NAME
        if not path.exists():
            return cls.from_dict(DEFAULT_CONFIG)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: governance config must be a mapping")
        return cls.from_dict(raw)

    def label_for(self, relative_path: str) -> str | None:
        """The first label whose glob matches `relative_path`, else None."""
        for label, patterns in self.labels.items():
            for pattern in patterns:
                if fnmatch(relative_path, pattern) or fnmatch(
                    relative_path, f"{pattern}/*"
                ):
                    return label
        return None


@dataclass
class LabelIndex:
    """Content fingerprints of every labelled file in a workspace."""

    by_fingerprint: dict[str, tuple[str, str]] = field(
        default_factory=dict
    )  # fp -> (label, source)

    @classmethod
    def build(cls, workspace: str | Path, governance: Governance) -> LabelIndex:
        root = Path(workspace)
        index: dict[str, tuple[str, str]] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            label = governance.label_for(relative)
            if label is None:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # binary or unreadable: no text fingerprints to take
            for fp in fingerprints(text):
                index.setdefault(fp, (label, relative))
        return cls(by_fingerprint=index)

    def classify_text(self, text: str) -> dict:
        """Classify a payload. Returns the `{"labels", "sources"}` shape the
        `routing_policy` pack expects — sorted, so the decision is deterministic."""
        labels: set[str] = set()
        sources: set[str] = set()
        for fp in fingerprints(text):
            hit = self.by_fingerprint.get(fp)
            if hit is not None:
                labels.add(hit[0])
                sources.add(hit[1])
        return {"labels": sorted(labels), "sources": sorted(sources)}

    def matched_fingerprints(self, text: str) -> set[str]:
        """The labelled fingerprints in `text`. The M3 leak sensor counts these."""
        return {fp for fp in fingerprints(text) if fp in self.by_fingerprint}


def _walk_strings(value):
    """Every string anywhere in a nested structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_strings(item)


def event_text(event) -> str:
    """All text carried by an SDK event, however it is nested.

    Walks the dumped model rather than serializing to JSON: JSON escaping would turn
    newlines into literal `\\n` and silently break fingerprint matching on multi-line
    content — a false negative in exactly the place we cannot afford one.
    """
    dump = getattr(event, "model_dump", None)
    if callable(dump):
        try:
            return "\n".join(_walk_strings(dump()))
        except Exception:  # noqa: BLE001 — a model that will not dump falls through
            pass
    parts = [
        value
        for attr in ("content", "observation", "message", "text", "command")
        if isinstance(value := getattr(event, attr, None), str)
    ]
    return "\n".join(parts) if parts else str(event)


def message_text(messages) -> str:
    """Flatten SDK `Message`s to the text that would actually leave the machine.

    Duck-typed on purpose: works for `Message` objects, plain dicts, and raw strings, so
    the classifier is testable without constructing SDK types.
    """
    parts: list[str] = []
    for message in messages:
        content = getattr(message, "content", None)
        if content is None and isinstance(message, dict):
            content = message.get("content")
        if content is None:
            parts.append(str(message))
            continue
        if isinstance(content, str):
            parts.append(content)
            continue
        for item in content:
            text = getattr(item, "text", None)
            if text is None and isinstance(item, dict):
                text = item.get("text")
            if text:
                parts.append(text)
    return "\n".join(parts)


__all__ = [
    "CONFIG_NAME",
    "DEFAULT_CONFIG",
    "Governance",
    "LabelIndex",
    "event_text",
    "is_distinctive_token",
    "fingerprints",
    "message_text",
]

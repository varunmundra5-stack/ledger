"""Receipts — the tamper-evident decision log.

`energy_orchestrator.provenance` already emits a `DecisionRecord` per decision (hashes,
never payloads). This adds the one property an auditor actually needs and that is far
cheaper to build in now than to retrofit: **each line commits to the one before it**, so
a record cannot be edited or removed after the fact without breaking the chain.

Deliberately implemented at the *sink* level — `DecisionRecord` stays untouched, so
this
is additive to EBRM and lifts into its core later if it earns its keep.

    sink = ChainedJsonlSink(".ebrm/receipts.jsonl")
    ...
    ok, problem = verify_chain(".ebrm/receipts.jsonl")
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


GENESIS = "0" * 64


def _hash_entry(prev_hash: str, record: dict) -> str:
    """Commit to (previous hash, this record). Canonical JSON so the digest is stable
    across processes and key insertion order."""
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{prev_hash}\n{payload}".encode()).hexdigest()


class ChainedJsonlSink:
    """An append-only `RecordSink` whose lines form a hash chain.

    Satisfies EBRM's `RecordSink` protocol (`emit(record) -> None`), so it drops into
    any
    `sink=` slot: `pack.solve(..., sink=sink)`, `service.route(..., sink=sink)`.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        """Resume the chain across restarts."""
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    try:
                        last = json.loads(line)["entry_hash"]
                    except (ValueError, KeyError):
                        return last
        return last

    def emit(self, record) -> None:
        body = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        entry = {"prev_hash": self._prev, "record": body}
        entry["entry_hash"] = _hash_entry(self._prev, body)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        self._prev = entry["entry_hash"]

    def records(self) -> list[dict]:
        return [entry["record"] for entry in read_entries(self.path)]


def read_entries(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def verify_chain(path: str | Path) -> tuple[bool, str | None]:
    """Recompute every link. Returns `(ok, problem)` — `problem` names the first
    broken
    line, which is where tampering happened."""
    prev = GENESIS
    for i, entry in enumerate(read_entries(path)):
        if entry.get("prev_hash") != prev:
            return False, f"line {i + 1}: prev_hash does not match the previous entry"
        expected = _hash_entry(prev, entry.get("record", {}))
        if entry.get("entry_hash") != expected:
            return (
                False,
                f"line {i + 1}: record does not match its hash (edited or truncated)",
            )
        prev = entry["entry_hash"]
    return True, None


def format_tail(path: str | Path, n: int = 20) -> str:
    """Human-readable receipts, newest last — the demo's 'UI'."""
    entries = read_entries(path)[-n:]
    if not entries:
        return "(no receipts)"
    lines = []
    for entry in entries:
        r = entry["record"]
        verdict = "OK     " if r.get("status") == "ok" else "REFUSED"
        detail = r.get("refusal_reason") or r.get("answer_fingerprint", "")[:16]
        lines.append(f"{verdict}  {r.get('pack') or r.get('kind'):<16}  {detail}")
    ok, problem = verify_chain(path)
    lines.append(
        f"\nchain: {'intact' if ok else 'BROKEN — ' + str(problem)} "
        f"({len(read_entries(path))} records)"
    )
    return "\n".join(lines)


__all__ = ["ChainedJsonlSink", "verify_chain", "read_entries", "format_tail", "GENESIS"]

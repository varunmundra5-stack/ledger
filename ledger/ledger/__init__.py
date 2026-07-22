"""Ledger — a governed agent harness.

Every routing decision and every committed action passes an exact policy check and
leaves a receipt. The decision layer is `energy_orchestrator` (EBRM); this package is
graft onto the OpenHands SDK's public extension seams.

    from ledger import EBRMSecurityAnalyzer, SovereignRouter, ChainedJsonlSink
"""

from ledger.analyzer import EBRMSecurityAnalyzer, normalize_action
from ledger.classify import Governance, LabelIndex, fingerprints, message_text
from ledger.receipts import ChainedJsonlSink, format_tail, verify_chain
from ledger.router import SovereignEgressRefused, SovereignRouter


__all__ = [
    "ChainedJsonlSink",
    "EBRMSecurityAnalyzer",
    "Governance",
    "LabelIndex",
    "SovereignEgressRefused",
    "SovereignRouter",
    "fingerprints",
    "format_tail",
    "message_text",
    "normalize_action",
    "verify_chain",
]

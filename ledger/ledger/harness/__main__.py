"""Run the leak experiment: `python -m ledger.harness [outdir]`."""

import logging
import os
import sys
import tempfile
from pathlib import Path


os.environ.setdefault("OPENHANDS_SUPPRESS_BANNER", "1")
# The SDK logs an INFO line every time RouterLLM forwards an attribute to the fallback
# LLM. Harmless, but it buries the report.
logging.getLogger("openhands").setLevel(logging.WARNING)

from ledger.harness.experiment import format_report, run_experiment  # noqa: E402


def main() -> int:
    root = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(tempfile.mkdtemp(prefix="ledger-"))
    )
    report = format_report(run_experiment(root))
    print(report)
    print(f"\nartifacts: {root}")
    return 0 if "PASS" in report else 1


if __name__ == "__main__":
    raise SystemExit(main())

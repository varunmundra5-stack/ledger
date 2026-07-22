# Ledger — a governed agent harness

> Every routing decision and every committed action passes an **exact policy check**
> and leaves a **tamper-evident receipt**.

This is a fork of [OpenHands/software-agent-sdk](https://github.com/OpenHands/software-agent-sdk)
that adds one thing: a governed decision layer. Upstream is untouched — all of our code
lives in [`ledger/`](ledger/), hanging off the SDK's public extension seams.

## Why

Every agent harness in 2026 — Perplexity Computer, Copilot, Agentforce, OpenHands
itself — decides orchestration with an **LLM planner and a learned router**. In July
2026 Perplexity shipped a hybrid orchestrator where an on-device *model* decides, per
sub-task, whether work stays local or goes to a cloud frontier model. That makes an
unverified classifier the thing standing between your data and someone else's servers,
and it cannot produce an artifact proving what it decided or why.

Better models do not fix this. Capability lowers the error rate; it never produces a
receipt. **Verification is a category problem, not a capability problem.**

Ledger replaces the two decisions that matter with exact ones:

| | stock harness | Ledger |
|---|---|---|
| where a payload goes | learned router / fixed cloud | argmin over destinations under exact deny-rules |
| what may be committed | LLM rates its own action's risk | exact policy check over the proposed action |
| when it cannot comply | picks something reachable | **refuses** |
| what it leaves behind | request logs | hash-chained decision receipts |

The decision layer is [EBRM](https://github.com/varunmundra5-stack/ledger) —
`energy_orchestrator`, a zero-dependency library where a decision is `argmin E` over
candidates gated by an exact verifier, with calibrated refusal. No LLM runs anywhere in
the gate, which is what makes it able to gate the LLM.

## The measurement

`python -m ledger.harness` runs a controlled A/B on a synthetic workspace containing a
`sovereign/` folder. Both arms replay identical payloads through the same wire-level
sensor; only the governance configuration differs.

```
LEAK MATRIX — sovereign content reaching the cloud destination
==============================================================
                             stock    governed
sovereign fragments            501           0
distinct chunks                 24           0
tasks completed                 10          10
tasks refused                    0           0
egress cmds allowed              2           1
egress cmds denied               0           1
receipts written                 0          10

benign tasks completed — stock    ['t01', 't02', 't03', 't04', 't05']
                         governed ['t01', 't02', 't03', 't04', 't05']
receipt coverage (governed): 100% (10/10 decisions)
receipt chain: intact

VERDICT: PASS — the governed arm leaked nothing, completed every task the
stock arm completed, and receipted every decision
```

Read that last line carefully, because it is the whole claim: **zero leaks at zero
capability cost.** The governed arm did not refuse a single task — sovereign work simply
went to the local model instead. The one thing it denied was a `curl` to an external
endpoint *after* credentials had entered the context; the same `curl` on a clean session
was allowed. The gate is context-dependent, not a blocklist.

It is also falsifiable, and runs in CI as a test. If the governed arm ever leaks, or
starts refusing work the stock arm completes, the build fails.

## How it works

```
prompt ──► classify the exact outbound bytes ──► routing_policy (EBRM) ──► local | cloud
                                                        │                       │
                                                     refuse ◄───────────────────┘
                                                        │
proposed action ──► action_policy (EBRM) ──► allow | deny ──► receipt (hash-chained)
```

- **`classify.py`** — declarative labels from `.governance.yaml` (`sovereign: ["sovereign/**"]`)
  plus **content fingerprints**. Fingerprints are the truth: sovereign bytes are caught
  however they entered the context — read by the file tool, `cat`-ed by a shell command,
  or paraphrased by the model into a later turn.
- **`router.py`** — `SovereignRouter(RouterLLM)` classifies the payload about to leave and
  asks the policy. No permitted destination means it **raises**, never silently falls back.
- **`action_policy.py` / `analyzer.py`** — exact deny-rules (egress-while-tainted, workspace
  escape, labelled content laundered into an unlabelled path) enforced through the SDK's
  own `SecurityAnalyzerBase` seam, replacing the upstream ask-the-model-to-rate-itself
  analyzer.
- **`receipts.py`** — each line commits to the previous one, so a record cannot be edited
  or dropped without breaking the chain. Shaped for EU AI Act Article 26 deployer duties
  (human oversight, ≥6-month logs), which land in December 2027.

Everything fails closed: an unparseable policy, a missing classification, or an
unconfigured router all refuse rather than route.

## Try it

```bash
uv sync
python -m ledger.harness                 # the leak experiment, no API key needed
python -m pytest ledger/tests -q         # 36 tests
```

Live wiring against real models is in [`ledger/demo/sovereign_demo.py`](ledger/ledger/demo/sovereign_demo.py).

## Design rule: this is a plugin, not a patch

`ledger/` imports **only public `openhands.sdk.*` API** — enforced by a test. There are
zero patches to upstream code, so `git merge upstream/main` stays trivial and the package
can lift out into its own repo and install against unforked `openhands-sdk`. A fork whose
value is "upstream plus our analyzer" is roadkill within a year; the plan is to de-fork
once the measurement holds up.

## Status

Early. The gate, the router, the receipts, and the falsification harness work and are
tested. Not yet done: live end-to-end runs against Kimi/NIM, the final-answer gate
(upstream's `FinishAction` bypasses analyzers, so that one belongs in the driver), and
the de-fork.

Licensed MIT, as upstream. Ledger's additions are in `ledger/`.

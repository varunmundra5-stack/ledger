# Issue #3984 investigation evidence

This PR records the investigation artifact requested in issue #3984.

## What was verified

- `software-agent-sdk` has multiple `AGENTS.md` files: root, SDK, subagent, tools, workspace, and agent-server.
- The root `AGENTS.md` includes a package-specific map telling agents to read the closest relevant package-level `AGENTS.md`.
- Current SDK project-skill loading automatically loads third-party files such as `AGENTS.md` from the working directory and git root; nested package files are reached through prompt guidance rather than deterministic file-touch injection.

## Public artifacts

- Edited issue comment: https://github.com/OpenHands/software-agent-sdk/issues/3984#issuecomment-4880478649
- Show-me visualization: https://enyst.github.io/arch/issue-3984-agents-md-loading.html

Created by an AI agent (OpenHands) on behalf of the issue requester.

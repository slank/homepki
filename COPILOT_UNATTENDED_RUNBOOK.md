# Copilot Unattended Runbook

This runbook is for continuing work with minimal manual intervention.

## 1) Preferred setup

1. Open this chat session's approval settings.
2. Enable command/tool execution as **always allow for this session**.
3. Mark the repository as **trusted**.

## 2) Start point

1. Open `COPILOT_WORK_QUEUE.md`.
2. Find the first task not marked `done`.
3. Execute only that task and run only its checks.

## 3) If terminal approvals still block commands

Pick one path:

- **Path A (recommended):** fix session approvals and rerun checks.
- **Path B:** run required commands in your own terminal and paste output.
- **Path C:** rely on CI workflow success as the validation signal.

## 4) Command bundle for current blocker (M1.2)

```bash
make generate && make test && make lint && make build && make cross-build && make appliance-package
```

## 5) Minimal prompt format per task

Use `COPILOT_TASK_PROMPT_TEMPLATE.md` so each request stays small and avoids token waste.

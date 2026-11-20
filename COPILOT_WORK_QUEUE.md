# Copilot Work Queue (Plain Language)

This file is the **step-by-step checklist** for unattended execution.

## Terms

- **Task**: one small unit of work (for example, "add SQLite migrations").
- **Done**: code + tests/checks for that task are complete.
- **Blocked**: task cannot continue because of a specific external constraint.

## How unattended execution should run

1. Pick the first task marked `ready`.
2. Change only files needed for that task.
3. Run only the checks listed for that task.
4. Mark task `done` and move to the next `ready` task.
5. If blocked, write the blocker and stop only that task.

## Task list

| ID | Task | Depends on | Status |
|---|---|---|---|
| M1.1 | Create Go module and base folders | none | done |
| M1.2 | Add make targets (generate/test/lint/build/cross-build/package) | M1.1 | done |
| M1.3 | Add CI + release workflows | M1.2 | done (files created; validation pending with M1.2) |
| M2.1 | Add SQLite connection and migration runner | M1.3 | done |
| M2.2 | Add auth session + CSRF | M2.1 | done |
| M2.3 | Add audit logging + config validation | M2.2 | done |
| M3.1 | Add YubiKey/PKCS#11 interfaces + mocks | M2.3 | done |
| M3.2 | Add setup state machine persistence | M3.1 | done |
| M3.3 | Add systemd + mDNS fallback behavior | M3.2 | done |
| M4.1 | Add PKI service boundary interfaces | M3.3 | done |
| M4.2 | Integrate Step CA provision state | M4.1 | done |
| M4.3 | Add hardware signing failure handling | M4.2 | done |
| M5.1 | Setup wizard + admin login flow | M4.3 | done |
| M5.2 | Issue/inventory/revoke/delete flows | M5.1 | done |
| M5.3 | Trust guidance + destructive action warnings | M5.2 | done |
| M6.1 | Appliance packaging path (image or installer) | M5.3 | done |
| M6.2 | Backup/restore/factory reset flows | M6.1 | done |
| M6.3 | Upgrade/rollback + release logistics | M6.2 | done |
| M7.1 | Hardware acceptance + release candidate evidence | M6.3 | blocked (requires Raspberry Pi Zero 2 W, YubiKey, and physical smoke-test evidence) |

## Current active task

`M7.1 Hardware acceptance + release candidate evidence (external hardware required)`

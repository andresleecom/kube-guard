---
description: Temporarily relax a protected Kubernetes context (a "context leash") for one command or N minutes, then it auto-reverts.
---

Grant a time-boxed or single-command exception so a write can run against an otherwise `readonly` (production) context — without permanently lowering its guard.

## Steps

1. Confirm with the user: which **context**, for how long (one command or N minutes), and at what **level**.
2. Create the lease:
   - For N minutes: `node "${CLAUDE_PLUGIN_ROOT}/scripts/lease.mjs" <context> --minutes <N> --level strict`
   - For one command: `node "${CLAUDE_PLUGIN_ROOT}/scripts/lease.mjs" <context> --once --level strict`
3. Show active leases: `node "${CLAUDE_PLUGIN_ROOT}/scripts/lease.mjs" --list`
4. Revoke early: `node "${CLAUDE_PLUGIN_ROOT}/scripts/lease.mjs" --clear <context>`

## Levels
- `strict` (default) — writes only **ask**; destructive stays **denied**. Safest exception.
- `standard` — destructive also allowed **with confirmation**.
- `audit` — allow everything, log only. Use sparingly.

## Rules
- Pick the smallest exception that unblocks the task; prefer `--once` over time, and `strict` over looser levels.
- Never lease a production context to `audit` without explicit user consent.
- The lease auto-reverts to the cluster's normal posture when it expires or the command is used — no cleanup needed.

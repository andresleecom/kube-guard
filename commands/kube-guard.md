---
description: Show the active kube-guard policy and recent decisions, or explain what kube-guard would do with a specific kubectl/helm command.
---

Help the user understand and operate kube-guard.

## Steps

1. **Show the active policy.** Read the effective config, applied in this order (later wins): built-in defaults (`${CLAUDE_PLUGIN_ROOT}/config/kube-guard.default.json`) → user-global `~/.claude/kube-guard.config.json` → per-project `.claude/kube-guard.config.json` → `KUBE_GUARD_MODE` env var. Report:
   - Mode (`readonly` / `strict` / `standard` / `audit`)
   - Protected contexts and namespaces
   - `allowExec` / `allowSecretRead`

2. **Show recent decisions.** Prefer the rollup over eyeballing the log:
   ```
   node "${CLAUDE_PLUGIN_ROOT}/scripts/audit-query.mjs" --since 24h
   ```
   It prints counts by verdict/class, denies by context, and the top denied commands (entries are already redacted). Useful flags: `--deny-only`, `--context <glob>`, `--since 7d`, `--json`. If you just want the raw tail, read the last ~10 lines of `.claude/kube-guard/audit.jsonl` and highlight any `deny`.

3. **If the user named a command to check**, dry-run it through the classifier (no execution):
   ```
   node "${CLAUDE_PLUGIN_ROOT}/scripts/explain.mjs" "<their command>"
   ```
   and explain the verdict and why.

4. **If the user asks to `doctor` / validate the setup**, run the health check (read-only):
   ```
   node "${CLAUDE_PLUGIN_ROOT}/scripts/doctor.mjs"
   ```
   It prints the Node/kubectl status, the effective config and current context's resolved level, active leases, and **validation warnings** for typo'd keys or invalid levels (which would otherwise silently weaken the posture). Surface any `⚠` warnings to the user.

## Notes
- `allow` = runs normally · `ask` = you'll get a confirmation prompt · `deny` = blocked (kube-guard explains why to the agent).
- kube-guard gates `kubectl`/`helm` regardless of permission mode — even with `--dangerously-skip-permissions`, a `deny`/`ask` still applies.
- To change behavior, edit `.claude/kube-guard.config.json` (e.g. `{ "defaultMode": "standard" }`) or set `KUBE_GUARD_MODE`. (`mode` is still accepted as a legacy alias.)

---
description: Show the active kube-guard policy and recent decisions, or explain what kube-guard would do with a specific kubectl/helm command.
---

Help the user understand and operate kube-guard.

## Steps

1. **Show the active policy.** Read the effective config, applied in this order (later wins): built-in defaults (`${CLAUDE_PLUGIN_ROOT}/config/kube-guard.default.json`) → user-global `~/.claude/kube-guard.config.json` → per-project `.claude/kube-guard.config.json` → `KUBE_GUARD_MODE` env var. Report:
   - Mode (`strict` / `standard` / `audit`)
   - Protected contexts and namespaces
   - `allowExec` / `allowSecretRead`

2. **Show recent decisions.** If `.claude/kube-guard/audit.jsonl` exists, summarize the last ~10 entries (timestamp, verdict, class, command). Highlight any `deny`.

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
- To change behavior, edit `.claude/kube-guard.config.json` (e.g. `{ "mode": "standard" }`) or set `KUBE_GUARD_MODE`.

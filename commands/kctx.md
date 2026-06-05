---
description: Show your Kubernetes contexts with their kube-guard safety level, and switch clusters safely.
---

Help the user see and switch Kubernetes contexts without hitting the wrong cluster.

## Steps

1. **List contexts with their level:**
   ```
   node "${CLAUDE_PLUGIN_ROOT}/scripts/contexts.mjs"
   ```
   The current context is marked with `*`; each shows its posture (`readonly` / `strict` / `standard` / `audit`) and any active lease.

2. **To switch**, run:
   ```
   kubectl config use-context <target>
   ```
   kube-guard asks for confirmation when you switch **into** a guarded context (prod/staging) and allows dev/local freely — so you always know which cluster you just pointed at.

3. If the user needs to make a change on a `readonly` (production) cluster, don't fight the guard — point them to **`/klease`** to grant a short, auto-reverting exception.

## Rules
- Never switch to a production context silently — state the target and its level to the user.
- After switching, confirm the new current context before running anything that mutates.

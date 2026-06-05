---
name: k8s-safety
description: Safe habits when running kubectl/helm in a project guarded by kube-guard. Use whenever operating on a Kubernetes cluster — prefer reads and dry-runs, never run destructive or high-risk commands against protected/production contexts.
---

# Kubernetes safety habits

This project is protected by **kube-guard**: a PreToolUse hook classifies every `kubectl`/`helm` command and may `allow`, `ask`, or `deny` it. Work with the guard, not against it.

## Do
- **Read before you write.** Use `kubectl get`/`describe`/`logs` to understand state first.
- **Dry-run mutations.** Prefer `kubectl apply --dry-run=server -f ... ` and show the diff (`kubectl diff -f ...`) before a real apply.
- **Be explicit about scope.** Target a specific resource and namespace; avoid `--all`/`-A` with mutating verbs.
- **Confirm the context.** Check `kubectl config current-context` before any change; never assume.

## Don't
- Don't run destructive verbs (`delete`, `drain`, `taint`, `replace --force`, `helm uninstall/rollback`) against production — kube-guard will deny them.
- Don't use high-risk verbs (`exec`, `run`, `cp`, `port-forward`, `proxy`, `kubectl config view`) or dump secrets (`get secret -o yaml`) unless the user explicitly asks and approves.
- Don't try to bypass the guard (no `eval`, piping into `sh`, base64, or hiding kubectl inside subshells) — kube-guard fails closed on unverifiable commands.

## If a command is denied
Explain to the user what was blocked and why, and propose a safer alternative (a read, a dry-run, a non-prod context, or a PR-based change). Let the human make the call.

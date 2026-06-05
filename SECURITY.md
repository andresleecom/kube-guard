# Security

`kube-guard` is itself a security tool, so it is built to fail safe. This document
describes its threat model, guarantees, and limits.

## Reporting a vulnerability

Please open a private [GitHub security advisory](https://github.com/andresleecom/kube-guard/security/advisories/new)
rather than a public issue.

## What kube-guard is (and isn't)

- **It is** a guardrail that reduces the blast radius of an AI agent running
  `kubectl`/`helm` from a Claude Code session: it classifies commands and
  allows / asks / denies them, and logs every decision.
- **It is not** a sandbox or a replacement for Kubernetes RBAC. A determined
  operator with cluster credentials can still act outside the agent. Use
  least-privilege credentials as the primary control; kube-guard is defense in depth.

## Threat model

- **Trusted:** Claude Code and the hook input it provides (`tool_name`,
  `tool_input.command`, `cwd`), and the `kubectl` binary on PATH.
- **Untrusted / adversarial:** the command text the model proposes (it may
  hallucinate or be steered by prompt injection), command output (may contain
  secrets), and the project config.
- **Out of scope:** a fully compromised shell where the attacker sets arbitrary
  env vars and runs processes directly — at that point kube-guard is bypassed by
  not going through Claude Code at all.

## Guarantees & mitigations

| Risk | Mitigation |
|------|------------|
| Destructive op on production | Verbs are classified; mutations on protected contexts/namespaces are **denied**. Current context is resolved even when `--context` is omitted. |
| Evasion via chaining/quoting | The command is split shell-aware (`&& \|\| ; \|`, quotes) and kubectl/helm is detected **anywhere**, not just as the first token. |
| Evasion via obfuscation | `eval`, `sh -c`, `xargs`, `$(...)`, backticks, `\| sh`, and `base64` around kubectl/helm **fail closed** (deny in strict). Unknown verbs → ask. |
| Permission-mode bypass | A `deny`/`ask` from the hook applies even under `acceptEdits` / `--dangerously-skip-permissions`. |
| Secret exfiltration | `kubectl get secret -o yaml/json/jsonpath/...` and `kubectl config view` are **denied** by default; a PostToolUse hook also warns the model if output looks like secrets (it cannot rewrite output — so prevention is at PreToolUse). |
| Guard failure opens the door | Any internal error returns **ask**, never a silent allow. |
| Audit log leaking secrets | The audit log redacts high-confidence secret shapes and is gitignored by default. |
| Path traversal via env | Project dir is normalized with `path.resolve()`. |

## Residual risks & honest limits

- **Best-effort classification.** kubectl's surface is large; an unrecognized or
  newly added verb is treated conservatively (ask), but novel data-exfil paths
  via an allowed read are possible. Reads are intentionally permissive.
- **Secret redaction is heuristic**, not a guarantee. Treat any captured output
  as sensitive.
- **`audit` mode does not block** — it only records. Use `strict` to enforce.
- kube-guard governs commands routed through Claude Code's Bash tool; it does not
  govern other tools or out-of-band shells.

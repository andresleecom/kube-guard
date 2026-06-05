# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-06-05

### Added
- **User-global config** at `~/.claude/kube-guard.config.json`, applied across every
  project (so a production context can be protected everywhere, not per-folder).
  Precedence: plugin defaults → user-global → per-project `.claude/kube-guard.config.json`
  → `KUBE_GUARD_MODE` env var.

## [0.1.3] - 2026-06-05

### Changed
- "Wide blast radius" is now only flagged for mutating verbs. A label selector
  (`-l`) or `-o wide` on a read is harmless, so reads no longer get that label in
  the decision reason (clearer messages).

## [0.1.2] - 2026-06-05

### Fixed
- **Guard the PowerShell tool, not just Bash.** On Windows the agent runs
  `kubectl`/`helm` through the PowerShell tool, which the `Bash`-only matcher
  missed — so commands like `kubectl scale` bypassed the guard entirely. The hook
  now matches `Bash|PowerShell` and classifies any matched shell tool.
- Treat PowerShell eval (`iex` / `Invoke-Expression`, `pwsh -Command`) as an
  unverifiable construct (fail closed).

## [0.1.1] - 2026-06-05

### Fixed
- Removed redundant `hooks` / `commands` / `skills` fields from `plugin.json`.
  The standard `hooks/hooks.json`, `commands/`, and `skills/` locations are loaded
  automatically; declaring them again caused a "Duplicate hooks file" load error.

## [0.1.0] - 2026-06-04

### Added
- PreToolUse hook (`guard.mjs`) that classifies `kubectl`/`helm` commands by blast
  radius and returns `allow` / `ask` / `deny`.
- Pure, tested classifier (`classify.mjs`): shell-aware splitting, verb mapping
  (READ / WRITE / DESTRUCTIVE / HIGH_RISK), protected context & namespace guards,
  blast-radius flag detection, and fail-closed handling of obfuscation/unknown verbs.
- Secret-dump blocking (`get secret -o ...`, `config view`) and exec/run/cp/port-forward
  gating; `allowExec` / `allowSecretRead` opt-outs.
- Three modes: `strict` (default), `standard`, `audit` (observe-only).
- Private, gitignored audit log (`.claude/kube-guard/audit.jsonl`) with secrets redacted.
- PostToolUse hook (`notice.mjs`) that warns the model when output looks like secrets.
- `/kube-guard` command (policy + recent decisions) and `explain.mjs` (dry-run a command).
- `k8s-safety` skill teaching safe kubectl habits.
- Table-driven test suite (`node --test`), zero dependencies, cross-platform.

[0.1.4]: https://github.com/andresleecom/kube-guard/releases/tag/v0.1.4
[0.1.3]: https://github.com/andresleecom/kube-guard/releases/tag/v0.1.3
[0.1.2]: https://github.com/andresleecom/kube-guard/releases/tag/v0.1.2
[0.1.1]: https://github.com/andresleecom/kube-guard/releases/tag/v0.1.1
[0.1.0]: https://github.com/andresleecom/kube-guard/releases/tag/v0.1.0

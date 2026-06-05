# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.1]: https://github.com/andresleecom/kube-guard/releases/tag/v0.1.1
[0.1.0]: https://github.com/andresleecom/kube-guard/releases/tag/v0.1.0

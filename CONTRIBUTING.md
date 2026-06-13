# Contributing to kube-guard

Thanks for helping! kube-guard is deliberately small, **zero-dependency**, and
fails closed. A few house rules keep it that way.

## Tests first

The classifier (`scripts/classify.mjs`) is pure and exhaustively tested. When you
change behavior:

1. **Add a failing test first** in `test/` (mirror the closest existing case).
2. Make it pass.
3. Run the whole suite — it must stay green:

   ```sh
   node --test      # or: npm test
   ```

No test runner to install: it's the built-in `node:test` (Node ≥ 18).

## Keep it fail-closed and zero-dependency

- If you can't *prove* a command is safe, it must `ask` or `deny` — never silently
  `allow`. New gating logic should only ever **tighten** when unsure.
- Do not add runtime dependencies. Node stdlib only.

## Style

- ESM (`.mjs`), 2-space indent, semicolons, single quotes — match the surrounding code.
- **LF line endings** are enforced via `.gitattributes` (the hooks run `node` on
  these files cross-platform). An `.editorconfig` is provided; please keep it on.
- Run `git add --renormalize .` if your editor introduced CRLF.

## Scope of a PR

Keep PRs focused (one issue / one concern). CI runs `node --test` on
{ubuntu, macOS, windows} × Node {18, 20, 22}; all must pass.

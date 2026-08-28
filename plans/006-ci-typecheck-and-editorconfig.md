# Plan 006: Gate CI on typecheck and add an editorconfig

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 8ac83e3..HEAD -- .github/workflows`
> If `.github/workflows/ci.yml` changed since this plan was written, compare the
> "Current state" excerpt against the live file; on a mismatch, STOP.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: dx
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

For a security library, CI is the gate that keeps regressions out of published
packages. The current CI runs `build` and `test` but never runs the repo's own
`typecheck` script, and the repo has no editorconfig — so editors disagree on
indentation/whitespace, producing noisy diffs. Adding a typecheck gate makes
type errors (including in code paths the build might not surface identically)
fail CI explicitly, and an editorconfig locks the observed 2-space/LF style so
contributions stay consistent. Both are cheap and non-breaking.

A full linter (ESLint/Prettier) is intentionally **not** part of this plan — see
"Deferred" — because introducing one requires a repo-wide formatting pass that
would touch every file and exceeds this plan's LOW-risk bar.

## Current state

- `.github/workflows/ci.yml` — runs build + test only:

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm -r build
      - run: pnpm -r test
```

- Root `package.json` already defines `"typecheck": "pnpm -r typecheck"`. Most
  TS packages have a per-package `typecheck` script (`tsc -p tsconfig.json
  --noEmit`); packages without it (e.g. `@zeroness/agent`, which is `.mjs`) are
  simply skipped by `pnpm -r`.
- No `.editorconfig` exists at the repo root. Observed style across the codebase:
  2-space indentation, LF line endings, UTF-8, files end with a newline.

## Commands you will need

| Purpose         | Command             | Expected on success              |
|-----------------|---------------------|----------------------------------|
| Install         | `pnpm install`      | exit 0                           |
| Typecheck (all) | `pnpm -r typecheck` | exit 0, no type errors           |
| Build (all)     | `pnpm -r build`     | exit 0                           |
| Test (all)      | `pnpm -r test`      | all pass                         |

## Scope

**In scope**:
- `.github/workflows/ci.yml` (add a typecheck step)
- `.editorconfig` (create)

**Out of scope** (do NOT touch):
- `.github/workflows/release.yml` — the publish pipeline; unchanged.
- Any source file. This plan adds no code and no formatting changes.
- Introducing ESLint/Prettier/Biome (see Deferred).

## Git workflow

- Branch: `advisor/006-ci-typecheck-and-editorconfig`
- Commit message style — conventional commits (e.g.
  `ci: gate on typecheck; chore: add .editorconfig`).
- Do NOT push or open a PR unless instructed.

## Steps

### Step 0: Confirm the typecheck gate is green before adding it

Run `pnpm -r typecheck` locally.

**Verify**: exit 0, no type errors.

> If it fails, **STOP and report** the errors — do not add a red gate to CI and
> do not attempt to fix unrelated type errors in this plan. Pre-existing type
> errors are their own finding.

### Step 1: Add a typecheck step to CI

In `.github/workflows/ci.yml`, add a typecheck run **between** `pnpm install`
and `pnpm -r build`:

```yaml
      - run: pnpm install --frozen-lockfile
      - run: pnpm -r typecheck
      - run: pnpm -r build
      - run: pnpm -r test
```

**Verify**: the file is valid YAML — `node -e "require('node:fs').readFileSync('.github/workflows/ci.yml','utf8')"` exits 0, and visually confirm the four `- run:` steps are in this order.

### Step 2: Add `.editorconfig`

Create `.editorconfig` at the repo root:

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 2

[*.md]
trim_trailing_whitespace = false
```

**Verify**: `test -f .editorconfig` exits 0.

### Step 3: Confirm nothing else changed

**Verify**:
- `pnpm -r typecheck` → exit 0
- `pnpm -r build` → exit 0
- `pnpm -r test` → all pass
- `git status --porcelain` shows only `.github/workflows/ci.yml` and
  `.editorconfig`

## Test plan

- No new unit tests (this plan changes CI config and adds an editorconfig).
- The verification is the workflow ordering + the three green root commands.

## Done criteria

ALL must hold:

- [ ] `pnpm -r typecheck` exits 0
- [ ] `.github/workflows/ci.yml` runs `pnpm -r typecheck` before build/test
- [ ] `.editorconfig` exists at the repo root with the content above
- [ ] `git status --porcelain` shows only the two in-scope files
- [ ] `plans/README.md` status row for 006 updated

## STOP conditions

Stop and report if:

- `pnpm -r typecheck` fails at Step 0 (pre-existing type errors — surface them,
  don't fix them here or ship a red gate).
- `ci.yml` differs from the "Current state" excerpt (drift).

## Deferred (not in this plan, but recommended follow-up)

- A linter/formatter (ESLint flat config + `typescript-eslint`, or Biome) with a
  CI `lint` step. This is deliberately separate: enabling it requires a one-time
  repo-wide format/lint-fix pass that touches many files, which would bury this
  plan's tiny, safe diff. Track it as its own plan when the team wants it. A
  strong first rule set for this repo: `no-floating-promises` (there are several
  `void`-ed and fire-and-forget awaits in the Broker/egress worth verifying) and
  `no-unused-vars`.

## Maintenance notes

- If a new package adds TypeScript, give it a `typecheck` script so `pnpm -r
  typecheck` covers it; `.mjs`-only packages (like `@zeroness/agent`) are
  correctly skipped.
- Reviewer: confirm CI still passes on the PR (the new step is green) and that
  no source files were reformatted as a side effect of adding `.editorconfig`.

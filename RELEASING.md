# Releasing

Packages are published to npm by GitHub Actions (`.github/workflows/release.yml`).

## One-time setup

1. Create an npm **automation token** with publish rights to the `@zeroness`
   scope (npm → Access Tokens → Generate → Automation).
2. Add it to the GitHub repo as a secret named **`NPM_TOKEN`**
   (Settings → Secrets and variables → Actions → New repository secret).
3. Ensure the `@zeroness` org/scope exists on npm and your token can publish to it.

## Cutting a release

1. Bump versions (keep the workspace in lockstep, or use per-package bumps):
   ```bash
   pnpm -r exec npm version patch   # or minor / major
   git commit -am "release: vX.Y.Z" && git tag vX.Y.Z && git push --follow-tags
   ```
2. Publish a **GitHub Release** for the tag. That triggers the `Release`
   workflow, which builds, tests, and runs `pnpm -r publish` with npm provenance.

Published packages: `@zeroness/core`, `@zeroness/broker`, `@zeroness/egress`,
`@zeroness/agent`, `@zeroness/policy`, `@zeroness/gatekeeper`, `@zeroness/tls`,
and `create-zeroness`. The example app is `private` and is never published.

## CI

Every push/PR to `main` runs `.github/workflows/ci.yml` (install → build → test).

# Contributing

Thanks for helping improve CSRF Review Assistant. Keep changes focused and use synthetic requests, cookies, tokens, and accounts in all issues and tests.

## Local validation

Use Node.js 22+ and the pnpm version declared in `package.json`.

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test:coverage
pnpm lint
pnpm knip
pnpm audit --audit-level high
pnpm build
```

Every command must pass before a pull request is ready. Add focused positive and negative tests for analyzer behavior and regression tests for bug fixes. Do not weaken passive safety boundaries or coverage thresholds without documenting the tradeoff.

Pull requests should describe user impact, verification performed, database migrations, and any changes to network behavior, raw-message access, reports, or defaults. Include screenshots for visible UI changes when practical and update `CHANGELOG.md` for user-visible behavior.

By contributing, you agree that your work is licensed under the repository's MIT license.

# CSRF Review Assistant for Caido

Professional, passive-by-default triage for HTTP requests that deserve manual Cross-Site Request Forgery (CSRF), login CSRF, or Cross-Site WebSocket Hijacking (CSWSH) review.

> The plugin produces evidence-driven review candidates, not vulnerability verdicts. Use it only on systems you are authorized to test.

## Highlights

- Scans bounded Caido HTTP History and monitors new responses without sending traffic.
- Detects unsafe actions, sensitive GET requests, method overrides, login/OAuth flows, GraphQL mutations, persisted/batched GraphQL, and WebSocket upgrades.
- Identifies token signals in query, form, multipart, nested JSON, XML, and request headers.
- Separates browser-ambient Cookie and Basic/Digest authentication from normally non-ambient Bearer authentication.
- Records Origin/Referer, Fetch Metadata, CORS, request forgeability, observed SameSite attributes, and confidence without claiming server enforcement.
- Provides Dashboard, paginated Candidate triage, Reports, Settings, and Review Guide workspaces.
- Supports database-side search/filter/sort, current-page bulk triage, bounded reviewer notes, and project-isolated results.
- Adds a structured manual verification matrix for control, token-removal, invalid-token, cross-site, and real application-state outcomes.
- Creates inert Replay variants and constrained manual-submit HTML PoCs. The plugin never presses Send.
- Publishes a deduplicated, redacted Caido Finding only after explicit manual confirmation.
- Exports complete sanitized HTML, JSON, and spreadsheet-safe CSV reports from the backend.

## Safety and privacy

- Passive analysis makes no network request and has no telemetry, AI provider, or cloud dependency.
- Stored candidates contain normalized endpoint paths and evidence metadata—not raw HTTP, Cookie/Authorization values, or token values.
- Raw messages are read from the active Caido project only when the reviewer explicitly opens the source HTTP view.
- Replay variants are inert until the reviewer sends them. Offline PoCs require manual submission and are limited to representable GET or URL-encoded POST forms.
- Target Scope filtering is enabled by default. Disabling it requires an explicit warning confirmation.
- Oversized or opaque request bodies are classified as unknown rather than incorrectly treated as token-free.
- Reviewer notes are excluded from reports by default. Enabling them requires confirmation and an additional redaction pass.
- Saving Settings is non-destructive. Rebuild and clear are explicit, confirmed operations; review states, notes, and verification matrices survive a rebuild.

## Installation

1. Download `plugin_package.zip` and `SHA256SUMS` from the latest GitHub Release.
2. Verify the package: `sha256sum --check SHA256SUMS`.
3. In Caido, open **Settings → Plugins**, install the ZIP, and enable **CSRF Review Assistant**.
4. Put authorized targets in Scope and open the plugin from the sidebar.

You can also right-click a saved History request or response and choose **Analyze with CSRF Review Assistant**.

## Recommended workflow

1. Start with **P1 urgent** candidates and understand the request's possible side effects.
2. Review authentication, token, Origin, Fetch Metadata, CORS, SameSite, and browser-forgeability evidence.
3. Create inert Replay variants and inspect every mutation before sending anything.
4. Use an authorized test account to compare control, token-removal, invalid-token, and cross-site behavior.
5. Record response acceptance separately from actual application state in the verification matrix.
6. Save the review decision and publish a Finding only after manual confirmation.

Status codes and similar response bodies do not confirm CSRF. Verify the actual server-side account or application state.

## Priority model

- **P1:** likely ambient authentication, sensitive/browser-forgeable action, and no identified token or strong observed cookie barrier.
- **P2:** missing, weak, or unknown token evidence with a browser/protocol barrier that still requires testing.
- **P3:** authentication or state-change evidence is uncertain and lower-confidence.
- **Protection observed:** a token-like signal exists, but passive inspection cannot prove server validation.

`Origin`, `Referer`, Fetch Metadata, CORS, and SameSite observations are evidence only.

## Development

Requirements:

- Node.js 22 or newer
- pnpm 11.13.0
- A Caido version compatible with plugin SDK 0.57.1

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test:coverage
pnpm lint
pnpm knip
pnpm audit --audit-level high
pnpm build
```

The installable package is created at `dist/plugin_package.zip`. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and [GUIDE_AR.md](GUIDE_AR.md) for the Arabic operator guide.

## Limitations

- Passive evidence cannot establish whether a server accepts a forged request.
- Custom session-cookie, token, or action names may need configuration.
- Opaque, protobuf, oversized, and gRPC bodies are not guessed.
- WebSocket review covers the upgrade handshake, not application messages.
- SameSite evidence is learned from observed responses and is not a full browser cookie-jar simulation.

## License

[MIT](LICENSE) © 2026 rust-memo

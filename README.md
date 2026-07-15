# CSRF Review Assistant for Caido

CSRF Review Assistant is a passive-by-default, evidence-driven Caido plugin for finding HTTP requests that deserve manual CSRF or Cross-Site WebSocket Hijacking (CSWSH) review.

It reports **review candidates, not confirmed vulnerabilities**. The analyzer considers browser-ambient authentication, action sensitivity, request shape, GraphQL operations, observed token signals, Origin/Referer, Fetch Metadata, credentialed CORS, SameSite observations, and WebSocket upgrade evidence.

## Features

- Scans recent Caido HTTP History and monitors new responses without sending traffic.
- Uses Target Scope only by default and supports Conservative, Balanced, and Aggressive policies.
- Detects sensitive unsafe methods, state-changing GET requests, method overrides, login/OAuth workflows, GraphQL mutations, persisted/batched GraphQL, and WebSocket upgrade handshakes.
- Finds CSRF tokens in query, form, multipart, JSON, XML, and request-header locations.
- Learns host-scoped token names from hidden HTML inputs and meta fields.
- Separates Cookie and Basic/Digest authentication from normally non-ambient Bearer authentication.
- Records Origin/Referer relationships, Fetch Metadata, CORS evidence, request forgeability, and observed SameSite attributes without claiming server-side enforcement.
- Groups candidates into P1, P2, P3, and Protection observed priorities.
- Stores review status and bounded reviewer notes per Caido project.
- Creates control, token-removal, empty/invalid-token, cross-site-header, and compatible `text/plain` variants in Replay without sending them.
- Generates a local manual-submit HTML PoC only for GET and URL-encoded POST requests that HTML forms can represent without changing method or parameter location.
- Exports redacted JSON, CSV, or offline HTML reports. Reviewer notes are excluded by default.
- Publishes a redacted Caido Finding only after the reviewer explicitly marks a candidate Confirmed.
- Has no telemetry, cloud dependency, or automatic active verification.

## Install

1. Download `plugin_package.zip` from the latest GitHub Release.
2. In Caido, open **Settings > Plugins**.
3. Install the downloaded package and enable **CSRF Review Assistant**.
4. Put authorized targets in Scope, browse normally, and open the plugin from the sidebar.

You can also right-click a saved History request or response and choose **Analyze with CSRF Review Assistant**.

## Recommended workflow

1. Begin with **P1 urgent review** candidates.
2. Read the authentication, token, Origin, Fetch Metadata, CORS, SameSite, and browser-forgeability evidence.
3. Create Replay variants. The plugin creates sessions only; it does not press Send.
4. Inspect each request and understand possible password, payment, permission, deletion, or other state-changing effects.
5. Use authorized test accounts and compare control, missing/invalid token, and cross-site evidence.
6. Verify the real server-side state. Status codes and similar response bodies do not confirm CSRF.
7. Save the review status and publish a Finding only after manual confirmation.

## Priority model

- **P1:** likely browser-ambient authentication, sensitive/browser-forgeable action, and no identified token or strong observed cookie barrier.
- **P2:** a missing or weak token with a method, Content-Type, SameSite attribute, or another uncertain browser barrier.
- **P3:** authentication or state-change evidence is uncertain. This is normally hidden by the Conservative policy.
- **Protection observed:** a token-like signal is present, but passive inspection cannot prove server validation.

`Origin`, `Referer`, Fetch Metadata, CORS headers, or SameSite observations are evidence only. Their presence does not prove correct enforcement.

## Build and verify

Node.js 20 or later and pnpm 9 are required.

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm knip
pnpm build
```

The installable package is created at:

```text
dist/plugin_package.zip
```

## Privacy and safety

Passive analysis makes no network request. Replay variants are inert until the user presses Send. The generated PoC is local and requires manual submission.

Candidate storage and reports contain evidence metadata rather than raw HTTP messages, Cookie/Authorization values, or token values. The raw-message view reads the original request from the active Caido project only when requested. Notes are excluded from reports unless explicitly enabled.

## Limitations

- Passive evidence cannot establish whether a server accepts a forged request.
- Custom session-cookie or token names may need to be added in Settings.
- Opaque, protobuf, and gRPC bodies are not parsed heuristically.
- Offline PoCs are intentionally limited to GET and URL-encoded POST forms.
- WebSocket support reviews the upgrade handshake; it does not replay application messages.
- Cookie SameSite evidence is learned from responses observed during the current plugin session and is not a complete browser cookie-jar simulation.

See [GUIDE_AR.md](GUIDE_AR.md) for the Arabic usage guide.

## License

MIT. See [LICENSE](LICENSE).

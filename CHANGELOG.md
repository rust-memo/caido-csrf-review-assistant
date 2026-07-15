# Changelog

All notable changes to this project are documented here.

## 1.1.1 — 2026-07-15

### Added

- Added visible plugin version information to the application header.
- Added `schemaVersion` and plugin `version` metadata to JSON report exports.

### Changed

- Updated the Caido release action from 1.9.0 to 1.20.0.
- Added a release preflight that refuses to overwrite an existing version tag.
- Kept Dependabot development updates within the supported Node 22, ESLint 9, and TypeScript 6 major versions.

### Fixed

- Fixed JSON and HTML reports continuing to identify themselves as version 1.1.0 after a plugin upgrade.
- Report generator metadata now derives from the backend package version instead of a duplicated hard-coded value.
- Prevented incompatible grouped major dependency updates from breaking the validation workflow.

## 1.1.0 — 2026-07-15

### Added

- Professional responsive UI with Dashboard, Candidate triage, Reports, Settings, and Review Guide workspaces.
- Database-side candidate search, priority/status/host filters, sorting, pagination, and current-page bulk review.
- Structured manual verification matrix covering control, missing-token, invalid-token, cross-site, and application-state outcomes.
- Project summaries, recent priority signals, top affected hosts, targeted Request ID analysis, and triage progress.
- Backend-generated sanitized HTML, JSON, and spreadsheet-safe CSV reports.
- Store migration/integration, report, message, utility, and component tests with enforced coverage thresholds.

### Changed

- Upgraded to Caido SDK 0.57.1, Vue 3.5, TypeScript 6, Vitest 4, Node.js 22, and pnpm 11.
- Settings saves and project changes are non-destructive; rebuild and clear are now separate confirmed actions.
- Candidate events send small invalidation messages rather than full project snapshots.
- Background scans use bounded, generation-aware workers and drain old work before a rebuild or clear.
- Hidden token learning now requires token-like names, reducing false protection signals.
- Published Findings include structured verification state while excluding notes and raw evidence.

### Fixed

- Fixed stale scan workers writing after cancellation, settings changes, or project switches.
- Fixed project changes and automatic History scans deleting saved candidate sets.
- Fixed candidate-cap races between concurrent workers and full-dataset UI transfers.
- Fixed oversized bodies being classified as token-free instead of unknown.
- Fixed nested XML token mutation and URL credentials being copied into offline PoCs.
- Fixed dropped queue items being marked processed before they were accepted.

## 1.0.0 — 2026-07-15

- Initial Caido release of the passive CSRF and CSWSH review workflow.
- Added bounded HTTP History scanning and monitoring of new responses.
- Added evidence-driven P1/P2/P3/Protection-observed analysis.
- Added query, form, multipart, JSON, XML, GraphQL, and WebSocket handshake coverage.
- Added host-scoped SameSite and hidden-token learning.
- Added persistent candidate review states, notes, filters, and settings.
- Added inert Replay variants and a constrained manual-submit offline PoC.
- Added redacted JSON, CSV, and HTML exports and confirmed-only Caido Finding publication.

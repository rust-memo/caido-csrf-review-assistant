# Security policy

## Supported versions

Only the latest minor release receives security fixes.

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | No |

## Reporting a vulnerability

Do not open a public issue for a problem that could expose credentials, local project data, or authorized target information. Report it privately through GitHub Security Advisories for this repository.

Include the affected version, minimal reproduction steps, impact, and any suggested mitigation. Remove real credentials, session tokens, customer traffic, and information from systems you do not own.

## Security model

Analysis is passive and local. Replay variants are created unsent, generated PoCs require manual submission, and only manually confirmed candidates can be published as Findings. Reports and stored candidates exclude raw credential and token values by design.

# ClaudePass is closed source, freemium, with a paid plan from v1

> **Superseded 2026-09-12 by [ADR-0011](0011-free-and-open-source.md):** ClaudePass is fully free and open source under the MIT license. Kept for history; do not follow this decision.

We considered open-core (open local tool, paid hosted service) for the trust argument: the tool reads every prompt and touches every secret, and auditability answers the "does it phone home" question. We chose fully closed source with a paid plan ($9.99/month) from the first release, following the 1Password and LastPass model rather than Bitwarden's.

The free tier is limited to 3 Secrets; the paid tier is unlimited. Gating is by a license key checked against a small hosted endpoint, which is the only server-side component in v1. Freemium-by-limits was chosen over a trial-only model (no free on-ramp) and over freemium-by-service (would pull sync and relay into v1).

Consequence: trust must be earned through documentation of exactly what the hooks and Broker do, a clear no-telemetry stance beyond the license check, and third-party audits, since source is not available to inspect.

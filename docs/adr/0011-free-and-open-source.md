# ClaudePass is free and open source under the MIT license

On 2026-09-12 the owner decided that ClaudePass becomes fully free and open source under the MIT license, with the explicit goal of becoming the standard way AI coding agents use Secrets. This supersedes [ADR-0006](0006-closed-source-paid.md) (closed source, freemium with 3 free Secrets, $9.99/month) in full. Monetization is deferred and undecided: nothing here rules out a future paid offering (support, hosting, a sync service), but that needs its own ADR rather than a revival of ADR-0006.

The reasoning is the one ADR-0006 already conceded: a tool that reads every prompt and touches every Secret is trusted only if it can be audited. ADR-0006 tried to earn that trust through documentation and third-party audits; a public repository answers "what does it phone home" directly, and the leak tests in `internal/e2e` become claims anyone can run. An industry standard also has to be something every agent vendor, CI system and developer can adopt without a purchase decision, and MIT is the license that removes every such obstacle.

Everything that existed only to gate or sell a license is removed rather than left dormant: the Stripe-backed license service (`services/license`), the CLI's offline Ed25519 license verification and `cpass license` command (`internal/license`), the free-tier limit of 3 Secrets, the pricing page, the checkout flow, the account/reissue page, and the deploy pieces that only ran the license service. `stripe/live` stays as the canonical example Handle throughout the docs and tests, and the Intercept detector keeps its Stripe key patterns: that is Secret detection, unrelated to Stripe as a payment provider.

## Consequences

- No license service, no Stripe, no billing, no accounts. The `cpass` binary still makes no network calls; the only networked component left is `install.sh`, which fetches a release archive.
- No Secret cap. A `license` file left under `$CPASS_HOME` by an earlier release is ignored.
- Trust comes from the source. `docs/SECURITY.md` and `docs/THREATS.md` remain the readable reference of what each component does and touches, now checkable against the code.
- The nav gains a `GITHUB` link and drops `PRICING`, so the shipped nav is `INSTALL / DOCS / SECURITY / GITHUB`. This amends [ADR-0010](0010-nav-footer-no-github-dark-footer.md), whose reasoning for omitting a GITHUB link depended on the source being closed; its footer-stays-Dark decision stands.
- Vulnerability reports go through GitHub's private vulnerability reporting (see `.github/SECURITY.md`); product support moves to GitHub issues. The site's error page and legal pages point there instead of at a mailbox.
- Contributions are welcome under the MIT license. `CONTRIBUTING.md` sets the bar: the leak test suite must stay green, and vocabulary follows `CONTEXT.md`.

# ClaudePass license service

The one server-side component in ClaudePass's paid plan (ADR-0006, CLA-15,
docs/PRD.md "Licensing and distribution"): it runs Stripe Checkout for the
$9.99/month plan, listens for Stripe's webhooks, and issues or refuses the
Ed25519-signed license tokens the `cpass` binary verifies completely
offline (`internal/license`, CLA-14). It never revokes an issued token —
tokens simply expire (see "Why no revocation list" below) — and it never
logs a token anywhere.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/checkout` | Creates a Stripe Checkout Session for the $9.99/month price and redirects the browser to it. Optional `email` form/query value prefills the Checkout form. |
| `POST` | `/webhook` | Stripe webhook receiver. Handles `checkout.session.completed` (issue the first token), `customer.subscription.updated` (refresh the known period end/status), `customer.subscription.deleted` (mark canceled — the next `/reissue` for that customer is refused). Every other event type is acknowledged (200) and ignored. |
| `GET` | `/license?session_id=...` | Stripe Checkout's `success_url` target. Shows the issued token **once**, as the exact `cpass license activate <token>` command to run, then clears it from the database — a reload, or anyone else who gets the URL, sees only an "already shown" page. |
| `POST` | `/reissue` | Form field `email`. For an active subscriber, mints a fresh token and **emails** it (never returns it in the HTTP response) along with a Stripe customer portal link. Refuses with `402 Payment Required` if the subscription is canceled, `404` if the email is unknown. |
| `GET` | `/healthz` | Liveness probe. |

Nothing outside these five routes is served by this process — point a
reverse proxy or your marketing site at `/`, `/checkout/canceled`, and
anything else.

## Design decisions worth knowing before you touch this

- **No revocation list.** Per ADR-0006/CLA-15: a token's `exp` is the
  subscription's current period end plus a 3-day grace window
  (`server.GracePeriod`). Canceling a subscription does not invalidate a
  token already on someone's machine — it just stops new ones from being
  issued for that customer. This is deliberate: `cpass` verifies tokens
  completely offline, so there is nothing to check a revocation list
  against without reintroducing a network call to every command.
- **`checkout.session.completed` issues with a default period, not the
  real one.** Stripe does not expand `subscription` on that event by
  default, so the exact period end usually isn't known yet at checkout
  time. The first token uses a one-month default (`+3` days grace)
  instead. The `customer.subscription.updated` event Stripe sends moments
  later (a side effect of the same checkout) refreshes the stored period
  end for every *subsequent* token — reissued or renewed.
- **`/reissue` never returns a token over HTTP.** It emails it. This is
  the plain reading of the CLA-15 spec ("`POST /reissue` emails a fresh
  token") and it also means a token can never end up in a browser history
  entry or a reverse-proxy access log for this endpoint. The email also
  carries a Stripe customer portal link so a subscriber can manage or
  resume billing from the same message.
- **`GET /license` tolerates the checkout-redirect/webhook race.** Nothing
  guarantees Stripe's webhook lands before the browser's own redirect to
  `success_url`. The handler polls the store briefly (~3s, configurable
  via `server.Deps.TokenPollInterval`/`TokenPollAttempts`) before giving
  up with a 404 telling the visitor to reload or use `/reissue`.
- **SQLite via `modernc.org/sqlite`, not Cloudflare D1.** CLA-15 asks to
  "pick one and record it": this service deploys as a single Fly.io
  machine with a persistent volume (see Deploy below), not a Cloudflare
  Worker, so a local SQLite file with a pure-Go driver (no CGo, matching
  the rest of this repo's build story) is the simpler choice. Revisit this
  if the service is ever redeployed to Workers.
- **`issued_tokens` is the customer→jti record CLA-15 asks for.** It is
  separate from `checkout_tokens.token` (the full signed token, cleared
  the moment `GET /license` shows it): a `jti` is a random correlation id,
  not a secret, so keeping `customer_id, jti, issued_at, exp` around after
  the token itself is cleared is safe and is what lets a support question
  ("which token did this customer end up activating?") be answered without
  a revocation list.
- **The service never logs a token.** `internal/server`'s request logging
  middleware logs only method/path/status; every handler logs errors and
  ids, never a token or license payload. `services/license/e2e_test.go`
  and `internal/server/webhook_test.go` both assert the issued token never
  appears in the captured log output, the same "assert it's absent from
  everything an observer would see" discipline `internal/e2e`'s leak
  tests apply to the CLI.

## Environment variables

All of these are read once, at startup, by `internal/config.Load()` —
nothing in a handler calls `os.Getenv` directly.

| Variable | Required | Purpose |
|---|---|---|
| `LICENSE_SIGNING_KEY` | **yes** | Base64 (standard encoding) of the 64-byte Ed25519 **private** key that signs tokens. **This must be the exact private key whose public half is already embedded in `internal/license/publickey.go` (`PublicKeyBase64`)** — the one `go run ./internal/license/cmd/keygen` produced for CLA-14 and that was handed to the repo owner directly (never committed). Signing with any other key produces tokens `cpass` will refuse. |
| `LICENSE_STRIPE_SECRET_KEY` | **yes** | Stripe secret API key (`sk_test_...` for Stripe test mode, `sk_live_...` in production). |
| `LICENSE_STRIPE_PRICE_ID` | **yes** | The recurring Stripe Price id for the $9.99/month plan (`price_...`). Create it once in the Stripe Dashboard (Product: "ClaudePass Pro", $9.99/month, recurring). |
| `LICENSE_STRIPE_WEBHOOK_SECRET` | **yes** | Signing secret for this service's webhook endpoint (`whsec_...`), from the Stripe Dashboard (or `stripe listen` while developing). |
| `LICENSE_BASE_URL` | **yes** | This service's own public URL, no trailing slash (e.g. `https://license.claudepass.dev`). Used to build Checkout's `success_url`/`cancel_url` and the billing portal's `return_url`. |
| `LICENSE_DB_PATH` | no (default `license.db`) | Path to the SQLite file. On Fly.io this should point at the mounted volume, e.g. `/data/license.db`. |
| `LICENSE_ADDR` | no (default `:8080`) | Listen address. |
| `LICENSE_SMTP_HOST` | no | SMTP host for `/reissue`'s email. Leave unset (with `LICENSE_SMTP_FROM`) and the service still runs — `/reissue` just refuses every request with a clear error until both are set. |
| `LICENSE_SMTP_PORT` | no (default `587`) | SMTP port. `465` dials with implicit TLS; anything else uses `net/smtp.SendMail` (STARTTLS handled by the server, standard for 587). |
| `LICENSE_SMTP_USERNAME` | no | SMTP auth username. |
| `LICENSE_SMTP_PASSWORD` | no | SMTP auth password. |
| `LICENSE_SMTP_FROM` | no | `From:` address for reissue emails. |

## Local development against Stripe test mode

```sh
go run ./internal/license/cmd/keygen        # once, if you need a *test* keypair —
                                             # do NOT use this to replace the real
                                             # production key described above
export LICENSE_SIGNING_KEY=<the printed private key, base64>
export LICENSE_STRIPE_SECRET_KEY=sk_test_...
export LICENSE_STRIPE_PRICE_ID=price_...
export LICENSE_BASE_URL=http://localhost:8080

stripe listen --forward-to localhost:8080/webhook
# stripe listen prints a webhook signing secret; export it:
export LICENSE_STRIPE_WEBHOOK_SECRET=whsec_...

go run ./services/license
```

Then `stripe trigger checkout.session.completed` or run the real Checkout
flow at `POST /checkout` with a Stripe test card.

## Tests

`go test ./services/...` (no live Stripe, ever — CLA-15's constraint):

- `internal/store`: table-driven unit tests against a real temp SQLite
  file (idempotent event marking, one-time token retrieval, upsert
  semantics).
- `internal/webhookfixture`: renders the recorded fixture payloads under
  `internal/webhookfixture/testdata/*.json` (shaped like real
  `stripe listen`/`stripe trigger` deliveries) and signs them with
  stripe-go's own exported `ComputeSignature` — the same HMAC scheme
  `stripe.ConstructEvent` verifies, so a test never hand-rolls signature
  logic that could drift from what Stripe actually sends.
- `internal/server`: every handler against httptest, with fake
  `CheckoutCreator`/`PortalCreator`/`Mailer` so nothing touches the
  network. Includes the concurrent "show the token exactly once" race,
  webhook idempotency on redelivery, and the "subscription deleted → next
  reissue refused" acceptance path.
- `services/license/e2e_test.go` (repo root's quality bar runs this too):
  builds the real `cpass` binary (`-tags e2e`, the same tag
  `internal/e2e` uses) and a real release build, starts this service as a
  real listening HTTP server, delivers a signed fixture to `/webhook`,
  reads the token off `GET /license`, and runs
  `cpass license activate <token>` as a subprocess — the literal CLA-15
  acceptance bullet. A companion test proves a release build refuses a
  token signed with anything but the production key, and another repeats
  the cancellation-refuses-reissue path over a real socket.

## Deploy (Fly.io)

Fly.io was chosen per CLA-15/ADR-0006's instruction to "choose based on
what the owner has credentials for, else Fly" — no deploy credentials for
either target were available to this Agent, so this is the documented
default, not a confirmed choice. If the owner has Cloudflare credentials
instead, redeploying as a Worker means swapping `internal/store` for a D1
client behind the same `*store.Store`-shaped interface `internal/server`
already depends on through `Deps.Store`; nothing else in this service
assumes a filesystem.

Run every `fly` command from the **repository root**, not from
`services/license/`: the Dockerfile needs the whole Go module as its build
context (this service imports `claudepass/internal/license`), so
`fly.toml` and the Dockerfile are pointed at explicitly instead of relying
on flyctl's directory-implied defaults.

```sh
# Once, to create the app (skip if it already exists):
fly apps create claudepass-license
fly volumes create license_data --size 1 --region <region> --app claudepass-license

fly secrets set --app claudepass-license \
  LICENSE_SIGNING_KEY=<base64 production private key> \
  LICENSE_STRIPE_SECRET_KEY=sk_live_... \
  LICENSE_STRIPE_PRICE_ID=price_... \
  LICENSE_STRIPE_WEBHOOK_SECRET=whsec_... \
  LICENSE_BASE_URL=https://claudepass-license.fly.dev \
  LICENSE_SMTP_HOST=... LICENSE_SMTP_PORT=587 \
  LICENSE_SMTP_USERNAME=... LICENSE_SMTP_PASSWORD=... \
  LICENSE_SMTP_FROM="ClaudePass <license@claudepass.dev>"

fly deploy --config services/license/fly.toml --dockerfile services/license/Dockerfile
```

Then, in the Stripe Dashboard: create the $9.99/month Price if it doesn't
exist yet, add a webhook endpoint pointed at
`https://<your-app>.fly.dev/webhook` subscribed to
`checkout.session.completed`, `customer.subscription.updated`, and
`customer.subscription.deleted`, and copy its signing secret into
`LICENSE_STRIPE_WEBHOOK_SECRET` above.

`Dockerfile` builds a static, CGo-free binary (`modernc.org/sqlite` needs
none) on `FROM scratch`; `fly.toml` mounts the volume at `/data` and sets
`LICENSE_DB_PATH=/data/license.db`.

## NEEDS-HUMAN

Nothing above can be completed by this Agent — every item is a credential,
an account, or a live-billing decision only the owner can supply:

1. **`LICENSE_SIGNING_KEY`** — the production Ed25519 private key. It was
   generated once during CLA-14 and sent to the owner directly as a file
   attachment titled "CLA-14: ClaudePass license signing keypair"; it is
   not and must never be in this repository. Put its base64 value into
   this service's `LICENSE_SIGNING_KEY` secret (e.g. `fly secrets set`),
   then delete the file. A mismatched key here signs tokens `cpass` will
   silently refuse — there is no other symptom to debug by.
2. **A Stripe account** with: the $9.99/month recurring Price created,
   an API secret key (`LICENSE_STRIPE_SECRET_KEY`), and a webhook
   endpoint pointed at this service's `/webhook` once it has a public URL
   (`LICENSE_STRIPE_WEBHOOK_SECRET` comes from that endpoint).
3. **A Fly.io account** (or Cloudflare, if that's what's actually
   available — see the Deploy section) to run `fly launch`/`fly volumes
   create`/`fly deploy` and hold the secrets above.
4. **SMTP credentials** (`LICENSE_SMTP_*`) for `/reissue` to actually send
   mail. Until these are set, every other endpoint works — `/reissue`
   alone refuses with a clear "SMTP is not configured" error instead of
   silently discarding a token nobody could receive.

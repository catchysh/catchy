# Catchy

[![CI](https://github.com/catchysh/catchy/actions/workflows/main.yaml/badge.svg)](https://github.com/catchysh/catchy/actions/workflows/main.yaml)
[![Release](https://img.shields.io/github/v/release/catchysh/catchy)](https://github.com/catchysh/catchy/releases)
[![License](https://img.shields.io/github/license/catchysh/catchy)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/catchysh/catchy)](go.mod)

Self-hosted hook catcher. Point a webhook, a contact form, or a script at
Catchy: every request is stored as received and shows up in your dashboard
and API, ready for something else to process.

- **One URL** — catch hooks with `POST /`, no setup and no keys needed
- **Channels** — group hooks with `?channel=stripe`; channels appear on first use
- **Raw capture** — method, query, headers, and the exact body (e.g. for signature checks), plus a decoded payload for JSON and forms
- **Process outside** — consumers list pending hooks, handle them, and mark them `processed`, `failed`, or `discarded`
- **Destinations** — send hooks over HTTP: email through Resend, Slack, Discord, or forward to any URL, with retries
- **Guards** — honeypot, captchas (Cloudflare Turnstile, Google reCAPTCHA), webhook signatures (GitHub, Shopify, Stripe, HMAC), and tokens, attached per channel
- **Forms too** — open CORS; your page shows its own thank-you
- **API** — REST, gRPC, gRPC-Web, and Connect on one endpoint

## Install

```bash
brew install catchysh/tap/catchy
```

Or download a binary from [Releases](https://github.com/catchysh/catchy/releases).

## Quick start

```bash
export SESSION_SECRET="your-secret-here"
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"

just run
# or: go run ./cmd/catchy serve --migrate
```

Visit `http://localhost:8080` to sign in, see hooks, and generate API keys.
Uses SQLite by default, with PostgreSQL available when you need a separate database.

## Catching hooks

Send anything to `POST /`. Add `?channel=name` to group hooks; without it
they go to the `default` channel. Channels are created by their first hook,
unless `AUTO_CREATE_CHANNELS=false`. Channel names are up to 64 lowercase letters
and digits, separated by single `_` or `-` (`stripe`, `contact-form`).

```bash
curl "https://catchy.example.com/?channel=signup" \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com"}'
# {"id":"01k6z3x2b9e8v4m7q5w1t0r2y3"}
```

The dashboard lists hooks a line each, newest first, filtered by channel and
status. Each hook has its own page at its ID —
`https://catchy.example.com/01k6z3x2b9e8v4m7q5w1t0r2y3` — with everything it
carried, its deliveries, and its actions.

Every hook is stored as received: method, query string, headers (except
`Cookie`), content type, and the exact body, up to 1 MiB. Any content type is
accepted. When the body is a JSON object or a form, it's also decoded into a
`payload`: form fields become strings, or arrays of strings when repeated, and
multipart file parts are skipped. Empty form fields whose names start with
`_` (such as honeypot fields) are left out of the payload, while `_` fields
with a value, like `_subject`, are kept; JSON keys are always kept as sent.

A channel can be **paused** from the dashboard or the API. While paused it
refuses new hooks with `503 Service Unavailable` and a `Retry-After` header;
webhook providers treat that as "retry later", so nothing sent meanwhile is
lost once you resume.

Responses are always JSON: `{"id":"…"}` with `200`, or `{"error":"…"}`
with a 4xx or 5xx status. CORS is open, so pages on any origin can send hooks with
`fetch`.

### Contact form

Submit the form with `fetch` and show your own message; Catchy never takes
the visitor away from your page.

```html
<form id="contact">
  <input type="text" name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>
  <!-- honeypot: keep it hidden and empty -->
  <input type="text" name="_gotcha" style="display:none" tabindex="-1" autocomplete="off">
  <button type="submit">Send</button>
</form>
<script>
  contact.addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await fetch("https://catchy.example.com/?channel=contact", {
      method: "POST",
      body: new URLSearchParams(new FormData(contact)),
    });
    contact.innerHTML = res.ok
      ? "Thanks! We'll be in touch."
      : "Something went wrong, please try again.";
  });
</script>
```

With a honeypot guard on the channel, a submission that fills the hidden
field (`_gotcha` by default) gets a normal success response but isn't stored,
so bots posting the form directly are dropped.

## Protecting channels

**Guards** are checks a hook must pass before it's stored. Create them on the
dashboard's **Guards** page, then attach them to channels in each channel's
panel; a hook must pass every guard on its channel.

| Type | Checks | Secret |
|---|---|---|
| `honeypot` | A hidden form field (`_gotcha` by default; set your own, e.g. `_website`) is empty; bots that fill it get a normal response and are dropped | — |
| `captcha` | A valid captcha token from the form's widget, with scheme `turnstile` or `recaptcha` (below) | the provider's secret key, e.g. `TURNSTILE_SECRET_KEY` |
| `signature` | A webhook signature over the raw body, with scheme `hmac` or `stripe` (below) | the signing secret, e.g. `STRIPE_WEBHOOK_SECRET` |
| `token` | A header holds the secret itself, after an optional prefix | the token, e.g. `API_TOKEN` |

**`hmac` signatures** are configurable — header, algorithm (`sha256`, `sha1`,
`sha512`), encoding (`hex`, `base64`), and a prefix before the value — so one
scheme covers most providers. The dashboard has presets:

| Preset | Header | Format |
|---|---|---|
| GitHub | `X-Hub-Signature-256` | `sha256=` + hex HMAC-SHA256 |
| Shopify | `X-Shopify-Hmac-Sha256` | base64 HMAC-SHA256 |
| Custom HMAC | `X-Catchy-Signature` | `sha256=` + hex HMAC-SHA256 |

**`captcha` guards** verify the token with the provider:

| Scheme | Token from | Notes |
|---|---|---|
| `turnstile` | [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/): the `cf-turnstile-response` form field, or a `CF-Turnstile-Response` header | |
| `recaptcha` | [Google reCAPTCHA](https://developers.google.com/recaptcha): the `g-recaptcha-response` form field, or an `X-Recaptcha-Token` header | v2 and v3; v3 tokens scoring below the guard's minimum (default 0.5) fail |

**`stripe` signatures** check `Stripe-Signature` (`t=…,v1=…`, HMAC of
`<t>.<body>`) and refuse timestamps more than 5 minutes off.

**`token` guards** have a header and prefix too; presets are *Bearer token*
(`Authorization: Bearer <token>`) and *GitLab* (`X-Gitlab-Token: <token>`).

Guards have a name, so you can have several of a type (`stripe-prod`,
`stripe-test`, a Turnstile guard per site) and reuse one across channels.
A guard's secret is picked from the [secrets](#secrets) that are set:
`STRIPE_WEBHOOK_SECRET` is the `CATCHY_SECRET_STRIPE_WEBHOOK_SECRET`
environment variable. Presets pick one, even before it's set. To rotate it,
change the variable and restart.

Every instance starts with a ready-made `honeypot` guard. Channels start
without guards — including ones created by their first hook — so attach the
ones each channel needs. To lock a channel down before its first hook, create
it on the **Channels** tab and pick its guards there.

By default a hook to a channel that doesn't exist yet creates it. Set
`AUTO_CREATE_CHANNELS=false` to turn that off: hooks to unknown channels then
get `404`, and only channels created in the dashboard — with the guards you
chose — accept hooks.

A hook that fails a guard gets `403` and isn't stored (a filled honeypot is
the exception: dropped quietly). If a captcha provider can't be reached, the hook gets
`502` so the sender can retry. A guard can't be deleted while it's attached to
a channel.

Signing a hook for the *Custom HMAC* preset:

```bash
BODY='{"event":"ping"}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')
curl "https://catchy.example.com/?channel=jobs" \
  -H "Content-Type: application/json" -H "X-Catchy-Signature: sha256=$SIG" -d "$BODY"
```

For a captcha guard, add the provider's widget to your form; its token is
sent along and checked by Catchy:

```html
<!-- Cloudflare Turnstile -->
<div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<!-- Google reCAPTCHA v2 -->
<div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
```

## Destinations

**Destinations** are where a channel's hooks are sent. Create them on the
dashboard's **Destinations** page, then check them on a channel's page. Every
hook caught there is queued for each destination and sent in the background.

A destination speaks a **protocol**; today that's `http`: a request to a URL
with a method, optional headers, and an optional body template. An empty body
forwards the hook as received. The URL, headers, and body are templates that
can use [secrets](#secrets) by name: `Authorization: Bearer
{{.Secrets.RESEND_API_KEY}}`, or a whole URL like
`{{.Secrets.SLACK_WEBHOOK_URL}}` (Slack's and Discord's carry a token). **Sign
with** picks a secret, like `WEBHOOK_SIGNING_SECRET`, and signs each request
with it in `X-Catchy-Signature` (the format `hmac` guards check).

Presets fill in the form:

| Preset | Secrets | Sends |
|---|---|---|
| **Resend** | `RESEND_API_KEY` | `POST https://api.resend.com/emails` with a JSON email (edit from and to in the body); reply-to is the hook's `email` field when it has one |
| **Slack** / **Discord** | `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` | A message with the hook's fields to an incoming webhook |
| **Webhook URL** | — | The hook as received |
| **Signed webhook** | `WEBHOOK_SIGNING_SECRET` | The hook as received, signed |

Placeholders are `{{.Channel}}`, `{{.Payload.email}}` (any field; nested
ones with dots, like `{{.Payload.customer.email}}`, and a missing one is just
empty), `{{.Text}}` (all fields), `{{.Body}}` (raw), `{{.URL}}` (the hook's
page in the dashboard), `{{.Vars.NAME}}` (variables, below), and
`{{.Secrets.NAME}}`. In a JSON body, put them inside strings and
they're escaped for you, so quotes or newlines in a form never break it:

```json
{"text": "New hook in #{{.Channel}}\n\n{{.Text}}"}
```

`{{json .Payload}}` inserts the whole payload as a JSON object. Empty
`reply_to`, `cc`, and `bcc` are left out of JSON bodies, so an email preset
can use `"reply_to": "{{.Payload.email}}"` even for hooks without an email.
The body is filled in with a sample hook when you save, so a broken template
is caught right away. (Templates are Go templates, so `{{if}}`, `{{range}}`,
and the rest work too.)

**Variables** are environment variables named `CATCHY_VAR_NAME`, for values
you'd rather set per deployment than write into templates: with
`CATCHY_VAR_to=team@acme.dev`, `{{.Vars.to}}` is `team@acme.dev`. A missing
one is empty, so `{{or .Vars.to "team@acme.dev"}}` gives a default. To vary a
value by channel, use `{{if eq .Channel "sales"}}…{{end}}` or one destination
per channel.

Anything in the payload comes from whoever sends the hook, so `from`, `to`,
`cc`, and `bcc` in a JSON body can't use it: a destination that took its
recipient from the hook would send email anywhere for anyone. Saving one is
refused; use fixed addresses or variables. `reply_to` and `subject` can use
the payload.

A failed delivery is retried after 10s, 40s, 90s, and 160s, then given up.
When every delivery of a hook succeeds, the hook becomes `processed`; when one
gives up, it becomes `failed` with the reason, and **retry** sends its failed
deliveries again. Each hook shows its deliveries in the dashboard.

## Secrets

Secrets are environment variables named `CATCHY_SECRET_NAME`, usually set by
a secret manager (AWS Secrets Manager, GCP Secret Manager, Vault, Doppler,
1Password, Kubernetes secrets) or, locally, in `.env`. Catchy never stores
them, and the dashboard never asks for a value: templates write
`{{.Secrets.NAME}}`, and other fields pick a secret by name.

| Where | How |
|---|---|
| Destination URL, headers, body | `{{.Secrets.RESEND_API_KEY}}` |
| Destination signing | **Sign with** `WEBHOOK_SIGNING_SECRET` |
| Guard | **Secret** `STRIPE_WEBHOOK_SECRET` |

```bash
CATCHY_SECRET_RESEND_API_KEY=re_…
CATCHY_SECRET_STRIPE_WEBHOOK_SECRET=whsec_…
```

A guard or destination can use a secret before it's set, so you can set it
up first and add the variable after. Until it's set — or if it's removed
later — its guards refuse hooks and its deliveries fail, and Catchy says so:
a warning in the log at startup, a banner on every dashboard page, and the
secret marked in red where it's used. Set or change a secret, then restart
Catchy.

Only `CATCHY_SECRET_` and `CATCHY_VAR_` variables are read, so Catchy's own
settings and other software's secrets in a shared environment stay out of
reach. But anyone signed in to the dashboard can use the secrets — for
instance by creating a destination that sends one to a URL of theirs — as in
GitHub Actions, where anyone who can edit a workflow can use its secrets.
Sign-in is limited by `ALLOWED_DOMAINS`; keep it to people you'd trust with
them. Delivery errors mention a URL's host only, since the URL may hold a
secret.

## Processing hooks

Catchy doesn't act on hooks itself; whatever processes them (a script, a
worker, a notifier) runs outside and reports back through the hook's status:

| Status | Meaning |
|---|---|
| `pending` | Caught, waiting for a consumer (every hook starts here) |
| `processed` | A consumer handled it |
| `failed` | A consumer tried and couldn't, and said why |
| `discarded` | Deliberately ignored |

A consumer loop:

```bash
# 1. fetch pending hooks of a channel
curl -H "Authorization: Bearer $KEY" "$CATCHY/v1/hooks?channel=contact&status=pending"
# 2. handle each one, then report back
curl -H "Authorization: Bearer $KEY" -X POST "$CATCHY/v1/hooks/$ID/process"
#    or, when it couldn't be handled:
curl -H "Authorization: Bearer $KEY" -X POST "$CATCHY/v1/hooks/$ID/fail" \
  -H "Content-Type: application/json" -d '{"message":"slack returned 500"}'
```

Each `fail` adds its message to the hook's `failures` with the time; the list
is kept when the hook is retried, so you can still see why it failed after
it's processed. `process` and `discard` set `finalized_at`.

`retry` sets a hook back to `pending` to process it again. Each channel reports how
many of its hooks are in each status. Statuses can also be set from the
dashboard.

## Build

```bash
just build          # build binary
just test           # run tests
just generate       # regenerate proto code
just tidy           # go mod tidy
just clean          # remove build artifacts
```

## Docker

```bash
cp .env.example .env  # fill in your secrets
docker compose up
```

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `PORT` | Server listen port | `8080` |
| `HOSTNAME` | Public base URL | `http://localhost:$PORT` |
| `DATABASE_URL` | Database connection string (see below) | `file:catchy.db` |
| `SESSION_SECRET` | HMAC key for signing session cookies | required |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 client ID | required |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 client secret | required |
| `ALLOWED_DOMAINS` | Comma-separated list of allowed email domains | — (all allowed) |
| `AUTO_CREATE_CHANNELS` | Let a hook to an unknown channel create it; `false` answers such hooks with `404` | `true` |
| `TRUST_PROXY` | Take the sender's IP from `X-Forwarded-For` (`true` only behind a proxy that sets it) | — |
| `CATCHY_VAR_*` | Variables for destination templates, as `{{.Vars.NAME}}` | — |
| `CATCHY_SECRET_*` | [Secrets](#secrets) for destinations and guards, used by name: `CATCHY_SECRET_RESEND_API_KEY` is `RESEND_API_KEY` | — |

## Database

Driver is auto-detected from the DSN:

| DSN | Database |
|---|---|
| `file:catchy.db` | SQLite (default) |
| `postgres://user:pass@host/db` | PostgreSQL |

Migrations are managed by [goose](https://github.com/pressly/goose). Run them explicitly:

```bash
catchy migrate
# or: catchy serve --migrate
```

## CLI

```
catchy serve [--migrate]   # start the server (default), optionally run migrations first
catchy migrate             # run database migrations and exit
catchy version             # print version
catchy help                # print usage
```

## Authentication

Catching hooks needs no authentication. Everything else does.

### Web UI (Google OAuth)

1. Visit `/` — sign in with Google
2. The dashboard shows hooks by channel and status, channel settings, and API keys

Every signed-in user sees all hooks and channels. Set `ALLOWED_DOMAINS` to
restrict login to specific email domains.

### API (Bearer token)

All `/v1/*` API endpoints require a Bearer token:

```bash
curl -H "Authorization: Bearer <api-key>" http://localhost:8080/v1/hooks
```

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/hooks` | List hooks, newest first. Query: `channel`, `status`, `limit` (1–100, default 50), `after` (last hook ID of the previous page) |
| `GET` | `/v1/hooks/{id}` | Get a hook |
| `POST` | `/v1/hooks/{id}/process` | Mark a hook processed |
| `POST` | `/v1/hooks/{id}/fail` | Mark a hook failed: `{"message": "…"}` |
| `POST` | `/v1/hooks/{id}/discard` | Mark a hook discarded |
| `POST` | `/v1/hooks/{id}/retry` | Set a hook back to pending |
| `DELETE` | `/v1/hooks/{id}` | Delete a hook |
| `GET` | `/v1/channels` | List channels with hook counts per status |
| `GET` | `/v1/channels/{name}` | Get a channel |
| `POST` | `/v1/channels/{name}/pause` | Pause a channel: new hooks get 503 until resumed |
| `POST` | `/v1/channels/{name}/resume` | Resume a paused channel |
| `DELETE` | `/v1/channels/{name}` | Delete a channel and all its hooks |

Hook IDs are lowercase [ULIDs](https://github.com/ulid/spec), so they sort by
the time a hook was caught. A hook:

```json
{
  "id": "01k6z3x2b9e8v4m7q5w1t0r2y3",
  "channel": "contact",
  "status": "processed",
  "method": "POST",
  "query": "channel=contact",
  "headers": {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 …"},
  "content_type": "application/x-www-form-urlencoded",
  "body": "ZW1haWw9amFuZSU0MGV4YW1wbGUuY29tJm1lc3NhZ2U9SGklMjE=",
  "payload": {"email": "jane@example.com", "message": "Hi!"},
  "ip": "203.0.113.7",
  "failures": [
    {"at": "2026-10-07T12:00:05Z", "message": "slack returned 500"}
  ],
  "created_at": "2026-10-07T12:00:00Z",
  "finalized_at": "2026-10-07T12:01:00Z"
}
```

Over REST, `body` is base64-encoded. Only the body is stored; `payload` is
decoded from it on every read, and is absent when the body isn't a
JSON object or a form.

The full OpenAPI spec is served at `/openapi.yaml`.

## Protocols

A single endpoint serves all protocols via [vanguard-go](https://github.com/connectrpc/vanguard-go) transcoding:

| Protocol | Transport |
|---|---|
| gRPC | HTTP/2 (h2c) |
| gRPC-Web | HTTP/1.1 or HTTP/2 |
| Connect | HTTP/1.1 or HTTP/2 |
| REST | HTTP/1.1 or HTTP/2 |

## License

[Apache 2.0](LICENSE)

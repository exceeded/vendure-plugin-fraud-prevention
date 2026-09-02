# Changelog

All notable changes to `@huloglobal/vendure-plugin-fraud-prevention` are
documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project
adheres to [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.17.0] — 2026-09-02

### Added
- **Licence & billing card in the admin.** Always visible: the current state (free tier, free trial with first-charge date, monthly/annual subscription, lifetime, or master licence) with the actions that apply — start the 14-day free trial or subscribe, buy lifetime, **Manage billing** (Stripe customer portal: update card, cancel, switch plan) and **Upgrade to lifetime** (the old subscription stops billing at the end of its paid period). Requires licence SDK ^0.14.0.

## [0.16.1] — 2026-09-02

### Changed
- **The 14-day free trial is now card-backed.** Unlicensed installs run in the free tier; start the trial from the admin banner (monthly or annual → *Start 14-day free trial*) — Stripe collects a card, nothing is charged until day 15, cancel any time before then, one trial per customer — and the licence installs itself within a minute. The automatic no-card evaluation window is retired (licence SDK ^0.13.0).

## [0.16.0] — 2026-09-02

### Added
- **Buy licence from the admin.** The evaluation / free-tier banner now has a plan picker and a **Buy licence** button: checkout opens in a new tab and, once payment completes, the licence **installs itself** — no email round-trip, no `.env` edit, no restart. Renewed subscription keys are picked up automatically too. New admin endpoints `licence/purchase-link` and `licence/claim-status`.

### Changed
- Requires `@huloglobal/vendure-licence-sdk` ^0.12.0.
- The 7-day card trial at checkout has been retired: every install already gets the 14-day no-card evaluation, and paid plans now bill from day one.

## [0.15.1] — 2026-09-02

### Changed
- **Licence SDK ^0.11.0.** Master licences (one key that activates every HULO plugin) and hardware-bound keys are now accepted by the runtime licence check.
- **Branding.** Refreshed HULO Global logo (inline HG monogram) in the admin UI.

## [0.15.0] — 2026-08-25

### Added
- **PostgreSQL support.** All of the plugin's SQL now runs on Postgres as
  well as MySQL/MariaDB — the licence SDK's new dialect adapter translates
  queries transparently at runtime, so no configuration is needed: the
  plugin follows whatever database your Vendure `dbConnectionOptions` use.
  Verified against PostgreSQL 17. MySQL/MariaDB installs are unaffected
  (byte-identical passthrough).

## [0.14.1] — 2026-08-25

### Added
- **"What's new" in the update banner.** The banner now links
  straight to this plugin's changelog page on huloglobal.com, so you
  can read exactly what a release contains before updating.

## [0.14.0] — 2026-08-23

### Added
- **One-click in-app updates.** The update banner now has an "Update
  now" button: the plugin installs the new version via your project's
  own package manager (yarn/npm/pnpm auto-detected), verifies it landed,
  and gracefully restarts under your process supervisor (pm2/systemd).
  Admin-only; the target version is verified against the npm registry;
  a failed install never restarts anything. Disable with
  HULO_SELF_UPDATE=off; force restart without a detected supervisor
  with HULO_SELF_UPDATE=force. Note: a separate worker process picks
  the update up on its next restart, and the admin UI itself refreshes
  after your next admin build.

## [0.13.0] — 2026-08-22

### Changed
- **"Off" no longer means "blind".** When protection is disabled the
  engine still evaluates every rule and records a shadow assessment
  (action 'shadow', never any holds). Risky shadow-scored orders warn in
  the server log, fan out to the ops channels (new 'shadow.risky'
  event), optionally email the admin, and the order-detail panel shows a
  "scored while protection was off" notice — so switching protection off
  never silently loses the risk picture.

## [0.12.0] — 2026-08-22

### Added
- **Fraud panel on the admin order page.** Every paid order's detail
  page now shows the risk score (/100), level, contributing signals and
  review-case status, colour-coded and adapted to the admin light/dark
  theme. Only rendered once the order has a settled payment. New
  GET order-assessment/:orderId admin endpoint.

## [0.11.0] — 2026-08-21

### Added
- **One-click threat-feed presets.** The Custom feeds section now offers
  seven curated, well-known public lists (IPsum L3+, blocklist.de,
  FireHOL L2/L3, Emerging Threats compromised, CINS Army, StopForumSpam
  toxic domains) as add-with-one-click presets — no more hunting URLs.
  All URLs verified live at publish time; already-added feeds are
  hidden from the preset row.

### Fixed
- Premium buttons (enforce mode, feed sync, custom feeds) were still
  disabled during the full-featured evaluation — gating now keys off
  the tier, so trial installs can use everything the server allows.

## [0.10.0] — 2026-08-21

### Added
- **In-admin licence activation.** Paste your key into the plugin's
  admin page and it verifies (signature, plugin id, domain binding,
  expiry, revocation) and activates instantly — no .env edit, no
  redeploy. The key persists in the shared hulo_licence_store table and
  is re-applied on every boot; an explicitly configured env/init key
  always wins. POST licence/activate + licence/deactivate endpoints.

## [0.9.1] — 2026-08-21

### Added
- Evaluation pings now include anonymous usage aggregates (counts only,
  never personal data) so the opt-in reminder emails can say what the
  plugin actually did during the trial.

## [0.9.0] — 2026-08-21

### Added
- **14-day full-featured evaluation.** Unlicensed installs now get the
  complete feature set for 14 days instead of the restricted free tier.
  Enforce mode, review-queue holds, threat feeds and alerts now also run during the evaluation window. The clock is anchored server-side (a hashed
  instance id — no personal data), so reinstalling does not restart it,
  and it fails open: if the licence server is unreachable the plugin
  keeps running fully. After the window the plugin drops to the free
  tier; all configuration is kept and reactivates instantly with a key.
- Admin-UI evaluation banner with live countdown and an optional
  "email me before it ends" reminder opt-in (explicit consent — no
  email is sent anywhere otherwise).

## [0.8.0] — 2026-08-04

### Added
- **Upload image / asset library** button in the message editor — opens
  Vendure's asset picker (browse or upload) and inserts the image, stored
  in your asset library. Editor selection is saved/restored so toolbar and
  colour actions apply reliably after a dialog opens.

## [0.7.0] — 2026-08-04

### Added
- **Full editor toolbar** for the customer messages: text + highlight
  colour, font size, underline/strikethrough, headings/quotes, numbered
  lists, indent/outdent, image insert, custom button, divider, alignment,
  clear-formatting and undo/redo.

### Fixed
- Editor text showed grey in dark mode (admin theme colouring bare block
  elements). Canvas content now forces dark ink on the white paper.

## [0.6.1] — 2026-08-04

### Fixed
- Dark mode: the customer-message editor canvas now reads as intentional
  white paper (framed, visible caret), and the message preview renders on
  white — it was showing on a dark surface, which misrepresented the
  email and clashed with its inline colours.

## [0.6.0] — 2026-08-04

### Added
- **Visual email editor** for the customer messages (held / approved /
  rejected): formatting toolbar, drag-and-drop variable chips, and a
  Visual / HTML toggle. Message bodies are now HTML-aware — the
  plain-text defaults still render as before, but you can build a fully
  styled HTML email and it passes through untouched.

## [0.5.0] — 2026-08-03

### Added
- **Custom threat feeds.** Add your own public blocklist URLs in the
  Lists tab — any line-based list (one entry per line, `#` comments
  ignored), typed as IP / CIDR range / email / email-domain. They sync
  nightly alongside the built-ins and are matched identically (CIDR
  included), with per-feed enable/disable, on-demand sync, and last
  sync count / error surfaced. Licensed feature.
- Endpoints: `GET/POST /fraud-prevention/feeds/custom`,
  `POST /feeds/custom/:id` (edit / `{sync:true}`), `DELETE /feeds/custom/:id`.

### Security
- Feed fetches reject non-http(s) schemes and internal/private targets
  (localhost, RFC-1918, link-local) as a basic SSRF guard, and cap the
  response at 30 MB.
## [0.4.3] — 2026-08-02

### Fixed
- Public `POST /fraud-prevention/check` returned Nest's default `201` for
  a POST; it's a read-only risk check, so it now returns `200`.

### Added
- End-to-end test suite (`@vendure/testing`, real MariaDB dialect): admin
  auth gating, public-check shape + rate limiting, and the assessment
  engine (disposable email, order value, returning-customer trust credit,
  blocklist incl. CIDR ranges, allowlist bypass, unlicensed enforce
  downgrade). 11 e2e tests.

## [0.4.2] — 2026-08-02

### Fixed
- **Webhook integration row showed nothing, Telegram row was wrong.** A
  regex repair back in 0.3.3 over-matched and deleted the Telegram chat-ID
  field and the entire Webhook case, leaving the Telegram row bound to the
  webhook secret. Both integration rows are restored: Telegram (bot token
  + chat ID) and Webhook (URL + signing secret).

### Added
- **Customer messages: multi-select + bulk reset.** Each of the three
  templates (held / approved / rejected) shows a default / customised
  badge; tick any combination and "Reset selected to default", or "Reset
  all to default" in one click. Per-template reset stays.

## [0.4.1] — 2026-08-02

### Fixed
- **Review queue froze the browser tab** ("page unresponsive") when
  toggling the per-case "email customer" / "blocklist" checkboxes. The
  checkboxes bound to method calls (`[ngModel]="caseNotify(id)"`) which
  Angular re-evaluated every change-detection pass. The per-case ticks
  are now seeded from the global defaults when cases load and bound to
  plain state. The Settings integrations list likewise iterates a stable
  array instead of one rebuilt each cycle.

## [0.4.0] — 2026-08-02

### Added
- **Silent resolution.** Approve and Reject each carry a per-case
  "email customer" tick — untick to resolve without telling the customer
  anything. Defaults follow the global settings.
- **Silent identity blocklist on reject.** A per-case "blocklist" tick
  (and a global default) quietly adds the rejected email + canonical +
  IP to the blocklist, so a fraudster is turned away next time and never
  learns why — the classic don't-tip-them-off move.
- **Global notification defaults**: email-on-approval, email-on-rejection
  and blocklist-on-reject are all channel-wide toggles in Settings; the
  per-case ticks pre-fill from them and override for the single case.

## [0.3.3] — 2026-08-02

### Fixed
- 0.3.2's `&#64;` escape was corrupted by the release tooling (sed `&`
  back-reference) and still shipped a bare `@` — admin builds kept
  failing. Repaired and verified: no bare `@` remains in any template
  text node.

## [0.3.2] — 2026-08-02

### Fixed
- Admin UI failed to compile under Angular 17+ block syntax: the literal
  `@BotFather` in the Telegram help text is now the `&#64;` entity.

### Changed
- New logo: shield + amber pulse trace (live risk monitoring), also used
  in the admin hero.

## [0.3.1] — 2026-08-02

### Changed
- **Rules tab simplified.** New Protection level presets — Relaxed /
  Balanced (recommended) / Strict — set thresholds and velocity limits
  in one click; every numeric field now lives behind an Advanced
  settings toggle. Editing any value flips the level to Custom.
- **Notifications redesigned** as an integrations list: one row per
  channel (Email, Slack, Discord, Teams, Telegram, Webhook) with a
  connected-status dot, expanding in place to its few fields — instead
  of seven URL inputs spread across the page.

## [0.3.0] — 2026-08-02

### Added
- **Ops notification fan-out**: Slack, **Discord**, **Microsoft Teams**,
  **Telegram** (bot token + chat id) and a **generic signed webhook**
  (JSON POST, HMAC-SHA256 in `X-Hulo-Signature`) — every held, approved,
  rejected and auto-released case pings all configured channels. Each
  transport fails independently.
- **Customisable customer messages, per channel**: the three gating
  outcomes (held / approved / rejected) are now editable templates with
  `{{orderCode}}`, `{{firstName}}`, `{{supportEmail}}` and
  `{{reviewHours}}` variables, live preview and one-click reset. Bodies
  are plain text (blank lines = paragraphs) so tone is editable without
  HTML foot-guns. Defaults rewritten to be honest without being alarming
  — a held order is "a quick security check", never an accusation, and a
  rejection includes a human-appeal path.
- **Hold-notice policy per channel**: tell the customer never / only at
  block level (default) / on every held order; plus a configurable
  `reviewHours` promise surfaced in the templates.
- Auto-released cases now email the customer with the approved template
  and post an ops event.

## [0.2.0] — 2026-08-02

### Added
- **IP intelligence** (ip-api.com, cached 30 days in `fraud_ip_intel`,
  fails open): VPN/proxy and datacentre-IP signals — the `blockVpnProxy`
  toggle finally does something — plus **IP vs billing-country mismatch**.
- **Email MX validation**: a domain that can't receive mail can't receive
  licence keys either. Authoritative NXDOMAIN/no-MX scores; DNS timeouts
  fail open. 24h in-memory cache.
- **Identity fan-out**: ≥3 distinct customer emails ordering from one IP
  inside 24h — the classic card-testing pattern.
- **Customer trust credit**: returning customers earn NEGATIVE points
  (−12 for 1–2 settled orders, −25 for 3+), counted by canonical email so
  plus-tag variants share one track record. Score floors at 0. High-value
  first orders still score as before.
- **Gibberish-email heuristic** (digit-heavy or keyboard-mash local
  parts; deliberately low-weight) and **billing/shipping country
  mismatch** signal.
- **Customer Lookup tab**: full dossier per email — orders, lifetime
  value, settled/cancelled split, failed payments, prior cases,
  assessment history, list status, one-click allow/block.
- **Slack alerts**: optional webhook pinged on every held order.
- **Auto-release timer** (per channel, default off): pending cases older
  than N hours auto-approve so held orders don't strand over a weekend.
- **CSV export** of the activity log.

## [0.1.0] — 2026-08-02

First release as a standalone plugin — a full rebuild of the fraud tooling
that previously lived inside the HULO host project, with the piece that
implementation never had: **real enforcement**.

### Added
- **Server-side order guard.** Every `OrderPlacedEvent` is assessed — the
  old `/check` endpoint required the storefront to call it, and nothing did.
- **Signal-based scoring engine** with per-channel weights: velocity
  (IP/hour, IP/day, email/day, email daily value), order value, disposable
  emails, block/allow lists, high-risk countries, failed payments,
  plus-addressing detection (emails canonicalised before velocity counting),
  first-order-high-value.
- **CIDR range matching.** Spamhaus DROP and FireHOL ship ranges; the old
  implementation stored them but never matched them. Prefix-filtered SQL +
  exact `ipInCidr` verification (unit-tested).
- **Enforcement modes** per channel: off / monitor / enforce, with separate
  review and block thresholds and a plain-English status sentence.
- **Review queue workflow.** Pending cases hold fulfilment (host hook:
  `pendingOrderIds()`); approve releases + emails the customer, reject
  cancels + emails. All decisions audited.
- **Multi-tab admin dashboard** on the verified HULO admin design system
  (WCAG AA both themes): Overview (KPIs, daily chart, top IPs with one-click
  block), Rules, Review queue (count badge), Lists (manual + feeds), Simulate
  (full signal breakdown, dry-run), Activity (filterable audit log),
  Settings (notifications).
- **Licensing** via the HULO licence SDK: free tier = monitor + manual lists
  + simulate; enforce, feed sync and alerts require a licence. Update banner
  + heartbeat as across the HULO suite.
- **Retention**: audit log pruned nightly (default 180 days).

### Changed
- Table names are inherited from the pre-plugin implementation
  (`fraud_config`, `fraud_log`, `fraud_blocked_orders`, `fraud_blocklist`,
  `fraud_whitelist`, `fraud_notification_config`) — upgrading preserves all
  live data; new columns are added automatically.

### Security
- Admin REST surface now requires an authenticated admin session
  (`ReadCatalog` / `UpdateCatalog`) — previously these endpoints were
  mounted without any auth guard. The public `/check` endpoint is
  rate-limited and returns a minimal shape (no signal internals to probe).

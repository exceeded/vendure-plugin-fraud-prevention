# Changelog

All notable changes to `@huloglobal/vendure-plugin-fraud-prevention` are
documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project
adheres to [semantic versioning](https://semver.org/spec/v2.0.0.html).

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

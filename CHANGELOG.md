# Changelog

All notable changes to `@huloglobal/vendure-plugin-fraud-prevention` are
documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project
adheres to [semantic versioning](https://semver.org/spec/v2.0.0.html).

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

# @huloglobal/vendure-plugin-fraud-prevention

Full fraud-prevention suite for [Vendure](https://www.vendure.io/). Every placed
order is risk-scored **server-side** the moment it lands — no storefront
integration required — and what happens next is up to your per-channel policy:
log it, hold it for manual review, or hold it *and* tell the customer it's
being verified.

**Plugin page & pricing:** https://huloglobal.com/vendure-plugins/fraud-prevention/

## Signals

Each fired signal adds weighted points (all weights overridable per channel):

| Signal | Default points |
|---|---|
| Blocklisted email / domain | 60 / 45 |
| Blocklisted IP / IP in CIDR range | 55 |
| Disposable email domain | 50 |
| Failed payments from IP (1h) | 45 |
| IP order velocity (hour / day) | 40 / 30 |
| High-risk country | 40 |
| Card AVS: postcode mismatch (issuer verdict) | 35 |
| Stripe Radar: highest risk | 35 |
| Email order velocity (24h) | 35 |
| Email daily value ceiling | 30 |
| Order value ceiling | 25 |
| Card AVS: street address mismatch (issuer verdict) | 20 |
| First order + high value | 18 |
| Stripe Radar: elevated risk | 15 |
| Plus-addressed email (`x+7@gmail`) | 12 |
| 3-D Secure failed (no liability shift) | 10 |
| Billing / shipping postcode differ (typed) | 8 |

Emails are canonicalised before velocity counting — `x+1@gmail.com`,
`x+2@gmail.com` and `x.y@gmail.com` all count as one identity. Allowlisted
identities bypass everything.

### Postcode / AVS

AVS (Address Verification Service) is the card issuer's own verdict on the
billing postcode and street number the customer typed — the strongest
address signal there is, because it comes from the bank rather than the
customer. Only an explicit **fail** scores; `unavailable` / `unchecked`
(issuer doesn't support it, or the field wasn't sent) is silent.

Where the verdict comes from, in order:

1. **`avsResolver`** plugin option — any gateway. Called once per placed
   order with the Vendure `Order` (payments loaded) and the request
   context; return `{ postalCode, line1, source }` using
   `pass | fail | unavailable | unchecked`, or `null` when unknown.
2. **Payment metadata** — a custom payment handler can store the result on
   the `Payment` as `{ avs: { postalCode: 'fail', line1: 'pass' } }`
   (Stripe-style `checks: { address_postal_code_check, address_line1_check }`
   and flat keys are recognised too; `Y/N/U`, `match/no_match` and booleans
   are all understood).
3. **Stripe, automatically** — for orders paid through Vendure's
   `StripePlugin` the PaymentIntent is fetched with `expand[]=latest_charge`
   using the payment method's own API key and
   `charge.payment_method_details.card.checks` is read. One GET per placed
   order, 5 s timeout, fails open. Switch it off per channel with
   *Check card AVS with Stripe* under Rules → Signals.

   **Stripe only runs AVS when your checkout sends the billing address.**
   The Payment Element does not collect the street address by itself, and
   many integrations never pass a postcode either — in which case both
   checks come back `null` and nothing scores. Send the order's billing
   address in `confirmPayment`
   (`confirmParams.payment_method_data.billing_details.address`, with the
   element created using `fields: { billingDetails: { address: 'never' } }`)
   and the issuer verifies postcode and street number on every card
   payment. Wallet payments (Apple Pay, Google Pay, Link) are verified by
   the wallet provider instead and carry no AVS checks.

A typed billing vs shipping postcode difference (same country, both present)
is scored separately and weakly — gifts and office deliveries do this
legitimately, but it compounds with the other signals. All three weights are
overridable per channel like every other signal.

The plugin also counts failed payments the
[checkout-guard plugin](https://huloglobal.com/vendure-plugins/checkout-guard/)
records before a Vendure `Payment` row exists (gateway declines and
storefront-reported client declines in `checkout_guard_payment_event`) towards
the *Failed payments from IP* signal, when that table is present. Nothing to
configure — it is detected automatically.

### Stripe Radar and 3-D Secure

The same Stripe lookup that reads the AVS checks also reads the charge's
**Radar risk level** (`outcome.risk_level`) and its **3-D Secure outcome**
(`payment_method_details.card.three_d_secure`), so orders paid through
Vendure's `StripePlugin` get three more signals for free:

| Signal | Fires when | Default points |
|---|---|---|
| `radar_risk_highest` | Radar rated the charge `highest` | 35 |
| `radar_risk_elevated` | Radar rated the charge `elevated` | 15 |
| `three_ds_failed` | 3DS ran and `authenticated` is `false` (result not `attempt_acknowledged` / `exempted` / `not_supported`) | 10 |

Radar sees the card across every Stripe merchant, so `highest` is a strong
signal even when nothing else fired; `normal` and `not_assessed` are silent.
`three_ds_failed` means liability did *not* shift to the issuer — a chargeback
would land on you. It is gated by the channel's *Score a failed 3-D Secure
authentication* rule (on by default). Wallet payments (Apple Pay, Google Pay,
Link) are authenticated by the wallet and carry neither AVS nor 3DS data;
Radar still assesses them.

Other gateways can supply the same verdicts through `avsResolver` or payment
metadata — return `{ riskLevel: 'elevated' | 'highest', threeDsAuthenticated:
false, threeDsResult: 'failed' }` alongside the AVS fields (the type is
`CardChecks`; `AvsResult` remains as an alias).

## Enforcement modes (per channel)

- **Off** — nothing, not even logging.
- **Monitor** — score + log every order; risky orders are flagged but never
  held. Start here and tune thresholds against the Activity tab.
- **Enforce** — score ≥ review threshold opens a case in the Review queue and
  (with the host integration below) holds licence-key/goods fulfilment until
  a human approves; score ≥ block threshold additionally emails the customer
  that their order is under verification. Approve releases + notifies;
  reject cancels the order in Vendure (`OrderService.cancelOrder`, so every
  `OrderStateTransitionEvent` subscriber sees it), voids Authorized payments
  (card holds, bank transfers), refunds every settled payment in full through
  the payment handler's `createRefund`, marks the order inactive and notifies
  the customer. Set `cancelOnReject: false` / `refundOnReject: false` in the
  plugin options to opt out, or pass `cancel` / `refund` per case in
  `POST /fraud-prevention/cases/:id/reject`. Anything Vendure refused
  (`RefundOrderStateError`, a handler without `createRefund`, …) comes back in
  `warnings` and the audit log — the case still closes.

## Threat feeds

Daily sync (03:00) into the blocklist: **FireHOL Level 1**, **Spamhaus DROP**
(IPv4 and IPv6 CIDR ranges are matched), **Tor exit nodes**, and the
community **disposable-email-domains** list. Manual allow/block entries ride
on top.

## Install

```bash
npm i @huloglobal/vendure-plugin-fraud-prevention
```

```ts
import { FraudPreventionPlugin } from '@huloglobal/vendure-plugin-fraud-prevention';

plugins: [
    FraudPreventionPlugin.init({
        publicBaseUrl: 'https://shop.example.com',
        licenceKey: process.env.HULO_FRAUD_LICENCE,
    }),
],
```

### Admin UI

```ts
// in your compileUiExtensions extensions array:
FraudPreventionPlugin.uiExtensions,
```

This registers three things:

- **Sales → Fraud Prevention** in the admin navigation, opening the multi-tab
  dashboard (Overview, Rules, Review queue, Lists, Simulate, Activity, Settings).
  It needs the `ReadCatalog` permission, the same as the page's read endpoints.
- A **fraud panel on every order-detail page** showing the score, the signals
  that fired and the review case, if any.
- A **dashboard widget** — Dashboard → Add widget → **Fraud Prevention** —
  with the last seven days' figures (orders scored, risky orders intercepted,
  value intercepted) and a link to the page.

## Weekly report, setup checklist and dashboard widget

**Weekly report.** Every Monday at 08:00 (server-local time) the plugin emails
a short report covering the previous seven days, with the week before for
comparison: orders risk-scored, orders held for review, orders blocked, the
value of the orders intercepted (the Vendure order totals behind every review
case), and review cases approved and rejected. Below the figures it lists up
to three next steps taken from the set-up checklist, the licence state when
something needs attention (a trial or key about to end), and a link to the
admin page. Nothing is reported that is not counted in the plugin's own
tables — a quiet week says so.

The report goes to the first of: the recipient entered under **Settings →
Weekly report**; the alert address under **Settings → Notifications → Email**;
the `defaultAdminEmail` option; the licence's customer email; the address given
to "Email me before it ends" during the evaluation. The card shows which
address applies ("Defaults to …"), when the last report went out and when the
next is due, and has **Send me a test** and **Preview** buttons. Untick *Send
the weekly report* to stop it. One report is sent per install, however many
server or worker processes run; the scheduler runs on the worker.

It uses the same SMTP transport as the fraud alerts — the `smtp` option, or
the `SMTP_SERVER` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM`
environment variables. With no SMTP configured the report is silently off and
"Send me a test" says why.

**Setup checklist.** The Overview tab opens with a checklist of real checks
against the configuration: scoring switched on for a channel, enforce mode on
at least one channel, an alert email set, threat feeds synced in the last
seven days, and a first review case worked. Each row links to the tab where it
is done. **Hide** keeps it out of the way (remembered in the browser); it
disappears for good once everything is done and comes back if something
becomes undone. The same items supply the weekly report's next steps.

**Dashboard widget.** Dashboard → Add widget → **Fraud Prevention**. Three
seven-day figures, the licence notice when one applies, and an "Open Fraud
Prevention" link. Supported widths: 4, 6 and 8 columns.

**Usage figures sent to HULO.** The same six counters (last 30 days, numbers
only, no customer data) ride along with the daily heartbeat and, during the
evaluation, with the evaluation check-in, so renewal and reminder emails can
say what the plugin did for the store. `HULO_HEARTBEAT_DISABLED=true` stops
the heartbeat entirely.

### Holding fulfilment on pending cases

The plugin marks orders as held; your fulfilment path asks before shipping:

```ts
import { FraudPreventionService } from '@huloglobal/vendure-plugin-fraud-prevention';

const held = new Set(await this.fraudService.heldOrderIds()); // pending + rejected
if (held.has(orderId)) continue;                                // skip until a human approves
if (!(await this.fraudService.isAssessed(orderId))) continue;   // not scored yet — try again shortly
```

`pendingOrderIds()` (open cases only) is unchanged. `heldOrderIds()` also
includes rejected cases, so a rejected order is never released by a
fulfilment path that only checks for open cases. `isAssessed(orderId)` (and
the batch `assessedOrderIds(ids)`) closes the race between `OrderPlacedEvent`
and the guard's asynchronous assessment: an order that has not been scored
yet has no case to hold it, so fulfil only once both are true. Every placed
order gets a `fraud_log` row — even with the channel off — so `isAssessed`
becomes true within a second or two of placement.

### Storefront pre-check (optional)

`POST /fraud-prevention/check` `{ email, orderValuePence, channelId }` →
`{ allowed, riskLevel }` — rate-limited, minimal response shape by design.

### Options

| Option | Default | Purpose |
|---|---|---|
| `publicBaseUrl` | — | Used in admin notification links and licence host binding |
| `licenceKey` | — | JWT from huloglobal.com; also activatable from the admin |
| `defaultAdminEmail` | — | Where fraud-alert emails go when no per-install setting exists |
| `smtp` | `SMTP_*` env | SMTP transport for alerts and customer notices |
| `rateLimit` | 60 / min | Rate limit for the public `/fraud-prevention/check` endpoint |
| `logRetentionDays` | 180 | Prune `fraud_log` rows older than this (0 = keep) |
| `disableFeedSync` | false | Skip the daily threat-feed sync |
| `avsResolver` | — | Supply `CardChecks` (AVS, Radar, 3DS) for any gateway |
| `cancelOnReject` | true | Rejecting a case cancels the order through Vendure |
| `refundOnReject` | true | Rejecting a case refunds settled payments in full |

## Licensing

Without a licence key the plugin runs in the **free tier**: monitor mode,
manual lists and simulate. Enforce mode, review-queue holds, threat-feed sync
and email alerts require a licence from
https://huloglobal.com/vendure-plugins/fraud-prevention/.

## Compatibility

Vendure `>=3.5 <4`. MariaDB/MySQL and PostgreSQL (through the licence SDK's
SQL dialect adapter). Tables are created/migrated automatically on boot,
including a best-effort index on Vendure's `payment(createdAt)`; upgrading
from the pre-plugin HULO implementation preserves all existing config, log
and list data. Block/allow list ranges accept IPv4 and IPv6 CIDR notation.

## License

AGPL-3.0-or-later — commercial licences available from HULO Global.

## Buying a licence

Pick monthly or annual on the plugin's admin banner and click **Start 14-day free trial** (card required, nothing charged until day 15, cancel any time), or choose lifetime — checkout opens in a new tab and the key installs itself within a minute. You can also buy at https://elite.charity/licence/buy/vendure-plugin-fraud-prevention and paste the emailed key into the admin.

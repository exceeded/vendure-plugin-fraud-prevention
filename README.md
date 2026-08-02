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
| Email order velocity (24h) | 35 |
| Email daily value ceiling | 30 |
| Order value ceiling | 25 |
| First order + high value | 18 |
| Plus-addressed email (`x+7@gmail`) | 12 |

Emails are canonicalised before velocity counting — `x+1@gmail.com`,
`x+2@gmail.com` and `x.y@gmail.com` all count as one identity. Allowlisted
identities bypass everything.

## Enforcement modes (per channel)

- **Off** — nothing, not even logging.
- **Monitor** — score + log every order; risky orders are flagged but never
  held. Start here and tune thresholds against the Activity tab.
- **Enforce** — score ≥ review threshold opens a case in the Review queue and
  (with the host integration below) holds licence-key/goods fulfilment until
  a human approves; score ≥ block threshold additionally emails the customer
  that their order is under verification. Approve releases + notifies;
  reject cancels + notifies.

## Threat feeds

Daily sync (03:00) into the blocklist: **FireHOL Level 1**, **Spamhaus DROP**
(CIDR ranges are matched properly), **Tor exit nodes**, and the
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

Admin UI (multi-tab dashboard: Overview, Rules, Review queue, Lists, Simulate,
Activity, Settings):

```ts
// in your compileUiExtensions extensions array:
FraudPreventionPlugin.uiExtensions,
```

### Holding fulfilment on pending cases

The plugin marks orders as held; your fulfilment path asks before shipping:

```ts
import { FraudPreventionService } from '@huloglobal/vendure-plugin-fraud-prevention';

const held = new Set(await this.fraudService.pendingOrderIds());
if (held.has(orderId)) continue; // skip until a human approves
```

### Storefront pre-check (optional)

`POST /fraud-prevention/check` `{ email, orderValuePence, channelId }` →
`{ allowed, riskLevel }` — rate-limited, minimal response shape by design.

## Licensing

Without a licence key the plugin runs in the **free tier**: monitor mode,
manual lists and simulate. Enforce mode, review-queue holds, threat-feed sync
and email alerts require a licence from
https://huloglobal.com/vendure-plugins/fraud-prevention/.

## Compatibility

Vendure `>=3.5 <4`. MariaDB/MySQL. Tables are created/migrated automatically
on boot; upgrading from the pre-plugin HULO implementation preserves all
existing config, log and list data.

## License

AGPL-3.0-or-later — commercial licences available from HULO Global.

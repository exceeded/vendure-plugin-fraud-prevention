/**
 * Postcode / AVS (Address Verification Service) helpers.
 *
 * Two related signals live here:
 *
 *   1. `postcode_mismatch` — the billing and shipping postcodes the
 *      customer typed differ (same country). Weak on its own — gifts and
 *      office deliveries do this legitimately — but it compounds.
 *
 *   2. `avs_postcode_fail` / `avs_address_fail` — the CARD ISSUER says
 *      the billing postcode / street number on the card does not match
 *      what the customer entered. This is the strongest address signal
 *      there is: it comes from the bank, not from the customer.
 *
 * AVS results are read, in order, from
 *   • a host-supplied `avsResolver` (any gateway),
 *   • the Vendure `Payment.metadata` (custom handlers can drop the result
 *     in as `avs: { postalCode, line1 }` or Stripe-style `checks`),
 *   • Stripe directly: for payments taken by Vendure's StripePlugin the
 *     PaymentIntent is fetched with `expand[]=latest_charge` using the
 *     payment method's own API key, and
 *     `charge.payment_method_details.card.checks` is read.
 *
 * Everything fails open: no result → no signal.
 */

/** Mirrors Stripe's vocabulary. `unavailable` = issuer does not support
 *  the check; `unchecked` = the value was not sent to the issuer. */
export type AvsCheck = 'pass' | 'fail' | 'unavailable' | 'unchecked';

export interface AvsResult {
    postalCode?: AvsCheck;
    line1?: AvsCheck;
    /** Where the result came from — shown in the signal detail. */
    source?: string;
}

/** Normalise a postcode for comparison: uppercase, alphanumerics only.
 *  "sw1a 1aa" / "SW1A1AA" / "SW1A-1AA" all become "SW1A1AA". */
export function normalisePostcode(pc: unknown): string {
    return String(pc ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/** True when both postcodes are present and differ after normalisation.
 *  Missing values never count as a mismatch, and neither does a partial
 *  form of the same code — a 5-digit ZIP against its ZIP+4, or a UK
 *  outward code against the full postcode — since one is a prefix of the
 *  other (three or more characters shared). */
export function postcodesDiffer(a: unknown, b: unknown): boolean {
    const na = normalisePostcode(a);
    const nb = normalisePostcode(b);
    if (!na || !nb) return false;
    if (na === nb) return false;
    const [short, long] = na.length <= nb.length ? [na, nb] : [nb, na];
    if (short.length >= 3 && long.startsWith(short)) return false;
    return true;
}

/** Coerce the many ways gateways spell an AVS outcome into our four
 *  values. Returns null for anything unrecognised so callers can skip. */
export function parseAvsCheck(v: unknown): AvsCheck | null {
    if (v === true) return 'pass';
    if (v === false) return 'fail';
    if (v == null) return null;
    const s = String(v).trim().toLowerCase();
    if (!s) return null;
    if (['pass', 'passed', 'match', 'matched', 'matches', 'y', 'yes', 'ok', 'true', '1'].includes(s)) return 'pass';
    if (['fail', 'failed', 'mismatch', 'no_match', 'nomatch', 'no-match', 'n', 'no', 'false', '0'].includes(s)) return 'fail';
    if (['unavailable', 'unsupported', 'not_supported', 'u', 'x', 'g', 's', 'r'].includes(s)) return 'unavailable';
    if (['unchecked', 'not_checked', 'notchecked', 'skipped', 'none', 'null'].includes(s)) return 'unchecked';
    return null;
}

/** Read an AVS result out of a Stripe Charge object (or anything shaped
 *  like `{ payment_method_details: { card: { checks } } }`). */
export function avsFromStripeCharge(charge: any): AvsResult | null {
    const checks = charge?.payment_method_details?.card?.checks ?? null;
    if (!checks) return null;
    const postalCode = parseAvsCheck(checks.address_postal_code_check);
    const line1 = parseAvsCheck(checks.address_line1_check);
    if (!postalCode && !line1) return null;
    const out: AvsResult = { source: 'stripe' };
    if (postalCode) out.postalCode = postalCode;
    if (line1) out.line1 = line1;
    return out;
}

/**
 * Read an AVS result from a Vendure `Payment.metadata` blob. Accepted
 * shapes (first match wins):
 *   { avs: { postalCode, line1 } }               — our canonical form
 *   { avs: { postal_code, address_line1 } }       — snake_case variant
 *   { checks: { address_postal_code_check, … } }  — Stripe checks object
 *   { address_postal_code_check, … }              — flat Stripe keys
 *   { avsPostalCode, avsLine1 }                   — flat camelCase keys
 */
export function avsFromMetadata(metadata: any, source = 'payment metadata'): AvsResult | null {
    if (!metadata || typeof metadata !== 'object') return null;
    const m = metadata;
    const candidates: Array<[unknown, unknown]> = [
        [m.avs?.postalCode, m.avs?.line1],
        [m.avs?.postal_code, m.avs?.address_line1 ?? m.avs?.line1],
        [m.avs?.address_postal_code_check, m.avs?.address_line1_check],
        [m.checks?.address_postal_code_check, m.checks?.address_line1_check],
        [m.address_postal_code_check, m.address_line1_check],
        [m.avsPostalCode ?? m.avs_postal_code, m.avsLine1 ?? m.avs_line1],
    ];
    for (const [pcRaw, l1Raw] of candidates) {
        const postalCode = parseAvsCheck(pcRaw);
        const line1 = parseAvsCheck(l1Raw);
        if (postalCode || line1) {
            const out: AvsResult = { source: typeof m.avs?.source === 'string' ? m.avs.source : source };
            if (postalCode) out.postalCode = postalCode;
            if (line1) out.line1 = line1;
            return out;
        }
    }
    return null;
}

export type FetchLike = (url: string, init?: any) => Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

export interface FetchStripeAvsOptions {
    fetchImpl?: FetchLike;
    timeoutMs?: number;
    /** Receives a one-line diagnostic whenever the lookup could not
     *  produce a verdict for a reason other than "not a card". */
    log?: (message: string) => void;
}

/** The request is pinned to this API version so `latest_charge` exists
 *  and can be expanded whatever the account's default version is (it was
 *  introduced in 2022-11-15, when `charges` left the PaymentIntent). A
 *  read-only GET only changes the response shape, never the account. */
export const STRIPE_API_VERSION = '2022-11-15';

/**
 * Fetch the AVS checks for a Stripe PaymentIntent. Uses the platform
 * `fetch` (Node 18+) so the plugin needs no Stripe SDK. Fails open —
 * any error, timeout or non-2xx returns null (and is reported through
 * `opts.log` so key-permission or API-version problems are visible).
 *
 * The request is pinned to STRIPE_API_VERSION so `expand[]=latest_charge`
 * is valid on every account; should the expansion ever be omitted, the
 * charge is fetched by id as a second call.
 */
export async function fetchStripeAvs(
    apiKey: string,
    paymentIntentId: string,
    opts: FetchStripeAvsOptions = {},
): Promise<AvsResult | null> {
    if (!apiKey || !paymentIntentId || !/^pi_[A-Za-z0-9]+$/.test(paymentIntentId)) return null;
    const fetchImpl: FetchLike = opts.fetchImpl ?? (globalThis as any).fetch;
    if (typeof fetchImpl !== 'function') return null;
    const log = opts.log ?? (() => undefined);
    const timeoutMs = opts.timeoutMs ?? 5000;
    const headers = { Authorization: `Bearer ${apiKey}`, 'Stripe-Version': STRIPE_API_VERSION };

    const get = async (path: string): Promise<any | null> => {
        const ac = typeof AbortController !== 'undefined' ? new AbortController() : null;
        let backup: ReturnType<typeof setTimeout> | undefined;
        const abortTimer = setTimeout(() => ac?.abort(), timeoutMs);
        try {
            const res = await Promise.race([
                fetchImpl(`https://api.stripe.com/v1/${path}`, { method: 'GET', headers, signal: ac?.signal }),
                new Promise<never>((_, reject) => { backup = setTimeout(() => reject(new Error('timed out')), timeoutMs + 250); }),
            ]);
            if (!res || !res.ok) {
                log(`Stripe GET ${path.split('?')[0]} returned HTTP ${res?.status ?? '?'}`);
                return null;
            }
            return await res.json();
        } catch (e: any) {
            log(`Stripe GET ${path.split('?')[0]} failed: ${e?.message || e}`);
            return null;
        } finally {
            clearTimeout(abortTimer);
            if (backup) clearTimeout(backup);
        }
    };

    const pi = await get(`payment_intents/${encodeURIComponent(paymentIntentId)}?expand[]=latest_charge`);
    if (!pi) return null;
    let charge: any = pi.latest_charge && typeof pi.latest_charge === 'object' ? pi.latest_charge : null;
    if (!charge) {
        const chargeId = typeof pi.latest_charge === 'string' ? pi.latest_charge : null;
        if (chargeId && /^ch_[A-Za-z0-9]+$/.test(chargeId)) charge = await get(`charges/${encodeURIComponent(chargeId)}`);
    }
    if (!charge) {
        log(`No charge found on ${paymentIntentId} (status ${pi.status ?? '?'})`);
        return null;
    }
    return avsFromStripeCharge(charge);
}

/** Human wording for the signal detail column. */
export function describeAvs(kind: 'postalCode' | 'line1', result: AvsResult): string {
    const what = kind === 'postalCode' ? 'billing postcode' : 'street address';
    const via = result.source ? ` (${result.source})` : '';
    return `Card issuer reports the ${what} does not match the card${via}`;
}

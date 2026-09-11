/**
 * Card-check helpers: postcode / AVS, Stripe Radar risk level and 3-D
 * Secure outcome.
 *
 * The signals that live here:
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
 *   3. `radar_risk_elevated` / `radar_risk_highest` — Stripe Radar's own
 *      machine-learned verdict on the charge (`outcome.risk_level`).
 *      Radar sees the card across every Stripe merchant, so its "highest"
 *      is a very strong signal even when nothing else fired.
 *
 *   4. `three_ds_failed` — 3-D Secure ran and the cardholder did NOT
 *      authenticate (`three_d_secure.authenticated === false`, and the
 *      result was not a benign "attempt acknowledged" / "exempted" /
 *      "not supported"). Liability did not shift to the issuer.
 *
 * Card checks are read, in order, from
 *   • a host-supplied `avsResolver` (any gateway),
 *   • the Vendure `Payment.metadata` (custom handlers can drop the result
 *     in as `avs: { postalCode, line1, riskLevel, threeDsAuthenticated }`
 *     or Stripe-style `checks` / `outcome` / `three_d_secure` objects),
 *   • Stripe directly: for payments taken by Vendure's StripePlugin the
 *     PaymentIntent is fetched with `expand[]=latest_charge` using the
 *     payment method's own API key, and the charge's
 *     `payment_method_details.card.checks`, `outcome.risk_level` and
 *     `payment_method_details.card.three_d_secure` are read.
 *
 * Everything fails open: no result → no signal.
 */

/** Mirrors Stripe's vocabulary. `unavailable` = issuer does not support
 *  the check; `unchecked` = the value was not sent to the issuer. */
export type AvsCheck = 'pass' | 'fail' | 'unavailable' | 'unchecked';

/** Stripe Radar's `outcome.risk_level`. `not_assessed` = Radar did not
 *  run (e.g. the charge was not evaluated); `unknown` = anything else. */
export type RadarRiskLevel = 'normal' | 'elevated' | 'highest' | 'not_assessed' | 'unknown';

/** Stripe's `three_d_secure.result` vocabulary (a subset is enough for
 *  scoring; unknown strings are kept verbatim for the detail column). */
export type ThreeDsResult =
    | 'authenticated'
    | 'attempt_acknowledged'
    | 'exempted'
    | 'failed'
    | 'not_supported'
    | 'processing_error'
    | string;

/** Everything the gateway told us about the card on this order. Every
 *  field is optional — a partial result still scores whatever it has. */
export interface CardChecks {
    /** Issuer AVS verdict on the billing postcode. */
    postalCode?: AvsCheck;
    /** Issuer AVS verdict on the billing street (house number). */
    line1?: AvsCheck;
    /** Stripe Radar risk level for the charge. */
    riskLevel?: RadarRiskLevel;
    /** Stripe Radar risk score 0-99 (Radar for Fraud Teams only). */
    riskScore?: number;
    /** `three_d_secure.authenticated` — whether the cardholder passed
     *  authentication. `undefined` when 3DS did not run. */
    threeDsAuthenticated?: boolean;
    /** `three_d_secure.result` when the gateway reports one. */
    threeDsResult?: ThreeDsResult;
    /** Where the result came from — shown in the signal detail. */
    source?: string;
}

/** Kept for hosts that imported the 0.18 name. `AvsResult` and
 *  `CardChecks` are the same shape. */
export type AvsResult = CardChecks;

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

/** Coerce a Radar risk level. Accepts Stripe's strings in any case and
 *  a few spellings other tools use; null for anything unrecognised. */
export function parseRiskLevel(v: unknown): RadarRiskLevel | null {
    if (v == null) return null;
    const s = String(v).trim().toLowerCase().replace(/[\s-]+/g, '_');
    if (!s) return null;
    if (['normal', 'low', 'ok'].includes(s)) return 'normal';
    if (['elevated', 'medium', 'moderate'].includes(s)) return 'elevated';
    if (['highest', 'high', 'critical'].includes(s)) return 'highest';
    if (['not_assessed', 'unassessed', 'not_evaluated', 'skipped'].includes(s)) return 'not_assessed';
    if (['unknown'].includes(s)) return 'unknown';
    return null;
}

/** Coerce a 3-D Secure "authenticated" flag from booleans or strings. */
export function parseThreeDsAuthenticated(v: unknown): boolean | null {
    if (v === true || v === false) return v;
    if (v == null) return null;
    const s = String(v).trim().toLowerCase();
    if (['true', 'yes', 'y', '1', 'authenticated', 'pass', 'passed', 'succeeded'].includes(s)) return true;
    if (['false', 'no', 'n', '0', 'failed', 'fail', 'unauthenticated'].includes(s)) return false;
    return null;
}

/** 3DS results where `authenticated: false` is NOT a failure: the issuer
 *  acknowledged an attempt (liability still shifts), the transaction was
 *  exempted (low value / TRA), or the card is not enrolled at all. */
const BENIGN_THREE_DS_RESULTS = new Set(['attempt_acknowledged', 'exempted', 'not_supported', 'authenticated']);

/** True when 3-D Secure ran and the cardholder failed to authenticate.
 *  `undefined` / no 3DS data is never a failure (fails open). */
export function threeDsFailed(checks: CardChecks | null | undefined): boolean {
    if (!checks || checks.threeDsAuthenticated !== false) return false;
    const result = String(checks.threeDsResult ?? '').toLowerCase();
    if (result && BENIGN_THREE_DS_RESULTS.has(result)) return false;
    return true;
}

/** True when the object carries at least one usable verdict. */
function hasAnyCheck(c: CardChecks): boolean {
    return c.postalCode !== undefined || c.line1 !== undefined || c.riskLevel !== undefined
        || c.threeDsAuthenticated !== undefined;
}

/** Read every card check out of a Stripe Charge object (or anything
 *  shaped like `{ payment_method_details: { card: { checks,
 *  three_d_secure } }, outcome: { risk_level, risk_score } }`). Returns
 *  null when the charge carries nothing usable (non-card, or nothing was
 *  checked). */
export function cardChecksFromStripeCharge(charge: any): CardChecks | null {
    if (!charge || typeof charge !== 'object') return null;
    const card = charge?.payment_method_details?.card ?? null;
    const out: CardChecks = { source: 'stripe' };

    const checks = card?.checks ?? null;
    if (checks) {
        const postalCode = parseAvsCheck(checks.address_postal_code_check);
        const line1 = parseAvsCheck(checks.address_line1_check);
        if (postalCode) out.postalCode = postalCode;
        if (line1) out.line1 = line1;
    }

    const riskLevel = parseRiskLevel(charge?.outcome?.risk_level);
    if (riskLevel) out.riskLevel = riskLevel;
    const riskScore = Number(charge?.outcome?.risk_score);
    if (Number.isFinite(riskScore) && charge?.outcome?.risk_score != null) out.riskScore = riskScore;

    const tds = card?.three_d_secure ?? null;
    if (tds && typeof tds === 'object') {
        const authenticated = parseThreeDsAuthenticated(tds.authenticated);
        if (authenticated !== null) out.threeDsAuthenticated = authenticated;
        if (typeof tds.result === 'string' && tds.result) out.threeDsResult = tds.result;
    }

    return hasAnyCheck(out) ? out : null;
}

/** 0.18 name — AVS only was read then; the same function now returns
 *  every card check. Kept so existing imports keep working. */
export const avsFromStripeCharge = cardChecksFromStripeCharge;

/**
 * Read card checks from a Vendure `Payment.metadata` blob. Accepted
 * shapes for AVS (first match wins):
 *   { avs: { postalCode, line1 } }               — our canonical form
 *   { avs: { postal_code, address_line1 } }       — snake_case variant
 *   { checks: { address_postal_code_check, … } }  — Stripe checks object
 *   { address_postal_code_check, … }              — flat Stripe keys
 *   { avsPostalCode, avsLine1 }                   — flat camelCase keys
 * Radar / 3DS may sit alongside in any of
 *   { avs: { riskLevel, threeDsAuthenticated, threeDsResult } }
 *   { card: { riskLevel, threeDsAuthenticated } }
 *   { radarRiskLevel | risk_level | outcome: { risk_level, risk_score } }
 *   { threeDsAuthenticated | three_d_secure: { authenticated, result } }
 */
export function avsFromMetadata(metadata: any, source = 'payment metadata'): CardChecks | null {
    if (!metadata || typeof metadata !== 'object') return null;
    const m = metadata;
    const out: CardChecks = { source: typeof m.avs?.source === 'string' ? m.avs.source : source };

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
            if (postalCode) out.postalCode = postalCode;
            if (line1) out.line1 = line1;
            break;
        }
    }

    const riskLevel = parseRiskLevel(
        m.avs?.riskLevel ?? m.card?.riskLevel ?? m.radarRiskLevel ?? m.risk_level ?? m.outcome?.risk_level,
    );
    if (riskLevel) out.riskLevel = riskLevel;
    const riskScoreRaw = m.avs?.riskScore ?? m.card?.riskScore ?? m.radarRiskScore ?? m.risk_score ?? m.outcome?.risk_score;
    if (riskScoreRaw != null && Number.isFinite(Number(riskScoreRaw))) out.riskScore = Number(riskScoreRaw);

    const tdsAuth = parseThreeDsAuthenticated(
        m.avs?.threeDsAuthenticated ?? m.card?.threeDsAuthenticated ?? m.threeDsAuthenticated
            ?? m.three_d_secure?.authenticated ?? m.threeDSecure?.authenticated,
    );
    if (tdsAuth !== null) out.threeDsAuthenticated = tdsAuth;
    const tdsResult = m.avs?.threeDsResult ?? m.card?.threeDsResult ?? m.threeDsResult
        ?? m.three_d_secure?.result ?? m.threeDSecure?.result;
    if (typeof tdsResult === 'string' && tdsResult) out.threeDsResult = tdsResult;

    return hasAnyCheck(out) ? out : null;
}

/** Same reader under the 0.19 name. */
export const cardChecksFromMetadata = avsFromMetadata;

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
 * Fetch the card checks (AVS, Radar risk level, 3DS outcome) for a Stripe
 * PaymentIntent. Uses the platform `fetch` (Node 18+) so the plugin needs
 * no Stripe SDK. Fails open — any error, timeout or non-2xx returns null
 * (and is reported through `opts.log` so key-permission or API-version
 * problems are visible).
 *
 * The request is pinned to STRIPE_API_VERSION so `expand[]=latest_charge`
 * is valid on every account; should the expansion ever be omitted, the
 * charge is fetched by id as a second call.
 */
export async function fetchStripeCardChecks(
    apiKey: string,
    paymentIntentId: string,
    opts: FetchStripeAvsOptions = {},
): Promise<CardChecks | null> {
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
    return cardChecksFromStripeCharge(charge);
}

/** 0.18 name, kept for existing imports. */
export const fetchStripeAvs = fetchStripeCardChecks;

/** Human wording for the signal detail column. */
export function describeAvs(kind: 'postalCode' | 'line1', result: CardChecks): string {
    const what = kind === 'postalCode' ? 'billing postcode' : 'street address';
    const via = result.source ? ` (${result.source})` : '';
    return `Card issuer reports the ${what} does not match the card${via}`;
}

/** Detail wording for the Radar signals. */
export function describeRadar(result: CardChecks): string {
    const score = result.riskScore != null ? `, risk score ${result.riskScore}` : '';
    const via = result.source ? ` (${result.source})` : '';
    return `Stripe Radar rated this charge "${result.riskLevel}"${score}${via}`;
}

/** Detail wording for the 3DS signal. */
export function describeThreeDs(result: CardChecks): string {
    const why = result.threeDsResult ? ` — result "${result.threeDsResult}"` : '';
    const via = result.source ? ` (${result.source})` : '';
    return `3-D Secure ran but the cardholder did not authenticate${why}; liability did not shift to the issuer${via}`;
}

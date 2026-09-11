import { describe, expect, it } from 'vitest';
import {
    avsFromMetadata,
    avsFromStripeCharge,
    cardChecksFromStripeCharge,
    describeAvs,
    describeRadar,
    describeThreeDs,
    fetchStripeAvs,
    fetchStripeCardChecks,
    normalisePostcode,
    parseAvsCheck,
    parseRiskLevel,
    parseThreeDsAuthenticated,
    postcodesDiffer,
    threeDsFailed,
} from './avs';

describe('normalisePostcode / postcodesDiffer', () => {
    it('normalises case, spaces and punctuation', () => {
        expect(normalisePostcode(' sw1a 1aa ')).toBe('SW1A1AA');
        expect(normalisePostcode('SW1A-1AA')).toBe('SW1A1AA');
        expect(normalisePostcode('90210')).toBe('90210');
        expect(normalisePostcode(null)).toBe('');
        expect(normalisePostcode(undefined)).toBe('');
    });
    it('only reports a mismatch when both are present and differ', () => {
        expect(postcodesDiffer('SW1A 1AA', 'sw1a1aa')).toBe(false);
        expect(postcodesDiffer('SW1A 1AA', 'EC1A 1BB')).toBe(true);
        expect(postcodesDiffer('SW1A 1AA', '')).toBe(false);
        expect(postcodesDiffer('', 'EC1A 1BB')).toBe(false);
        expect(postcodesDiffer(undefined, undefined)).toBe(false);
        expect(postcodesDiffer('10115', '10115 ')).toBe(false);
    });
    it('treats a partial form of the same code as a match (ZIP+4, UK outward code)', () => {
        expect(postcodesDiffer('90210', '90210-1234')).toBe(false);
        expect(postcodesDiffer('SW1A', 'SW1A 1AA')).toBe(false);
        expect(postcodesDiffer('SW1A 1AA', 'SW1A 2BB')).toBe(true);
        expect(postcodesDiffer('90210', '90211-1234')).toBe(true);
        expect(postcodesDiffer('S', 'SW1A 1AA')).toBe(true); // too short to be a partial
    });
});

describe('parseAvsCheck', () => {
    it('maps Stripe vocabulary straight through', () => {
        expect(parseAvsCheck('pass')).toBe('pass');
        expect(parseAvsCheck('fail')).toBe('fail');
        expect(parseAvsCheck('unavailable')).toBe('unavailable');
        expect(parseAvsCheck('unchecked')).toBe('unchecked');
    });
    it('maps other gateway spellings and booleans', () => {
        expect(parseAvsCheck('MATCH')).toBe('pass');
        expect(parseAvsCheck('no_match')).toBe('fail');
        expect(parseAvsCheck('Y')).toBe('pass');
        expect(parseAvsCheck('N')).toBe('fail');
        expect(parseAvsCheck('U')).toBe('unavailable');
        expect(parseAvsCheck(true)).toBe('pass');
        expect(parseAvsCheck(false)).toBe('fail');
    });
    it('returns null for unknowns and empties', () => {
        expect(parseAvsCheck(null)).toBeNull();
        expect(parseAvsCheck(undefined)).toBeNull();
        expect(parseAvsCheck('')).toBeNull();
        expect(parseAvsCheck('banana')).toBeNull();
        expect(parseAvsCheck(42)).toBeNull();
    });
});

describe('avsFromStripeCharge', () => {
    it('reads card checks', () => {
        const r = avsFromStripeCharge({
            payment_method_details: { card: { checks: { address_line1_check: 'pass', address_postal_code_check: 'fail', cvc_check: 'pass' } } },
        });
        expect(r).toEqual({ source: 'stripe', postalCode: 'fail', line1: 'pass' });
    });
    it('returns null when checks are absent or all null (non-card or not checked)', () => {
        expect(avsFromStripeCharge(null)).toBeNull();
        expect(avsFromStripeCharge({})).toBeNull();
        expect(avsFromStripeCharge({ payment_method_details: { paypal: {} } })).toBeNull();
        expect(avsFromStripeCharge({ payment_method_details: { card: { checks: { address_line1_check: null, address_postal_code_check: null, cvc_check: 'pass' } } } })).toBeNull();
    });
    it('omits the check that was null but keeps the other', () => {
        const r = avsFromStripeCharge({ payment_method_details: { card: { checks: { address_line1_check: null, address_postal_code_check: 'pass' } } } });
        expect(r).toEqual({ source: 'stripe', postalCode: 'pass' });
    });
});

describe('avsFromMetadata', () => {
    it('reads the canonical avs object', () => {
        expect(avsFromMetadata({ paymentIntentId: 'pi_1', avs: { postalCode: 'fail', line1: 'pass' } }))
            .toEqual({ source: 'payment metadata', postalCode: 'fail', line1: 'pass' });
    });
    it('honours a source inside the avs object', () => {
        expect(avsFromMetadata({ avs: { postalCode: 'N', source: 'worldpay' } }))
            .toEqual({ source: 'worldpay', postalCode: 'fail' });
    });
    it('reads snake_case, Stripe checks and flat keys', () => {
        expect(avsFromMetadata({ avs: { postal_code: 'match', address_line1: 'no_match' } }))
            .toEqual({ source: 'payment metadata', postalCode: 'pass', line1: 'fail' });
        expect(avsFromMetadata({ checks: { address_postal_code_check: 'fail' } }))
            .toEqual({ source: 'payment metadata', postalCode: 'fail' });
        expect(avsFromMetadata({ address_postal_code_check: 'pass', address_line1_check: 'fail' }))
            .toEqual({ source: 'payment metadata', postalCode: 'pass', line1: 'fail' });
        expect(avsFromMetadata({ avsPostalCode: 'fail' }))
            .toEqual({ source: 'payment metadata', postalCode: 'fail' });
    });
    it('returns null for Vendure StripePlugin metadata (no checks stored) and junk', () => {
        expect(avsFromMetadata({ paymentIntentAmountReceived: 1000, paymentIntentId: 'pi_1' })).toBeNull();
        expect(avsFromMetadata(null)).toBeNull();
        expect(avsFromMetadata('avs')).toBeNull();
        expect(avsFromMetadata({ avs: { postalCode: 'weird' } })).toBeNull();
    });
});

describe('fetchStripeAvs', () => {
    const okResponse = (body: any) => ({ ok: true, status: 200, json: async () => body });

    it('expands latest_charge, sends the bearer key and parses the checks', async () => {
        const calls: any[] = [];
        const fetchImpl = async (url: string, init: any) => {
            calls.push({ url, init });
            return okResponse({
                id: 'pi_123', latest_charge: { payment_method_details: { card: { checks: { address_postal_code_check: 'fail', address_line1_check: 'unavailable' } } } },
            });
        };
        const r = await fetchStripeAvs('sk_test_abc', 'pi_123', { fetchImpl });
        expect(r).toEqual({ source: 'stripe', postalCode: 'fail', line1: 'unavailable' });
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe('https://api.stripe.com/v1/payment_intents/pi_123?expand[]=latest_charge');
        expect(calls[0].init.headers.Authorization).toBe('Bearer sk_test_abc');
        expect(calls[0].init.headers['Stripe-Version']).toBe('2022-11-15');
        expect(calls[0].init.method).toBe('GET');
    });

    it('fetches the charge by id when latest_charge was not expanded', async () => {
        const urls: string[] = [];
        const fetchImpl = async (url: string) => {
            urls.push(url);
            if (url.includes('/charges/ch_9')) return okResponse({ id: 'ch_9', payment_method_details: { card: { checks: { address_line1_check: 'fail' } } } });
            return okResponse({ id: 'pi_1', latest_charge: 'ch_9' });
        };
        expect(await fetchStripeAvs('sk', 'pi_1', { fetchImpl })).toEqual({ source: 'stripe', line1: 'fail' });
        expect(urls[1]).toBe('https://api.stripe.com/v1/charges/ch_9');
    });

    it('fails open on HTTP errors, thrown errors, timeouts and bad ids — and reports why', async () => {
        const logs: string[] = [];
        const log = (m: string) => logs.push(m);
        expect(await fetchStripeAvs('sk', 'pi_1', { log, fetchImpl: async () => ({ ok: false, status: 401, json: async () => ({}) }) })).toBeNull();
        expect(logs.pop()).toMatch(/HTTP 401/);
        expect(await fetchStripeAvs('sk', 'pi_1', { log, fetchImpl: async () => { throw new Error('boom'); } })).toBeNull();
        expect(logs.pop()).toMatch(/boom/);
        expect(await fetchStripeAvs('sk', 'pi_1', { log, fetchImpl: () => new Promise(() => {}), timeoutMs: 20 })).toBeNull();
        expect(logs.pop()).toMatch(/timed out/);
        expect(await fetchStripeAvs('sk', 'pi_1', { log, fetchImpl: async () => okResponse({ id: 'pi_1', status: 'requires_payment_method' }) })).toBeNull();
        expect(logs.pop()).toMatch(/No charge found/);
        expect(await fetchStripeAvs('sk', 'not-a-pi', { fetchImpl: async () => okResponse({}) })).toBeNull();
        expect(await fetchStripeAvs('', 'pi_1', { fetchImpl: async () => okResponse({}) })).toBeNull();
    });

    it('never calls the network for a non-card charge and returns null', async () => {
        const fetchImpl = async () => okResponse({ id: 'pi_1', latest_charge: { payment_method_details: { paypal: {} } } });
        expect(await fetchStripeAvs('sk', 'pi_1', { fetchImpl })).toBeNull();
    });
});

describe('parseRiskLevel / parseThreeDsAuthenticated', () => {
    it('maps Radar vocabulary and common spellings', () => {
        expect(parseRiskLevel('normal')).toBe('normal');
        expect(parseRiskLevel('Elevated')).toBe('elevated');
        expect(parseRiskLevel('HIGHEST')).toBe('highest');
        expect(parseRiskLevel('not_assessed')).toBe('not_assessed');
        expect(parseRiskLevel('not assessed')).toBe('not_assessed');
        expect(parseRiskLevel('high')).toBe('highest');
        expect(parseRiskLevel('unknown')).toBe('unknown');
        expect(parseRiskLevel(null)).toBeNull();
        expect(parseRiskLevel('')).toBeNull();
        expect(parseRiskLevel('banana')).toBeNull();
    });
    it('reads the 3DS authenticated flag from booleans and strings', () => {
        expect(parseThreeDsAuthenticated(true)).toBe(true);
        expect(parseThreeDsAuthenticated(false)).toBe(false);
        expect(parseThreeDsAuthenticated('false')).toBe(false);
        expect(parseThreeDsAuthenticated('authenticated')).toBe(true);
        expect(parseThreeDsAuthenticated(undefined)).toBeNull();
        expect(parseThreeDsAuthenticated('maybe')).toBeNull();
    });
});

describe('threeDsFailed', () => {
    it('is true only when 3DS ran and did not authenticate', () => {
        expect(threeDsFailed({ threeDsAuthenticated: false })).toBe(true);
        expect(threeDsFailed({ threeDsAuthenticated: false, threeDsResult: 'failed' })).toBe(true);
        expect(threeDsFailed({ threeDsAuthenticated: false, threeDsResult: 'processing_error' })).toBe(true);
        expect(threeDsFailed({ threeDsAuthenticated: true })).toBe(false);
        expect(threeDsFailed({})).toBe(false);
        expect(threeDsFailed(null)).toBe(false);
        expect(threeDsFailed(undefined)).toBe(false);
    });
    it('treats attempt-acknowledged, exempted and not-enrolled cards as benign', () => {
        expect(threeDsFailed({ threeDsAuthenticated: false, threeDsResult: 'attempt_acknowledged' })).toBe(false);
        expect(threeDsFailed({ threeDsAuthenticated: false, threeDsResult: 'exempted' })).toBe(false);
        expect(threeDsFailed({ threeDsAuthenticated: false, threeDsResult: 'not_supported' })).toBe(false);
    });
});

describe('cardChecksFromStripeCharge (Radar + 3DS)', () => {
    it('is the same function as avsFromStripeCharge', () => {
        expect(cardChecksFromStripeCharge).toBe(avsFromStripeCharge);
        expect(fetchStripeCardChecks).toBe(fetchStripeAvs);
    });
    it('reads outcome.risk_level and risk_score alongside the AVS checks', () => {
        const r = cardChecksFromStripeCharge({
            outcome: { network_status: 'approved_by_network', risk_level: 'elevated', risk_score: 71, type: 'authorized' },
            payment_method_details: { card: { checks: { address_postal_code_check: 'pass', address_line1_check: null } } },
        });
        expect(r).toEqual({ source: 'stripe', postalCode: 'pass', riskLevel: 'elevated', riskScore: 71 });
    });
    it('returns Radar / 3DS verdicts even when no AVS check ran (wallet payments)', () => {
        const r = cardChecksFromStripeCharge({
            outcome: { risk_level: 'highest' },
            payment_method_details: { card: { checks: { address_postal_code_check: null, address_line1_check: null }, wallet: { type: 'apple_pay' } } },
        });
        expect(r).toEqual({ source: 'stripe', riskLevel: 'highest' });
        const tds = cardChecksFromStripeCharge({
            payment_method_details: { card: { three_d_secure: { authenticated: false, succeeded: false, result: 'failed', version: '2.2.0' } } },
        });
        expect(tds).toEqual({ source: 'stripe', threeDsAuthenticated: false, threeDsResult: 'failed' });
        expect(threeDsFailed(tds)).toBe(true);
    });
    it('ignores an unrecognised risk level and a missing risk score', () => {
        const r = cardChecksFromStripeCharge({
            outcome: { risk_level: 'banana' },
            payment_method_details: { card: { checks: { address_line1_check: 'fail' } } },
        });
        expect(r).toEqual({ source: 'stripe', line1: 'fail' });
    });
    it('still returns null when nothing at all was checked', () => {
        expect(cardChecksFromStripeCharge({ outcome: { network_status: 'approved_by_network' }, payment_method_details: { card: {} } })).toBeNull();
        expect(cardChecksFromStripeCharge({ payment_method_details: { paypal: {} }, outcome: {} })).toBeNull();
    });
});

describe('avsFromMetadata (Radar + 3DS)', () => {
    it('reads riskLevel / threeDs from the canonical avs object and flat keys', () => {
        expect(avsFromMetadata({ avs: { postalCode: 'fail', riskLevel: 'highest', threeDsAuthenticated: false, threeDsResult: 'failed', source: 'adyen' } }))
            .toEqual({ source: 'adyen', postalCode: 'fail', riskLevel: 'highest', threeDsAuthenticated: false, threeDsResult: 'failed' });
        expect(avsFromMetadata({ radarRiskLevel: 'elevated' })).toEqual({ source: 'payment metadata', riskLevel: 'elevated' });
        expect(avsFromMetadata({ outcome: { risk_level: 'normal', risk_score: 12 }, three_d_secure: { authenticated: true } }))
            .toEqual({ source: 'payment metadata', riskLevel: 'normal', riskScore: 12, threeDsAuthenticated: true });
        expect(avsFromMetadata({ card: { threeDsAuthenticated: 'false' } }))
            .toEqual({ source: 'payment metadata', threeDsAuthenticated: false });
    });
});

describe('fetchStripeCardChecks', () => {
    it('returns Radar and 3DS data from the expanded charge', async () => {
        const fetchImpl = async () => ({ ok: true, status: 200, json: async () => ({
            id: 'pi_1',
            latest_charge: {
                outcome: { risk_level: 'highest', risk_score: 93 },
                payment_method_details: { card: { checks: { address_postal_code_check: 'fail' }, three_d_secure: { authenticated: false, result: 'failed' } } },
            },
        }) });
        expect(await fetchStripeCardChecks('sk', 'pi_1', { fetchImpl })).toEqual({
            source: 'stripe', postalCode: 'fail', riskLevel: 'highest', riskScore: 93, threeDsAuthenticated: false, threeDsResult: 'failed',
        });
    });
});

describe('describeRadar / describeThreeDs', () => {
    it('names the verdict, the score and the source', () => {
        expect(describeRadar({ riskLevel: 'highest', riskScore: 93, source: 'stripe' }))
            .toBe('Stripe Radar rated this charge "highest", risk score 93 (stripe)');
        expect(describeRadar({ riskLevel: 'elevated' }))
            .toBe('Stripe Radar rated this charge "elevated"');
        expect(describeThreeDs({ threeDsAuthenticated: false, threeDsResult: 'failed', source: 'stripe' }))
            .toBe('3-D Secure ran but the cardholder did not authenticate — result "failed"; liability did not shift to the issuer (stripe)');
        expect(describeThreeDs({ threeDsAuthenticated: false }))
            .toBe('3-D Secure ran but the cardholder did not authenticate; liability did not shift to the issuer');
    });
});

describe('describeAvs', () => {
    it('names the check and the source', () => {
        expect(describeAvs('postalCode', { postalCode: 'fail', source: 'stripe' }))
            .toBe('Card issuer reports the billing postcode does not match the card (stripe)');
        expect(describeAvs('line1', { line1: 'fail' }))
            .toBe('Card issuer reports the street address does not match the card');
    });
});

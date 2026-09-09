import { describe, expect, it } from 'vitest';
import {
    avsFromMetadata,
    avsFromStripeCharge,
    describeAvs,
    fetchStripeAvs,
    normalisePostcode,
    parseAvsCheck,
    postcodesDiffer,
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

describe('describeAvs', () => {
    it('names the check and the source', () => {
        expect(describeAvs('postalCode', { postalCode: 'fail', source: 'stripe' }))
            .toBe('Card issuer reports the billing postcode does not match the card (stripe)');
        expect(describeAvs('line1', { line1: 'fail' }))
            .toBe('Card issuer reports the street address does not match the card');
    });
});

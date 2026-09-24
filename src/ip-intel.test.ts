import { describe, it, expect, beforeEach } from 'vitest';
import { lookupIpIntel, _resetIpIntelState } from './ip-intel';

describe('lookupIpIntel guards', () => {
    beforeEach(() => _resetIpIntelState());

    it('rejects non-addresses without a network call', async () => {
        const r = await lookupIpIntel('not-an-ip');
        expect(r.resolved).toBe(false);
    });

    it('accepts IPv6 syntactically (does not short-circuit on the v4 regex)', async () => {
        // With a 1 ms timeout the lookup fails open quickly; the point is that it was attempted.
        const r = await lookupIpIntel('2a06:98c0:3600::103', 1);
        expect(r.ip).toBe('2a06:98c0:3600::103');
        expect(r.resolved).toBe(false);
    });

    it('remembers a failed lookup so the next call returns at once', async () => {
        const t0 = Date.now();
        await lookupIpIntel('203.0.113.77', 1);   // fails (timeout) and is negatively cached
        const t1 = Date.now();
        await lookupIpIntel('203.0.113.77', 4000); // must not wait for the network again
        expect(Date.now() - t1).toBeLessThan(50);
        expect(t1 - t0).toBeLessThan(2000);
    });
});

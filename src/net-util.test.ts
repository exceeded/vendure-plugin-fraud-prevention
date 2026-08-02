import { describe, expect, it } from 'vitest';
import { ipInCidr, ipv4ToInt, normalizeEmail } from './net-util';

describe('ipv4ToInt', () => {
    it('parses valid addresses', () => {
        expect(ipv4ToInt('0.0.0.0')).toBe(0);
        expect(ipv4ToInt('255.255.255.255')).toBe(0xffffffff);
        expect(ipv4ToInt('1.2.3.4')).toBe((1 << 24) + (2 << 16) + (3 << 8) + 4);
    });
    it('rejects garbage', () => {
        expect(ipv4ToInt('256.1.1.1')).toBeNull();
        expect(ipv4ToInt('1.2.3')).toBeNull();
        expect(ipv4ToInt('::1')).toBeNull();
        expect(ipv4ToInt('')).toBeNull();
    });
});

describe('ipInCidr', () => {
    it('matches inside the range', () => {
        expect(ipInCidr('192.168.1.55', '192.168.1.0/24')).toBe(true);
        expect(ipInCidr('10.5.0.1', '10.0.0.0/8')).toBe(true);
        expect(ipInCidr('1.2.3.4', '1.2.3.4')).toBe(true); // bare IP = /32
        expect(ipInCidr('1.2.3.4', '0.0.0.0/0')).toBe(true);
    });
    it('rejects outside the range', () => {
        expect(ipInCidr('192.168.2.1', '192.168.1.0/24')).toBe(false);
        expect(ipInCidr('11.0.0.1', '10.0.0.0/8')).toBe(false);
        expect(ipInCidr('1.2.3.5', '1.2.3.4')).toBe(false);
    });
    it('handles Spamhaus-style ranges', () => {
        expect(ipInCidr('223.254.0.99', '223.254.0.0/16')).toBe(true);
    });
    it('rejects malformed input without throwing', () => {
        expect(ipInCidr('1.2.3.4', 'not-a-cidr')).toBe(false);
        expect(ipInCidr('bad', '10.0.0.0/8')).toBe(false);
        expect(ipInCidr('1.2.3.4', '10.0.0.0/33')).toBe(false);
    });
});

describe('normalizeEmail', () => {
    it('lowercases + extracts domain', () => {
        const n = normalizeEmail('User@Example.COM')!;
        expect(n.email).toBe('user@example.com');
        expect(n.domain).toBe('example.com');
        expect(n.canonical).toBe('user@example.com');
        expect(n.usedPlusAddressing).toBe(false);
    });
    it('strips plus tags to a canonical identity', () => {
        const n = normalizeEmail('fraudster+7@gmail.com')!;
        expect(n.canonical).toBe('fraudster@gmail.com');
        expect(n.usedPlusAddressing).toBe(true);
    });
    it('strips gmail dots but not other domains', () => {
        expect(normalizeEmail('f.r.a.u.d@gmail.com')!.canonical).toBe('fraud@gmail.com');
        expect(normalizeEmail('f.r@company.co.uk')!.canonical).toBe('f.r@company.co.uk');
    });
    it('rejects malformed addresses', () => {
        expect(normalizeEmail('nope')).toBeNull();
        expect(normalizeEmail('@nope.com')).toBeNull();
        expect(normalizeEmail('x@')).toBeNull();
    });
});

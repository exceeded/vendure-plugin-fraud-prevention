import { describe, expect, it } from 'vitest';
import { ipInCidr, ipv4ToInt, isCidr, normalizeEmail, parseCidr } from './net-util';

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

import { looksGibberish } from './ip-intel';

describe('looksGibberish', () => {
    it('flags digit-heavy locals', () => {
        expect(looksGibberish('xk492811')).toBe(true);
        expect(looksGibberish('9284712x')).toBe(true);
    });
    it('flags long consonant runs', () => {
        expect(looksGibberish('asdkjhqwrtz')).toBe(true);
    });
    it('passes normal names', () => {
        expect(looksGibberish('wayne.garrison')).toBe(false);
        expect(looksGibberish('chris.wiles')).toBe(false);
        expect(looksGibberish('sales')).toBe(false);
        expect(looksGibberish('john1985')).toBe(false);
    });
});

import { renderTemplate, textToHtml, DEFAULT_TEMPLATES } from './templates';

describe('renderTemplate', () => {
    it('substitutes variables', () => {
        expect(renderTemplate('Hi {{firstName}}, order {{orderCode}}', { firstName: 'Sam', orderCode: 'ABC' }))
            .toBe('Hi Sam, order ABC');
    });
    it('renders unknown/missing vars as empty', () => {
        expect(renderTemplate('x{{nope}}y', {})).toBe('xy');
    });
    it('default templates carry all their variables', () => {
        for (const t of Object.values(DEFAULT_TEMPLATES)) {
            const out = renderTemplate(t.body, { firstName: 'A', orderCode: 'B', supportEmail: 'c@d.e', reviewHours: 24 });
            expect(out).not.toMatch(/\{\{/);
        }
    });
});

describe('textToHtml', () => {
    it('escapes HTML and makes paragraphs', () => {
        const html = textToHtml('para one <script>\n\npara two');
        expect(html).toContain('&lt;script&gt;');
        expect((html.match(/<p /g) || []).length).toBe(2);
    });
});

import { renderBody, looksLikeHtml } from './templates';

describe('renderBody (HTML-aware)', () => {
    it('wraps plain text into paragraphs', () => {
        const out = renderBody('line one\n\nline two');
        expect((out.match(/<p /g) || []).length).toBe(2);
    });
    it('passes HTML through untouched', () => {
        const html = '<p style="color:red">Hi <a href="{{reviewUrl}}">link</a></p>';
        expect(renderBody(html)).toBe(html);
    });
    it('looksLikeHtml detects tags', () => {
        expect(looksLikeHtml('<div>x</div>')).toBe(true);
        expect(looksLikeHtml('just text')).toBe(false);
    });
});

import { normaliseIp } from './net-util';

describe('normaliseIp', () => {
    it('unwraps IPv4-mapped IPv6 addresses and trims', () => {
        expect(normaliseIp('::ffff:203.0.113.9')).toBe('203.0.113.9');
        expect(normaliseIp('  203.0.113.9 ')).toBe('203.0.113.9');
        expect(normaliseIp('2A06:98C0:3600::103')).toBe('2a06:98c0:3600::103');
        expect(normaliseIp(undefined)).toBe('');
    });
});

describe('ipInCidr (IPv6)', () => {
    it('matches a /64 and a /32 prefix', () => {
        expect(ipInCidr('2001:db8:abcd:1234:ffff:ffff:ffff:ffff', '2001:db8:abcd:1234::/64')).toBe(true);
        expect(ipInCidr('2001:db8:abcd:1235::1', '2001:db8:abcd:1234::/64')).toBe(false);
        expect(ipInCidr('2001:db8::1', '2001:db8::/32')).toBe(true);
        expect(ipInCidr('2001:db9::1', '2001:db8::/32')).toBe(false);
    });
    it('a bare address is a /128 and compression does not matter', () => {
        expect(ipInCidr('2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(true);
        expect(ipInCidr('2001:db8::1', '2001:db8::1/128')).toBe(true);
        expect(ipInCidr('2001:db8::2', '2001:db8::1/128')).toBe(false);
        expect(ipInCidr('2001:DB8::1%eth0', '2001:db8::/48')).toBe(true);
        expect(ipInCidr('[2001:db8::1]', '2001:db8::/48')).toBe(true);
    });
    it('::/0 matches everything', () => {
        expect(ipInCidr('fe80::1', '::/0')).toBe(true);
        expect(ipInCidr('1.2.3.4', '::/0')).toBe(true);
    });
    it('IPv4-mapped addresses match IPv4 ranges and IPv4 clients match mapped ranges', () => {
        expect(ipInCidr('::ffff:192.168.1.55', '192.168.1.0/24')).toBe(true);
        expect(ipInCidr('::ffff:192.168.2.55', '192.168.1.0/24')).toBe(false);
        expect(ipInCidr('192.168.1.55', '::ffff:192.168.1.0/120')).toBe(true);
        expect(ipInCidr('192.168.2.55', '::ffff:192.168.1.0/120')).toBe(false);
        expect(ipInCidr('::ffff:c0a8:137', '::ffff:192.168.1.0/120')).toBe(true);
        expect(ipInCidr('192.168.1.55', '::ffff:192.168.1.55')).toBe(true);
    });
    it('rejects malformed entries without throwing', () => {
        expect(ipInCidr('2001:db8::1', '2001:db8::/129')).toBe(false);
        expect(ipInCidr('2001:db8::1', '2001:db8::/-1')).toBe(false);
        expect(ipInCidr('2001:db8::1', '2001:db8:::/64')).toBe(false);
        expect(ipInCidr('2001:db8::1', '2001:db8::1::/64')).toBe(false);
        expect(ipInCidr('2001:db8::1', '2001:db8:gggg::/64')).toBe(false);
        expect(ipInCidr('2001:db8::1', '1:2:3:4:5:6:7:8:9/64')).toBe(false);
        expect(ipInCidr('2001:db8::1', '1:2:3:4:5:6:7/64')).toBe(false);
        expect(ipInCidr('2001:db8::1', '2001:db8::/64/1')).toBe(false);
        expect(ipInCidr('2001:db8::1', '10.0.0.0/8')).toBe(false);
        expect(ipInCidr('not-an-ip', '2001:db8::/32')).toBe(false);
        expect(ipInCidr('', '')).toBe(false);
    });
});

describe('isCidr / parseCidr', () => {
    it('accepts IPv4 and IPv6 ranges and bare addresses', () => {
        expect(isCidr('203.0.113.0/24')).toBe(true);
        expect(isCidr('203.0.113.9')).toBe(true);
        expect(isCidr('2001:db8::/32')).toBe(true);
        expect(isCidr('::ffff:203.0.113.0/120')).toBe(true);
        expect(parseCidr('2001:db8::/32')).toEqual({ family: 6, base: BigInt('0x20010db8') << BigInt(96), bits: 32 });
        expect(parseCidr('10.0.0.0/8')).toEqual({ family: 4, base: 10 << 24, bits: 8 });
    });
    it('rejects malformed ranges', () => {
        for (const bad of ['', '/24', '10.0.0.0/33', '10.0.0.0/8/1', '2001:db8::/129', '2001:db8::/x', 'example.com', '1.2.3', '2001:db8:::1'])
            expect(isCidr(bad), bad).toBe(false);
    });
});

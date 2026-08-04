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

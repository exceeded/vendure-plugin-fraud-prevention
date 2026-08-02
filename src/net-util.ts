/**
 * Small pure helpers: CIDR matching for IPv4 blocklist ranges (Spamhaus
 * DROP ships ranges, and the previous implementation never matched them
 * at all) and email normalisation for plus-addressing / dot-trick
 * detection.
 */

export function ipv4ToInt(ip: string): number | null {
    const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const parts = m.slice(1).map(Number);
    if (parts.some(p => p > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/** True when `ip` (IPv4) falls inside `cidr` ("1.2.3.0/24" or bare IP). */
export function ipInCidr(ip: string, cidr: string): boolean {
    const [base, bitsRaw] = cidr.trim().split('/');
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(base);
    if (ipInt == null || baseInt == null) return false;
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
}

export interface NormalizedEmail {
    /** Lowercased original. */
    email: string;
    domain: string;
    /** Canonical form: gmail dots stripped, +tag removed — the identity a
     *  fraudster can't multiply by re-tagging one inbox. */
    canonical: string;
    usedPlusAddressing: boolean;
}

const DOT_INSENSITIVE_DOMAINS = new Set(['gmail.com', 'googlemail.com']);

export function normalizeEmail(raw: string): NormalizedEmail | null {
    const email = (raw || '').trim().toLowerCase();
    const at = email.lastIndexOf('@');
    if (at <= 0 || at === email.length - 1) return null;
    let local = email.slice(0, at);
    const domain = email.slice(at + 1);
    const usedPlusAddressing = local.includes('+');
    if (usedPlusAddressing) local = local.split('+')[0];
    if (DOT_INSENSITIVE_DOMAINS.has(domain)) local = local.replace(/\./g, '');
    return { email, domain, canonical: `${local}@${domain}`, usedPlusAddressing };
}

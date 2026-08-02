import * as http from 'http';
import { Logger } from '@vendure/core';

const loggerCtx = 'FraudPrevention';

export interface IpIntel {
    ip: string;
    countryCode: string | null;
    isVpnOrProxy: boolean;
    isHosting: boolean;
    /** False when the lookup failed — callers must fail open. */
    resolved: boolean;
}

/**
 * IP intelligence via ip-api.com (free tier: HTTP only, 45 req/min).
 * Results are cached by the service in `fraud_ip_intel` for 30 days, so
 * the rate limit only matters for genuinely new IPs. Lookups fail OPEN:
 * a timeout or rate-limit never adds points and never blocks an order.
 */
export function lookupIpIntel(ip: string, timeoutMs = 4000): Promise<IpIntel> {
    const empty: IpIntel = { ip, countryCode: null, isVpnOrProxy: false, isHosting: false, resolved: false };
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return Promise.resolve(empty);
    return new Promise(resolve => {
        const req = http.get(
            `http://ip-api.com/json/${ip}?fields=status,countryCode,proxy,hosting`,
            { timeout: timeoutMs },
            res => {
                let data = '';
                res.on('data', c => (data += c));
                res.on('end', () => {
                    try {
                        const j = JSON.parse(data);
                        if (j.status !== 'success') return resolve(empty);
                        resolve({
                            ip,
                            countryCode: j.countryCode || null,
                            isVpnOrProxy: !!j.proxy,
                            isHosting: !!j.hosting,
                            resolved: true,
                        });
                    } catch {
                        resolve(empty);
                    }
                });
            },
        );
        req.on('error', e => {
            Logger.debug(`ip-intel lookup failed for ${ip}: ${e.message}`, loggerCtx);
            resolve(empty);
        });
        req.on('timeout', () => { req.destroy(); resolve(empty); });
    });
}

// ── Email MX validation ─────────────────────────────────────────────
// A domain with no MX records can't receive the licence-key email —
// classic throwaway checkout address. In-memory cache with 24h TTL;
// DNS failures (as opposed to authoritative empty answers) fail open.

const mxCache = new Map<string, { hasMx: boolean; at: number }>();
const MX_TTL = 24 * 3600 * 1000;

export async function domainHasMx(domain: string, timeoutMs = 3000): Promise<boolean | null> {
    const hit = mxCache.get(domain);
    if (hit && Date.now() - hit.at < MX_TTL) return hit.hasMx;
    try {
        const dns = await import('dns');
        const records = await Promise.race([
            dns.promises.resolveMx(domain),
            new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), timeoutMs)),
        ]);
        const hasMx = Array.isArray(records) && records.length > 0;
        mxCache.set(domain, { hasMx, at: Date.now() });
        if (mxCache.size > 10_000) mxCache.delete(mxCache.keys().next().value as string);
        return hasMx;
    } catch (e: any) {
        // ENOTFOUND / ENODATA are authoritative "this domain can't receive
        // mail"; anything else (timeout, SERVFAIL) is unknown -> fail open.
        if (e?.code === 'ENOTFOUND' || e?.code === 'ENODATA') {
            mxCache.set(domain, { hasMx: false, at: Date.now() });
            return false;
        }
        return null;
    }
}

/** Heuristic for keyboard-mash local parts (xk49281@, asdkjhqw@).
 *  Deliberately weak on its own — it only matters in combination. */
export function looksGibberish(localPart: string): boolean {
    const lp = localPart.toLowerCase().replace(/[._-]/g, '');
    if (lp.length < 6) return false;
    // 0.6 not 0.5 — "john1985"-style birth-year suffixes are normal and
    // sit exactly at half digits.
    const digits = (lp.match(/\d/g) || []).length;
    if (digits / lp.length >= 0.6) return true;
    const consonantRun = lp.match(/[bcdfghjklmnpqrstvwxz]{6,}/);
    return !!consonantRun;
}

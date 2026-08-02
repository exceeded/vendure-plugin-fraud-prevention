import { mergeConfig } from '@vendure/core';
import { createTestEnvironment, registerInitializer, MysqlInitializer, testConfig } from '@vendure/testing';
import { initialData } from '../../../e2e-shared/initial-data';
import { FraudPreventionPlugin } from '../src/plugin';
import { FraudPreventionService } from '../src/fraud-prevention.service';

/**
 * Fraud-prevention targets MySQL / MariaDB (its risk queries use
 * DATE_SUB / INTERVAL and the schema uses ENUM + ADD COLUMN IF NOT
 * EXISTS), so this suite runs against a real MariaDB — the same dialect
 * production uses — rather than the sql.js harness the other plugins use.
 *
 * It is SKIPPED unless MySQL creds are provided via env, so it never
 * ships secrets and never fails on a machine without a database:
 *   FP_E2E_DB_HOST FP_E2E_DB_PORT FP_E2E_DB_USER FP_E2E_DB_PASS
 */
const DB = process.env.FP_E2E_DB_HOST
    ? {
          host: process.env.FP_E2E_DB_HOST,
          port: Number(process.env.FP_E2E_DB_PORT || 3306),
          username: process.env.FP_E2E_DB_USER || 'root',
          password: process.env.FP_E2E_DB_PASS || '',
      }
    : null;

const PORT = 3063;
const BASE = `http://localhost:${PORT}`;
const run = DB ? describe : describe.skip;

run('@huloglobal/vendure-plugin-fraud-prevention (MariaDB)', () => {
    registerInitializer('mysql', new MysqlInitializer());

    const config = mergeConfig(testConfig, {
        apiOptions: { port: PORT },
        dbConnectionOptions: {
            type: 'mysql' as const,
            host: DB!.host,
            port: DB!.port,
            username: DB!.username,
            password: DB!.password,
            database: 'hulo_fp_e2e',
            synchronize: true,
        },
        // The plugin reads the client IP from Order.customFields.ip — the
        // host is responsible for declaring + populating it (documented in
        // the README). Register it here as a host would.
        customFields: {
            Order: [{ name: 'ip', type: 'string' as const, nullable: true }],
        },
        plugins: [
            FraudPreventionPlugin.init({ publicBaseUrl: BASE, defaultAdminEmail: 'ops@test.local' }),
        ],
    });
    const { server } = createTestEnvironment(config);

    beforeAll(async () => {
        await server.init({ initialData, productsCsvPath: '', customerCount: 0 } as any);
    }, 120_000);

    afterAll(async () => {
        await server.destroy();
    });

    const svc = () => (server as any).app.get(FraudPreventionService) as FraudPreventionService;

    // ── HTTP security contracts ──────────────────────────────────────
    it('admin endpoints reject anonymous callers', async () => {
        for (const p of ['config', 'stats', 'cases', 'log', 'meta', 'notification-config', 'lists/whitelist']) {
            const res = await fetch(`${BASE}/fraud-prevention/${p}`);
            expect([401, 403]).toContain(res.status);
        }
    });

    it('the public /check endpoint answers with a minimal shape', async () => {
        const res = await fetch(`${BASE}/fraud-prevention/check`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ email: 'shopper@example.com', orderValuePence: 5000, channelId: 1 }),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body).toHaveProperty('allowed');
        expect(body).toHaveProperty('riskLevel');
        expect(body).not.toHaveProperty('signals'); // never leak internals publicly
        expect(body).not.toHaveProperty('score');
    });

    it('rate-limits the public /check endpoint', async () => {
        let got429 = false;
        for (let i = 0; i < 75; i++) {
            const res = await fetch(`${BASE}/fraud-prevention/check`, {
                method: 'POST',
                headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.7' },
                body: JSON.stringify({ email: 'x@y.z', orderValuePence: 1, channelId: 1 }),
            });
            if (res.status === 429) { got429 = true; break; }
        }
        expect(got429).toBe(true);
    });

    it('feed sync is not public', async () => {
        const res = await fetch(`${BASE}/fraud-prevention/lists/sync`, {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
        });
        expect([401, 403]).toContain(res.status);
    });

    // ── Assessment engine (real production SQL dialect) ──────────────
    it('a clean order scores low with no signals', async () => {
        const a = await svc().assess({
            channelId: 1, email: 'good.customer@example.com', ip: '203.0.113.10',
            orderValuePence: 2000, dryRun: true,
        });
        expect(a.score).toBe(0);
        expect(a.level).toBe('low');
        expect(a.signals).toHaveLength(0);
        expect(a.action).toBe('allow');
    });

    it('fires the disposable-email signal', async () => {
        const a = await svc().assess({
            channelId: 1, email: 'burner@mailinator.com', ip: '203.0.113.11',
            orderValuePence: 2000, dryRun: true,
        });
        expect(a.signals.some(s => s.key === 'disposable_email')).toBe(true);
        expect(a.score).toBeGreaterThan(0);
    });

    it('fires order_value + new_customer_high_value on a large first order', async () => {
        const a = await svc().assess({
            channelId: 1, email: 'whale@example.com', ip: '203.0.113.12',
            orderValuePence: 900000, countryCode: 'GB', isReturningCustomer: false, dryRun: true,
        });
        const keys = a.signals.map(s => s.key);
        expect(keys).toContain('order_value');
        expect(keys).toContain('new_customer_high_value');
    });

    it('gives trust credit to a returning customer (negative points, floored at 0)', async () => {
        const a = await svc().assess({
            channelId: 1, email: 'loyal@example.com', ip: '203.0.113.13',
            orderValuePence: 2000, isReturningCustomer: true, dryRun: true,
        });
        expect(a.signals.some(s => s.key === 'returning_customer_3plus' && s.points < 0)).toBe(true);
        expect(a.score).toBeGreaterThanOrEqual(0);
    });

    it('never enforces without a licence — a blocklisted order flags, not blocks', async () => {
        await svc().addEntry('blocklist', 'email', 'fraudster@evil.test', 'e2e');
        await svc().saveConfig({
            ...(await svc().getConfig(1)),
            channelId: 1, enabled: true, mode: 'enforce', reviewThreshold: 40, blockThreshold: 70,
        } as any);
        const a = await svc().assess({
            channelId: 1, email: 'fraudster@evil.test', ip: '203.0.113.14',
            orderValuePence: 2000, dryRun: true,
        });
        expect(a.signals.some(s => s.key === 'blocklist_email')).toBe(true);
        expect(a.mode).toBe('monitor'); // licence gate downgraded enforce -> monitor
        expect(a.action).toBe('flag');  // flagged, never blocked, in free tier
    });

    it('allowlist bypasses every check', async () => {
        await svc().addEntry('whitelist', 'email', 'vip@example.com', 'e2e');
        const a = await svc().assess({
            channelId: 1, email: 'vip@example.com', ip: '203.0.113.15',
            orderValuePence: 900000, dryRun: true,
        });
        expect(a.allowlisted).toBe(true);
        expect(a.score).toBe(0);
        expect(a.action).toBe('allow');
    });

    it('CIDR range blocklist matches an IP inside the range', async () => {
        await svc().addEntry('blocklist', 'ip_range', '198.51.100.0/24', 'e2e');
        const a = await svc().assess({
            channelId: 1, email: 'range@example.com', ip: '198.51.100.88',
            orderValuePence: 2000, dryRun: true,
        });
        expect(a.signals.some(s => s.key === 'blocklist_ip_range')).toBe(true);
    });
});

import { LicenceStore, adapterFor, PurchaseClaimClient } from '@huloglobal/vendure-licence-sdk';
import { createHash } from 'crypto';
import { Injectable, OnModuleInit } from '@nestjs/common';
import {
    ID,
    Logger,
    Order,
    OrderService,
    Payment,
    PaymentMethod,
    RequestContext,
    RequestContextService,
    TransactionalConnection,
} from '@vendure/core';
import * as nodemailer from 'nodemailer';
import * as https from 'https';
import * as http from 'http';

import {
    DEFAULT_CONFIG,
    DEFAULT_WEIGHTS,
    FraudAssessment,
    FraudChannelConfig,
    FraudMode,
    FraudPreventionPluginOptions,
    FraudSignal,
    RiskLevel,
} from './types';
import { BUILTIN_DISPOSABLE_DOMAINS, FRAUD_SOURCES } from './fraud-sources';
import { ipInCidr, isCidr, normalizeEmail, normaliseIp } from './net-util';
import {
    CardChecks,
    avsFromMetadata,
    describeAvs,
    describeRadar,
    describeThreeDs,
    fetchStripeCardChecks,
    postcodesDiffer,
    threeDsFailed,
} from './avs';
import { domainHasMx, lookupIpIntel, looksGibberish, IpIntel } from './ip-intel';
import { DEFAULT_TEMPLATES, MessageKind, renderTemplate, renderBody } from './templates';
import { fanOutOpsEvent, OpsEvent } from './ops-notify';

const loggerCtx = 'FraudPrevention';
/** Postgres advisory-lock key for the feed sync (any fixed 64-bit value; 'HULOFEED' as bytes). */
const FEED_SYNC_LOCK_KEY = '5211883387260327236';

export interface AssessInput {
    channelId: number;
    ip?: string;
    email?: string;
    orderValuePence: number;
    countryCode?: string;
    shippingCountryCode?: string;
    /** Typed billing / shipping postcodes — compared when both present. */
    billingPostalCode?: string;
    shippingPostalCode?: string;
    /** Card checks from the gateway — issuer AVS verdicts, Stripe Radar
     *  risk level, 3-D Secure outcome (see resolveAvsForOrder). */
    avs?: CardChecks | null;
    orderId?: number;
    orderCode?: string;
    /** True when this customer has at least one prior settled order. */
    isReturningCustomer?: boolean;
    /** Dry-run: skip logging + case creation (Simulate tab). */
    dryRun?: boolean;
}

export interface ResolveCaseResult {
    ok: boolean;
    message: string;
    caseRow?: any;
    /** Reject only: the order was moved to `Cancelled` (or already was). */
    cancelled?: boolean;
    /** Reject only: the order's state after the decision. */
    orderState?: string;
    /** Reject only: refunds created, in minor units. */
    refunds?: Array<{ paymentId: number; amount: number }>;
    /** Reject only: Vendure-side steps that did not go through. The case
     *  is still closed; an admin should finish these by hand. */
    warnings?: string[];
}

@Injectable()
export class FraudPreventionService implements OnModuleInit {
    private options: FraudPreventionPluginOptions = {};

    constructor(
        private connection: TransactionalConnection,
        private orderService: OrderService,
        private requestContextService: RequestContextService,
    ) {}

    setOptions(opts: FraudPreventionPluginOptions) {
        this.options = opts;
    }
    getOptions(): FraudPreventionPluginOptions {
        return this.options;
    }

    async onModuleInit() {
        try {
            await this.ensureSchema();
        } catch (e: any) {
            Logger.error(`Schema init failed: ${e.message}`, loggerCtx);
        }
    }

    private get db() {
        return adapterFor(this.connection.rawConnection);
    }

    private licenceStore = new LicenceStore((sql, params) => this.db.query(sql, params));

    // Buy-from-admin auto-install (hooks are supplied by the controller so
    // this file never imports the plugin class).
    private purchaseClaim: PurchaseClaimClient | null = null;
    initPurchaseClaim(hooks: { packageName: string; instanceId: () => string | null; onLicence: (key: string) => Promise<boolean> }): PurchaseClaimClient {
        if (!this.purchaseClaim) {
            this.purchaseClaim = new PurchaseClaimClient({ ...hooks, query: (sql, params, opts) => this.db.query(sql, params, opts) });
        }
        return this.purchaseClaim;
    }

    async loadStoredLicenceKey(): Promise<string | null> {
        await this.licenceStore.ensureTable();
        return this.licenceStore.load('vendure-plugin-fraud-prevention');
    }

    async saveStoredLicenceKey(key: string): Promise<void> {
        await this.licenceStore.ensureTable();
        await this.licenceStore.save('vendure-plugin-fraud-prevention', key);
    }

    async clearStoredLicenceKey(): Promise<void> {
        await this.licenceStore.clear('vendure-plugin-fraud-prevention');
    }

    /** Anonymous usage aggregates for the evaluation drip (numbers only). */
    async evalStats(): Promise<Record<string, number>> {
        const [held] = await this.db.query(`SELECT COUNT(*) AS n FROM fraud_blocked_orders`);
        const [blocked] = await this.db.query(`SELECT COUNT(*) AS n FROM fraud_blocked_orders WHERE riskLevel = 'blocked'`);
        return { ordersHeld: Number(held?.n || 0), ordersBlocked: Number(blocked?.n || 0) };
    }

    // ── Schema ──────────────────────────────────────────────────────────
    /**
     * Table names are inherited from the pre-plugin implementation so an
     * upgrade preserves live data (configs, 15k+ feed rows, audit log).
     * New columns arrive via ADD COLUMN IF NOT EXISTS (MariaDB).
     */
    async ensureSchema() {
        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_config (
                channelId INT PRIMARY KEY,
                maxOrdersPerIpPerHour INT DEFAULT 5,
                maxOrdersPerEmailPerDay INT DEFAULT 10,
                maxOrdersPerIpPerDay INT DEFAULT 20,
                maxOrderValuePence INT DEFAULT 500000,
                maxDailyValuePerEmailPence INT DEFAULT 1000000,
                requireEmailVerificationAbovePence INT DEFAULT 100000,
                enforce3dSecure TINYINT DEFAULT 1,
                blockDisposableEmails TINYINT DEFAULT 1,
                blockVpnProxy TINYINT DEFAULT 0,
                blockHighRiskCountries TINYINT DEFAULT 0,
                highRiskCountries TEXT,
                maxFailedPaymentsPerIpPerHour INT DEFAULT 3,
                cooldownMinutesAfterFailedPayment INT DEFAULT 15,
                enabled TINYINT DEFAULT 1
            )`);
        const alters = [
            `ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS mode VARCHAR(16) DEFAULT 'monitor'`,
            `ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS reviewThreshold INT DEFAULT 40`,
            `ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS blockThreshold INT DEFAULT 70`,
            `ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS holdFulfilment TINYINT DEFAULT 1`,
            `ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS signalWeights TEXT`,
            `ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS avsLookup TINYINT DEFAULT 1`,
        ];
        for (const sql of alters) await this.db.query(sql);

        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                channelId INT,
                orderId INT NULL,
                ip VARCHAR(255),
                email VARCHAR(255),
                riskScore INT,
                riskLevel VARCHAR(20),
                reasons TEXT,
                action VARCHAR(50),
                createdAt DATETIME
            )`);
        await this.db.query(`ALTER TABLE fraud_log ADD COLUMN IF NOT EXISTS signals TEXT`);
        await this.db.query(`ALTER TABLE fraud_log ADD COLUMN IF NOT EXISTS orderCode VARCHAR(32) NULL`);
        await this.db.query(`ALTER TABLE fraud_log ADD INDEX IF NOT EXISTS idx_fraud_log_created (createdAt)`);
        // The host fulfilment gate and the order panel look assessments up by order.
        await this.db.query(`ALTER TABLE fraud_log ADD INDEX IF NOT EXISTS idx_fraud_log_order (orderId)`).catch(() => undefined);
        await this.db.query(`ALTER TABLE fraud_log ADD INDEX IF NOT EXISTS idx_fraud_log_channel (channelId, createdAt)`);

        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_blocked_orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                orderId INT,
                channelId INT,
                ip VARCHAR(255),
                email VARCHAR(255),
                riskScore INT,
                reasons TEXT,
                status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                reviewedAt DATETIME NULL,
                reviewNotes TEXT NULL,
                createdAt DATETIME
            )`);
        await this.db.query(`ALTER TABLE fraud_blocked_orders ADD COLUMN IF NOT EXISTS orderCode VARCHAR(32) NULL`);
        await this.db.query(`ALTER TABLE fraud_blocked_orders ADD COLUMN IF NOT EXISTS riskLevel VARCHAR(20) DEFAULT 'review'`);
        await this.db.query(`ALTER TABLE fraud_blocked_orders ADD COLUMN IF NOT EXISTS signals TEXT`);
        await this.db.query(`ALTER TABLE fraud_blocked_orders ADD INDEX IF NOT EXISTS idx_fraud_cases_status (status, createdAt)`);
        await this.db.query(`ALTER TABLE fraud_blocked_orders ADD INDEX IF NOT EXISTS idx_fraud_cases_order (orderId, status)`).catch(() => undefined);

        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_blocklist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                listType VARCHAR(50),
                value VARCHAR(255),
                source VARCHAR(100),
                note VARCHAR(255),
                createdAt DATETIME,
                updatedAt DATETIME,
                INDEX idx_bl_type_value (listType, value)
            )`);
        // Feed replacement deletes by source: without this index the DELETE scanned and
        // locked the whole table and deadlocked against the hot path most nights.
        await this.db.query(`ALTER TABLE fraud_blocklist ADD INDEX IF NOT EXISTS idx_bl_source (source)`).catch(() => undefined);
        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_feed_state (
                source VARCHAR(100) PRIMARY KEY,
                contentHash VARCHAR(64),
                entries INT DEFAULT 0,
                syncedAt DATETIME
            )`);
        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_whitelist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                type VARCHAR(50),
                value VARCHAR(255),
                note VARCHAR(255),
                createdAt DATETIME,
                INDEX idx_wl_type_value (type, value)
            )`);
        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_ip_intel (
                ip VARCHAR(64) PRIMARY KEY,
                countryCode VARCHAR(4) NULL,
                isVpnOrProxy TINYINT DEFAULT 0,
                isHosting TINYINT DEFAULT 0,
                checkedAt DATETIME
            )`);
        await this.db.query(`ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS autoApproveAfterHours INT DEFAULT 0`);
        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_notification_config (
                id INT PRIMARY KEY DEFAULT 1,
                adminEmail VARCHAR(255),
                notifyOnBlocked TINYINT DEFAULT 1,
                notifyOnHighRisk TINYINT DEFAULT 1,
                notifyOnApproval TINYINT DEFAULT 1
            )`);
        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_custom_feed (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(120) NOT NULL,
                url VARCHAR(1024) NOT NULL,
                listType VARCHAR(20) NOT NULL DEFAULT 'ip',
                enabled TINYINT NOT NULL DEFAULT 1,
                lastSyncedAt DATETIME NULL,
                lastCount INT NULL,
                lastError VARCHAR(255) NULL,
                createdAt DATETIME NOT NULL,
                updatedAt DATETIME NOT NULL
            )`);
        await this.db.query(`ALTER TABLE fraud_notification_config ADD COLUMN IF NOT EXISTS slackWebhookUrl VARCHAR(512) NULL`);
        await this.db.query(`ALTER TABLE fraud_notification_config ADD COLUMN IF NOT EXISTS notifyOnRejection TINYINT DEFAULT 1`);
        await this.db.query(`ALTER TABLE fraud_notification_config ADD COLUMN IF NOT EXISTS blocklistOnReject TINYINT DEFAULT 0`);
        for (const col of ['discordWebhookUrl VARCHAR(512)', 'teamsWebhookUrl VARCHAR(512)',
                           'telegramBotToken VARCHAR(128)', 'telegramChatId VARCHAR(64)',
                           'genericWebhookUrl VARCHAR(512)', 'genericWebhookSecret VARCHAR(128)']) {
            await this.db.query(`ALTER TABLE fraud_notification_config ADD COLUMN IF NOT EXISTS ${col} NULL`);
        }
        await this.db.query(`ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS notifyCustomerOnHold VARCHAR(8) DEFAULT 'block'`);
        await this.db.query(`ALTER TABLE fraud_config ADD COLUMN IF NOT EXISTS reviewHours INT DEFAULT 24`);
        await this.db.query(`
            CREATE TABLE IF NOT EXISTS fraud_message_templates (
                channelId INT NOT NULL,
                kind VARCHAR(16) NOT NULL,
                subject VARCHAR(255),
                body TEXT,
                PRIMARY KEY (channelId, kind)
            )`);
        // The failed-payments signal and the overview count Vendure `payment` rows by createdAt, which Vendure
        // never indexes. Best effort: MariaDB (>= 10.1) and Postgres accept IF NOT EXISTS; MySQL 8 does not, so
        // a plain CREATE INDEX is tried once and a duplicate-name error is ignored.
        try {
            await this.db.query(`CREATE INDEX IF NOT EXISTS idx_fp_payment_created ON payment (\`createdAt\`)`);
        } catch (e: any) {
            try {
                await this.db.query(`CREATE INDEX idx_fp_payment_created ON payment (\`createdAt\`)`);
            } catch (e2: any) {
                Logger.debug(`payment(createdAt) index not created: ${e2?.message || e?.message}`, loggerCtx);
            }
        }
    }

    // ── Config ──────────────────────────────────────────────────────────
    private rowToConfig(row: any, channelCode?: string): FraudChannelConfig {
        let weights: Record<string, number> = {};
        try {
            weights = row.signalWeights ? JSON.parse(row.signalWeights) : {};
        } catch { /* corrupted JSON -> defaults */ }
        return {
            channelId: row.channelId,
            channelCode,
            enabled: !!row.enabled,
            mode: (['off', 'monitor', 'enforce'].includes(row.mode) ? row.mode : 'monitor') as FraudMode,
            reviewThreshold: row.reviewThreshold ?? 40,
            blockThreshold: row.blockThreshold ?? 70,
            holdFulfilment: row.holdFulfilment == null ? true : !!row.holdFulfilment,
            maxOrdersPerIpPerHour: row.maxOrdersPerIpPerHour ?? DEFAULT_CONFIG.maxOrdersPerIpPerHour,
            maxOrdersPerIpPerDay: row.maxOrdersPerIpPerDay ?? DEFAULT_CONFIG.maxOrdersPerIpPerDay,
            maxOrdersPerEmailPerDay: row.maxOrdersPerEmailPerDay ?? DEFAULT_CONFIG.maxOrdersPerEmailPerDay,
            maxDailyValuePerEmailPence: row.maxDailyValuePerEmailPence ?? DEFAULT_CONFIG.maxDailyValuePerEmailPence,
            maxOrderValuePence: row.maxOrderValuePence ?? DEFAULT_CONFIG.maxOrderValuePence,
            requireEmailVerificationAbovePence: row.requireEmailVerificationAbovePence ?? DEFAULT_CONFIG.requireEmailVerificationAbovePence,
            blockDisposableEmails: !!row.blockDisposableEmails,
            blockVpnProxy: !!row.blockVpnProxy,
            blockHighRiskCountries: !!row.blockHighRiskCountries,
            highRiskCountries: row.highRiskCountries || '',
            enforce3dSecure: !!row.enforce3dSecure,
            maxFailedPaymentsPerIpPerHour: row.maxFailedPaymentsPerIpPerHour ?? DEFAULT_CONFIG.maxFailedPaymentsPerIpPerHour,
            cooldownMinutesAfterFailedPayment: row.cooldownMinutesAfterFailedPayment ?? DEFAULT_CONFIG.cooldownMinutesAfterFailedPayment,
            avsLookup: row.avsLookup == null ? true : !!row.avsLookup,
            autoApproveAfterHours: row.autoApproveAfterHours ?? 0,
            notifyCustomerOnHold: (['never', 'block', 'always'].includes(row.notifyCustomerOnHold) ? row.notifyCustomerOnHold : 'block'),
            reviewHours: row.reviewHours ?? 24,
            signalWeights: weights,
        };
    }

    async getAllConfigs(): Promise<FraudChannelConfig[]> {
        const channels = await this.db.query(
            `SELECT id AS channelId, code AS channelCode FROM channel ORDER BY id`,
        );
        const rows = await this.db.query(`SELECT * FROM fraud_config`).catch(() => []);
        return channels.map((ch: any) => {
            const existing = rows.find((r: any) => r.channelId === ch.channelId);
            if (existing) return this.rowToConfig(existing, ch.channelCode);
            return { ...DEFAULT_CONFIG, channelId: ch.channelId, channelCode: ch.channelCode };
        });
    }

    /** Small in-process memo for read-mostly rows (config, notification settings, stats). */
    private memo = new Map<string, { at: number; value: any }>();
    private async cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
        const hit = this.memo.get(key);
        if (hit && Date.now() - hit.at < ttlMs) return hit.value as T;
        const value = await fn();
        this.memo.set(key, { at: Date.now(), value });
        return value;
    }
    private forget(prefix: string) { for (const k of this.memo.keys()) if (k.startsWith(prefix)) this.memo.delete(k); }

    async getConfig(channelId: number): Promise<FraudChannelConfig> {
        return this.cached(`config:${channelId}`, 30_000, async () => {
            const rows = await this.db.query(`SELECT * FROM fraud_config WHERE channelId = ?`, [channelId]).catch(() => []);
            if (rows.length) return this.rowToConfig(rows[0]);
            return { ...DEFAULT_CONFIG, channelId };
        });
    }

    async saveConfig(c: FraudChannelConfig): Promise<void> {
        // Bounds: thresholds are percentages and review must not sit above block.
        const num = (v: any, d: number, lo = 0, hi = 1_000_000_000) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };
        c.reviewThreshold = num(c.reviewThreshold, DEFAULT_CONFIG.reviewThreshold, 0, 100);
        c.blockThreshold = num(c.blockThreshold, DEFAULT_CONFIG.blockThreshold, 0, 100);
        if (c.reviewThreshold > c.blockThreshold) c.reviewThreshold = c.blockThreshold;
        for (const k of ['maxOrdersPerIpPerHour', 'maxOrdersPerIpPerDay', 'maxOrdersPerEmailPerDay', 'maxDailyValuePerEmailPence', 'maxOrderValuePence', 'requireEmailVerificationAbovePence', 'maxFailedPaymentsPerIpPerHour', 'cooldownMinutesAfterFailedPayment', 'autoApproveAfterHours'] as const) {
            (c as any)[k] = num((c as any)[k], (DEFAULT_CONFIG as any)[k] ?? 0);
        }
        if (!['off', 'monitor', 'enforce'].includes(String(c.mode))) c.mode = DEFAULT_CONFIG.mode;
        this.forget('config:'); this.forget('stats:');
        await this.db.query(
            `INSERT INTO fraud_config (channelId, enabled, mode, reviewThreshold, blockThreshold, holdFulfilment,
                maxOrdersPerIpPerHour, maxOrdersPerIpPerDay, maxOrdersPerEmailPerDay, maxDailyValuePerEmailPence,
                maxOrderValuePence, requireEmailVerificationAbovePence, blockDisposableEmails, blockVpnProxy,
                blockHighRiskCountries, highRiskCountries, enforce3dSecure, maxFailedPaymentsPerIpPerHour,
                cooldownMinutesAfterFailedPayment, autoApproveAfterHours, notifyCustomerOnHold, reviewHours, signalWeights, avsLookup)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                enabled=VALUES(enabled), mode=VALUES(mode), reviewThreshold=VALUES(reviewThreshold),
                blockThreshold=VALUES(blockThreshold), holdFulfilment=VALUES(holdFulfilment),
                maxOrdersPerIpPerHour=VALUES(maxOrdersPerIpPerHour), maxOrdersPerIpPerDay=VALUES(maxOrdersPerIpPerDay),
                maxOrdersPerEmailPerDay=VALUES(maxOrdersPerEmailPerDay), maxDailyValuePerEmailPence=VALUES(maxDailyValuePerEmailPence),
                maxOrderValuePence=VALUES(maxOrderValuePence), requireEmailVerificationAbovePence=VALUES(requireEmailVerificationAbovePence),
                blockDisposableEmails=VALUES(blockDisposableEmails), blockVpnProxy=VALUES(blockVpnProxy),
                blockHighRiskCountries=VALUES(blockHighRiskCountries), highRiskCountries=VALUES(highRiskCountries),
                enforce3dSecure=VALUES(enforce3dSecure), maxFailedPaymentsPerIpPerHour=VALUES(maxFailedPaymentsPerIpPerHour),
                cooldownMinutesAfterFailedPayment=VALUES(cooldownMinutesAfterFailedPayment),
                autoApproveAfterHours=VALUES(autoApproveAfterHours), notifyCustomerOnHold=VALUES(notifyCustomerOnHold),
                reviewHours=VALUES(reviewHours), signalWeights=VALUES(signalWeights), avsLookup=VALUES(avsLookup)`,
            [
                c.channelId, c.enabled ? 1 : 0, c.mode, c.reviewThreshold, c.blockThreshold, c.holdFulfilment ? 1 : 0,
                c.maxOrdersPerIpPerHour, c.maxOrdersPerIpPerDay, c.maxOrdersPerEmailPerDay, c.maxDailyValuePerEmailPence,
                c.maxOrderValuePence, c.requireEmailVerificationAbovePence, c.blockDisposableEmails ? 1 : 0,
                c.blockVpnProxy ? 1 : 0, c.blockHighRiskCountries ? 1 : 0, c.highRiskCountries || '',
                c.enforce3dSecure ? 1 : 0, c.maxFailedPaymentsPerIpPerHour, c.cooldownMinutesAfterFailedPayment,
                c.autoApproveAfterHours || 0, (c as any).notifyCustomerOnHold || 'block',
                (c as any).reviewHours || 24, JSON.stringify(c.signalWeights || {}),
                c.avsLookup === false ? 0 : 1,
            ],
            { conflictColumns: ['channelId'] },
        );
    }

    // ── Assessment engine ───────────────────────────────────────────────
    private weight(cfg: FraudChannelConfig, key: string): number {
        return cfg.signalWeights?.[key] ?? DEFAULT_WEIGHTS[key] ?? 0;
    }

    async assess(input: AssessInput): Promise<FraudAssessment> {
        const cfg = await this.getConfig(input.channelId);
        const signals: FraudSignal[] = [];
        const push = (key: string, label: string, detail: string) => {
            const points = this.weight(cfg, key);
            if (points !== 0) signals.push({ key, label, points, detail });
        };

        // Even when protection is disabled we still evaluate every rule —
        // "off" must never mean "blind". The result is recorded as a
        // shadow assessment (no action, no holds) so admins can see what
        // protection WOULD have caught and be nudged to switch it on.
        const protectionOff = !cfg.enabled || cfg.mode === 'off';

        const norm = input.email ? normalizeEmail(input.email) : null;
        if (input.ip) input.ip = normaliseIp(input.ip);

        // The two network lookups start now and are awaited where their signals are scored,
        // so they overlap each other and every database signal instead of running in series.
        const intelP: Promise<IpIntel> | null = input.ip ? this.getIpIntel(input.ip).catch(() => ({ ip: input.ip!, countryCode: null, isVpnOrProxy: false, isHosting: false, resolved: false })) : null;
        const mxP: Promise<boolean | null> | null = norm ? domainHasMx(norm.domain).catch(() => null) : null;

        // 0. Allowlist — trusted identities bypass everything.
        if (await this.isAllowlisted(norm?.email, norm?.domain, input.ip)) {
            return { score: 0, level: 'low', signals: [], allowlisted: true, action: 'allow', mode: cfg.mode };
        }

        // 1. Blocklists (manual + feeds), incl. CIDR ranges.
        if (norm) {
            const hits = await this.db.query(
                `SELECT listType, source, value FROM fraud_blocklist
                 WHERE (listType = 'email' AND value IN (?, ?)) OR (listType = 'email_domain' AND value = ?) LIMIT 3`,
                [norm.email, norm.canonical, norm.domain],
            ).catch(() => []);
            for (const h of hits) {
                push(h.listType === 'email' ? 'blocklist_email' : 'blocklist_email_domain',
                    'Blocklisted email', `${h.value} (${h.source})`);
            }
        }
        if (input.ip) {
            const exact = await this.db.query(
                `SELECT source, value FROM fraud_blocklist WHERE listType = 'ip' AND value = ? LIMIT 1`,
                [input.ip],
            ).catch(() => []);
            if (exact.length) {
                push('blocklist_ip', 'Blocklisted IP', `${input.ip} (${exact[0].source})`);
            } else {
                // CIDR ranges: narrow the candidates in SQL first so we never scan
                // all rows (IPv4: same /8 prefix, catch-all 0.x and IPv4-mapped
                // ranges; IPv6: every IPv6 range), then verify precisely in JS.
                const isV6 = input.ip.includes(':');
                const firstOctet = input.ip.split('.')[0];
                const ranges = await this.db.query(
                    isV6
                        ? `SELECT source, value FROM fraud_blocklist
                           WHERE listType = 'ip_range' AND value LIKE '%:%'
                           LIMIT 2000`
                        : `SELECT source, value FROM fraud_blocklist
                           WHERE listType = 'ip_range' AND (value LIKE ? OR value LIKE '0.%' OR value LIKE '::ffff:%')
                           LIMIT 2000`,
                    isV6 ? [] : [`${firstOctet}.%`],
                ).catch(() => []);
                const hit = ranges.find((r: any) => ipInCidr(input.ip!, r.value));
                if (hit) push('blocklist_ip_range', 'IP in blocklisted range', `${input.ip} ∈ ${hit.value} (${hit.source})`);
            }
        }

        // 2. Disposable email — feed rows count via blocklist above; the
        //    built-in set is the safety net for fresh installs.
        if (cfg.blockDisposableEmails && norm && BUILTIN_DISPOSABLE_DOMAINS.has(norm.domain)
            && !signals.some(s => s.key === 'blocklist_email_domain')) {
            push('disposable_email', 'Disposable email domain', norm.domain);
        }

        // 3. Plus-addressing / dot tricks — weak signal on its own, matters
        //    in combination with velocity.
        if (norm?.usedPlusAddressing) {
            push('plus_addressing', 'Plus-addressed email', `${norm.email} → ${norm.canonical}`);
        }

        // 4. Velocity — IP.
        if (input.ip) {
            const [hourRow] = await this.db.query(
                `SELECT COUNT(*) AS cnt FROM \`order\`
                 WHERE \`customFieldsIp\` = ? AND \`orderPlacedAt\` > DATE_SUB(NOW(), INTERVAL 1 HOUR)`,
                [input.ip],
            );
            const hourCnt = Number(hourRow?.cnt || 0);
            if (hourCnt >= cfg.maxOrdersPerIpPerHour) {
                push('ip_velocity_hour', 'IP velocity (hour)', `${hourCnt} orders/hour (limit ${cfg.maxOrdersPerIpPerHour})`);
            } else if (hourCnt >= Math.ceil(cfg.maxOrdersPerIpPerHour * 0.7)) {
                push('ip_velocity_warm', 'IP velocity warming', `${hourCnt} orders this hour`);
            }
            const [dayRow] = await this.db.query(
                `SELECT COUNT(*) AS cnt FROM \`order\`
                 WHERE \`customFieldsIp\` = ? AND \`orderPlacedAt\` > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
                [input.ip],
            );
            const dayCnt = Number(dayRow?.cnt || 0);
            if (dayCnt >= cfg.maxOrdersPerIpPerDay) {
                push('ip_velocity_day', 'IP velocity (24h)', `${dayCnt} orders/24h (limit ${cfg.maxOrdersPerIpPerDay})`);
            }
        }

        // 5. Velocity — email identity. Uses the CANONICAL address so
        //    person+1@gmail / person+2@gmail count as one identity.
        if (norm) {
            const like = norm.canonical === norm.email
                ? [norm.email]
                : [norm.email, norm.canonical];
            const [emailRow] = await this.db.query(
                `SELECT COUNT(*) AS cnt, COALESCE(SUM(o.\`subTotalWithTax\`), 0) AS totalValue
                 FROM \`order\` o JOIN customer c ON c.id = o.\`customerId\`
                 WHERE c.\`emailAddress\` IN (${like.map(() => '?').join(',')})
                   AND o.\`orderPlacedAt\` > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
                like,
            );
            const cnt = Number(emailRow?.cnt || 0);
            const val = Number(emailRow?.totalValue || 0);
            if (cnt >= cfg.maxOrdersPerEmailPerDay) {
                push('email_velocity_day', 'Email velocity (24h)', `${cnt} orders/24h (limit ${cfg.maxOrdersPerEmailPerDay})`);
            }
            if (val + input.orderValuePence > cfg.maxDailyValuePerEmailPence) {
                push('email_value_day', 'Email daily value',
                    `£${((val + input.orderValuePence) / 100).toFixed(2)} > £${(cfg.maxDailyValuePerEmailPence / 100).toFixed(2)} limit`);
            }
        }

        // 5b. Identity fan-out — many distinct emails ordering from one IP
        //     inside 24h is the classic card-testing pattern.
        if (input.ip) {
            const [fanRow] = await this.db.query(
                `SELECT COUNT(DISTINCT LOWER(c.\`emailAddress\`)) AS n
                 FROM \`order\` o JOIN customer c ON c.id = o.\`customerId\`
                 WHERE o.\`customFieldsIp\` = ? AND o.\`orderPlacedAt\` > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
                [input.ip],
            );
            const fan = Number(fanRow?.n || 0);
            if (fan >= 3) {
                push('identity_fanout', 'Identity fan-out', `${fan} different customer emails from this IP in 24h`);
            }
        }

        // 5c. IP intelligence — VPN/proxy/hosting + geo vs billing country.
        //     Cached 30 days in fraud_ip_intel; lookups fail open.
        if (input.ip && intelP) {
            const intel = await intelP;
            if (intel.resolved) {
                if (cfg.blockVpnProxy && intel.isVpnOrProxy) {
                    push('vpn_proxy', 'VPN / proxy IP', input.ip);
                }
                if (cfg.blockVpnProxy && intel.isHosting && !intel.isVpnOrProxy) {
                    push('hosting_ip', 'Datacentre / hosting IP', input.ip);
                }
                if (intel.countryCode && input.countryCode
                    && intel.countryCode.toUpperCase() !== input.countryCode.toUpperCase()) {
                    push('geo_mismatch', 'IP / billing country mismatch',
                        `IP in ${intel.countryCode}, billing ${input.countryCode.toUpperCase()}`);
                }
            }
        }

        // 5d. Email deliverability + shape.
        if (norm) {
            const hasMx = mxP ? await mxP : null;
            if (hasMx === false) {
                push('email_no_mx', 'Email domain has no MX records', `${norm.domain} cannot receive mail`);
            }
            if (looksGibberish(norm.email.split('@')[0])) {
                push('gibberish_email', 'Gibberish email local part', norm.email);
            }
        }

        // 5e. Billing vs shipping country (both present and different).
        if (input.countryCode && input.shippingCountryCode
            && input.countryCode.toUpperCase() !== input.shippingCountryCode.toUpperCase()) {
            push('country_mismatch', 'Billing / shipping country differ',
                `${input.countryCode.toUpperCase()} vs ${input.shippingCountryCode.toUpperCase()}`);
        }

        // 5f. Billing vs shipping postcode (same country, both typed,
        //     different). Weak alone — gifts, offices — but it compounds.
        const sameCountry = !input.countryCode || !input.shippingCountryCode
            || input.countryCode.toUpperCase() === input.shippingCountryCode.toUpperCase();
        if (sameCountry && postcodesDiffer(input.billingPostalCode, input.shippingPostalCode)) {
            push('postcode_mismatch', 'Billing / shipping postcode differ',
                `${String(input.billingPostalCode).trim().toUpperCase()} vs ${String(input.shippingPostalCode).trim().toUpperCase()}`);
        }

        // 5g. Card AVS — the issuer's own verdict on the billing address.
        //     Only an explicit FAIL scores; unavailable/unchecked is silent.
        if (input.avs) {
            if (input.avs.postalCode === 'fail') {
                push('avs_postcode_fail', 'Card AVS: postcode mismatch', describeAvs('postalCode', input.avs));
            }
            if (input.avs.line1 === 'fail') {
                push('avs_address_fail', 'Card AVS: street address mismatch', describeAvs('line1', input.avs));
            }
            // 5h. Stripe Radar — the gateway's own ML verdict on the charge.
            //     'normal' / 'not_assessed' are silent.
            if (input.avs.riskLevel === 'highest') {
                push('radar_risk_highest', 'Stripe Radar: highest risk', describeRadar(input.avs));
            } else if (input.avs.riskLevel === 'elevated') {
                push('radar_risk_elevated', 'Stripe Radar: elevated risk', describeRadar(input.avs));
            }
            // 5i. 3-D Secure ran and the cardholder failed to authenticate —
            //     no liability shift. Gated by the channel's 3DS rule.
            if (cfg.enforce3dSecure !== false && threeDsFailed(input.avs)) {
                push('three_ds_failed', '3-D Secure failed', describeThreeDs(input.avs));
            }
        }

        // 6. Order value.
        if (input.orderValuePence > cfg.maxOrderValuePence) {
            push('order_value', 'High order value',
                `£${(input.orderValuePence / 100).toFixed(2)} > £${(cfg.maxOrderValuePence / 100).toFixed(2)} limit`);
        }

        // 7. Customer history — positive trust for a track record, caution
        //    for a high-value first order. Counted by canonical email so the
        //    credit survives plus-tag variations, and simulate can override
        //    via isReturningCustomer.
        let settledCount = 0;
        if (input.isReturningCustomer !== undefined) {
            settledCount = input.isReturningCustomer ? 3 : 0;
        } else if (norm) {
            const like = norm.canonical === norm.email ? [norm.email] : [norm.email, norm.canonical];
            const [histRow] = await this.db.query(
                `SELECT COUNT(*) AS n FROM \`order\` o JOIN customer c ON c.id = o.\`customerId\`
                 WHERE c.\`emailAddress\` IN (${like.map(() => '?').join(',')})
                   AND o.state IN ('PaymentSettled', 'Delivered')${input.orderId ? ' AND o.id <> ?' : ''}`,
                input.orderId ? [...like, input.orderId] : like,
            );
            settledCount = Number(histRow?.n || 0);
        }
        if (settledCount >= 3) {
            push('returning_customer_3plus', 'Trusted returning customer', `${settledCount} settled orders`);
        } else if (settledCount >= 1) {
            push('returning_customer_2', 'Returning customer', `${settledCount} settled order(s)`);
        } else if (input.orderValuePence > cfg.requireEmailVerificationAbovePence) {
            push('new_customer_high_value', 'First order, high value',
                `first order at £${(input.orderValuePence / 100).toFixed(2)}`);
        }

        // 8. High-risk countries.
        if (cfg.blockHighRiskCountries && input.countryCode && cfg.highRiskCountries) {
            const list = cfg.highRiskCountries.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
            if (list.includes(input.countryCode.toUpperCase())) {
                push('high_risk_country', 'High-risk country', input.countryCode.toUpperCase());
            }
        }

        // 9. Failed payments from this IP — Vendure Payment rows that ended
        //    Declined/Error/Cancelled, plus (when the checkout-guard plugin
        //    is installed) gateway failures and client-side declines it
        //    recorded before any Payment row existed.
        if (input.ip) {
            const [fpRow] = await this.db.query(
                `SELECT COUNT(*) AS cnt FROM payment p JOIN \`order\` o ON o.id = p.\`orderId\`
                 WHERE o.\`customFieldsIp\` = ? AND p.state IN ('Declined', 'Error', 'Cancelled')
                   AND p.\`createdAt\` > DATE_SUB(NOW(), INTERVAL 1 HOUR)`,
                [input.ip],
            );
            const vendureCnt = Number(fpRow?.cnt || 0);
            const guardCnt = await this.countCheckoutGuardFailures(input.ip, 60);
            const cnt = vendureCnt + guardCnt;
            if (cnt >= cfg.maxFailedPaymentsPerIpPerHour) {
                const via = guardCnt ? ` (${vendureCnt} payment records + ${guardCnt} gateway/client declines)` : '';
                push('failed_payments', 'Failed payments', `${cnt} failed payments from IP in the last hour${via}`);
            }
        }

        const score = Math.max(0, Math.min(signals.reduce((s, x) => s + x.points, 0), 100));
        let level: RiskLevel = 'low';
        if (score >= cfg.blockThreshold) level = 'blocked';
        else if (score >= cfg.reviewThreshold) level = 'review';
        else if (score >= Math.floor(cfg.reviewThreshold / 2)) level = 'medium';

        // FREE tier never enforces — a configured 'enforce' downgrades to
        // monitor (flag + log) until a valid licence is present.
        let effectiveMode = cfg.mode;
        if (effectiveMode === 'enforce') {
            // Lazy import avoids a static plugin<->service cycle at load time.
            const { FraudPreventionPlugin } = require('./plugin');
            if (!FraudPreventionPlugin.hasPremiumAccess()) effectiveMode = 'monitor';
        }

        let action: FraudAssessment['action'] = 'allow';
        if (level === 'review' || level === 'blocked') {
            action = protectionOff ? 'shadow'
                : effectiveMode === 'enforce' ? (level === 'blocked' ? 'block' : 'review') : 'flag';
        }

        return { score, level, signals, allowlisted: false, action, mode: effectiveMode, protectionActive: !protectionOff };
    }

    /**
     * Work out the card checks (issuer AVS verdicts, Stripe Radar risk
     * level, 3-D Secure outcome) for a placed order. Order of trust:
     *   1. host `avsResolver` option (any gateway),
     *   2. `Payment.metadata` on a settled/authorised payment,
     *   3. Stripe: fetch the PaymentIntent (expand latest_charge) with the
     *      payment method's own API key — only when the channel's
     *      `avsLookup` is on. One GET yields AVS, Radar and 3DS together.
     * Never throws; unknown → null → no signal.
     */
    async resolveAvsForOrder(ctx: RequestContext, order: Order, cfg?: FraudChannelConfig): Promise<CardChecks | null> {
        try {
            let payments: Payment[] = Array.isArray(order.payments) && order.payments.length ? order.payments : [];
            if (!payments.length) {
                payments = await this.connection.getRepository(ctx, Payment).find({
                    where: { order: { id: order.id } as any },
                    order: { createdAt: 'DESC' } as any,
                }).catch(() => [] as Payment[]);
            }
            const live = payments.filter(p => ['Settled', 'Authorized'].includes(p.state));
            const candidates = live.length ? live : payments;

            if (this.options.avsResolver) {
                try {
                    const r = await this.options.avsResolver({ ...order, payments: candidates } as any, ctx);
                    if (r && (r.postalCode || r.line1 || r.riskLevel || r.threeDsAuthenticated !== undefined)) return r;
                } catch (e: any) {
                    Logger.warn(`avsResolver threw for ${order.code}: ${e.message}`, loggerCtx);
                }
            }

            for (const p of candidates) {
                const fromMeta = avsFromMetadata(p.metadata);
                if (fromMeta) return fromMeta;
            }

            const lookup = cfg ? cfg.avsLookup !== false : (await this.getConfig(Number(ctx.channelId || 1))).avsLookup !== false;
            if (!lookup) return null;
            for (const p of candidates) {
                const piId = p.transactionId || (p.metadata as any)?.paymentIntentId;
                if (!piId || !/^pi_/.test(String(piId))) continue;
                // Payment-method codes are per channel: pick the one assigned
                // to this order's channel so a multi-channel host with two
                // Stripe accounts uses the right key.
                const methods = await this.connection.getRepository(ctx, PaymentMethod)
                    .find({ where: { code: p.method }, relations: ['channels'] })
                    .catch(() => [] as PaymentMethod[]);
                const channelId = String(ctx.channelId ?? '');
                const method = methods.find(m => (m.channels || []).some(ch => String(ch.id) === channelId))
                    ?? (methods.length === 1 ? methods[0] : undefined);
                if (!method || method.handler?.code !== 'stripe') continue;
                const apiKey = method.handler.args?.find(a => a.name === 'apiKey')?.value;
                if (!apiKey) continue;
                const r = await fetchStripeCardChecks(String(apiKey), String(piId), {
                    log: msg => Logger.warn(`Card-check lookup for ${order.code}: ${msg}`, loggerCtx),
                });
                if (r) return r;
                Logger.verbose(`No card checks on ${piId} for ${order.code} (non-card payment, or the charge carries no AVS / Radar / 3DS data)`, loggerCtx);
            }
        } catch (e: any) {
            Logger.warn(`AVS resolution failed for ${order.code}: ${e.message}`, loggerCtx);
        }
        return null;
    }

    private async isAllowlisted(email?: string, domain?: string, ip?: string): Promise<boolean> {
        if (email || domain) {
            const wl = await this.db.query(
                `SELECT id FROM fraud_whitelist
                 WHERE (type = 'email' AND value = ?) OR (type = 'email_domain' AND value = ?) LIMIT 1`,
                [email || '', domain || ''],
            ).catch(() => []);
            if (wl.length) return true;
        }
        if (ip) {
            const wl = await this.db.query(
                `SELECT id FROM fraud_whitelist WHERE type = 'ip' AND value = ? LIMIT 1`, [ip],
            ).catch(() => []);
            if (wl.length) return true;
            // Allowlisted ranges (IPv4 or IPv6 CIDR), narrowed in SQL the same way as blocklist ranges.
            const isV6 = ip.includes(':');
            const ranges = await this.db.query(
                isV6
                    ? `SELECT value FROM fraud_whitelist WHERE type = 'ip_range' AND value LIKE '%:%' LIMIT 2000`
                    : `SELECT value FROM fraud_whitelist WHERE type = 'ip_range' AND (value LIKE ? OR value LIKE '0.%' OR value LIKE '::ffff:%') LIMIT 2000`,
                isV6 ? [] : [`${ip.split('.')[0]}.%`],
            ).catch(() => []);
            if (ranges.some((r: any) => ipInCidr(ip, r.value))) return true;
        }
        return false;
    }

    /** Everything we know about one order, for the admin order-detail
     *  panel: latest assessments (every order gets one) + the review
     *  case if the order was held/blocked. */
    async orderAssessment(orderId: number): Promise<any> {
        const assessments = await this.db.query(
            `SELECT riskScore, riskLevel, reasons, action, signals, createdAt
             FROM fraud_log WHERE orderId = ? ORDER BY createdAt DESC LIMIT 5`, [orderId]).catch(() => []);
        const [caseRow] = await this.db.query(
            `SELECT status, riskLevel, riskScore, reasons, createdAt
             FROM fraud_blocked_orders WHERE orderId = ? ORDER BY id DESC LIMIT 1`, [orderId]).catch(() => []);
        const latest = assessments[0] || null;
        let signals: any[] = [];
        try { signals = latest?.signals ? JSON.parse(latest.signals) : []; } catch { /* legacy rows */ }
        return {
            assessed: !!latest,
            score: latest ? Number(latest.riskScore) : null,
            level: latest?.riskLevel || null,
            action: latest?.action || null,
            assessedAt: latest?.createdAt || null,
            signals,
            reasons: latest?.reasons || '',
            case: caseRow || null,
        };
    }

    // ── Logging + cases ────────────────────────────────────────────────
    async logAssessment(input: AssessInput, a: FraudAssessment): Promise<void> {
        await this.db.query(
            `INSERT INTO fraud_log (channelId, orderId, orderCode, ip, email, riskScore, riskLevel, reasons, action, signals, createdAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [
                input.channelId, input.orderId || null, input.orderCode || null,
                input.ip || '', input.email || '', a.score, a.level,
                a.signals.map(s => `${s.label}: ${s.detail}`).join('; ') || (a.allowlisted ? 'allowlisted' : ''),
                a.action, JSON.stringify(a.signals),
            ],
        );
    }

    async createCase(input: AssessInput, a: FraudAssessment): Promise<number> {
        if (input.orderId) {
            const [open] = await this.db.query(
                `SELECT id FROM fraud_blocked_orders WHERE orderId = ? AND status = 'pending' LIMIT 1`, [Number(input.orderId)],
            ).catch(() => []);
            if (open?.id) return Number(open.id);
        }
        const res = await this.db.query(
            `INSERT INTO fraud_blocked_orders (orderId, orderCode, channelId, ip, email, riskScore, riskLevel, reasons, signals, status, createdAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
            [
                input.orderId || null, input.orderCode || null, input.channelId,
                input.ip || '', input.email || '', a.score, a.level,
                a.signals.map(s => `${s.label}: ${s.detail}`).join('; '),
                JSON.stringify(a.signals),
            ],
            { needInsertId: true },
        );
        return res.insertId;
    }

    /** Order ids with a pending review case — hosts use this to gate
     *  fulfilment (e.g. licence-key release). */
    async pendingOrderIds(): Promise<number[]> {
        const rows = await this.db.query(
            `SELECT orderId FROM fraud_blocked_orders WHERE status = 'pending' AND orderId IS NOT NULL`,
        ).catch(() => []);
        return rows.map((r: any) => Number(r.orderId));
    }

    /** Order ids with a review case that is pending OR was rejected —
     *  neither must ever be fulfilled. Hosts that gate on
     *  `pendingOrderIds()` alone release a rejected order the moment the
     *  case closes; use this set instead. */
    async heldOrderIds(): Promise<number[]> {
        const rows = await this.db.query(
            `SELECT orderId FROM fraud_blocked_orders WHERE status IN ('pending', 'rejected') AND orderId IS NOT NULL`,
        ).catch(() => []);
        return rows.map((r: any) => Number(r.orderId));
    }

    /**
     * True once the order guard has scored this order (a `fraud_log` row
     * exists for it). The guard runs asynchronously after
     * `OrderPlacedEvent`, so a fulfilment path that fires on the same
     * event — or a cron that runs seconds later — can see an order that
     * has not been assessed yet and therefore has no case to hold it.
     * Gate on `isAssessed(orderId) && !pending` to close that race.
     * Orders placed while the channel was `off` are still logged (shadow
     * assessment), so this is true for every placed order once the guard
     * has seen it.
     */
    async isAssessed(orderId: ID | number): Promise<boolean> {
        const rows = await this.db.query(
            `SELECT 1 AS present FROM fraud_log WHERE orderId = ? LIMIT 1`, [Number(orderId)],
        ).catch(() => []);
        return rows.length > 0;
    }

    /** Batch form of `isAssessed` for crons: the subset of `orderIds`
     *  that have an assessment row. */
    async assessedOrderIds(orderIds: Array<ID | number>): Promise<number[]> {
        const ids = Array.from(new Set(orderIds.map(id => Number(id)).filter(n => Number.isFinite(n))));
        if (!ids.length) return [];
        const rows = await this.db.query(
            `SELECT DISTINCT orderId FROM fraud_log WHERE orderId IN (${ids.map(() => '?').join(',')})`, ids,
        ).catch(() => []);
        return rows.map((r: any) => Number(r.orderId));
    }

    /**
     * Review-queue listing. `signal` narrows to cases where a signal key
     * with that prefix fired — 'avs' = the card issuer's AVS verdict — by
     * matching the stored signal JSON, so no schema change is needed.
     */
    async listCases(status?: string, signal?: string, take = 100): Promise<any[]> {
        const clauses: string[] = [];
        const params: any[] = [];
        if (status) { clauses.push('bo.status = ?'); params.push(status); }
        const prefix = (signal || '').replace(/[^a-z0-9_]/gi, '');
        if (prefix) { clauses.push('bo.signals LIKE ?'); params.push(`%"key":"${prefix}%`); }
        const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
        return this.db.query(
            `SELECT bo.*, o.code AS liveOrderCode, o.state AS orderState, o.\`subTotalWithTax\` AS subTotalWithTax,
                    c.\`firstName\` AS firstName, c.\`lastName\` AS lastName, c.\`emailAddress\` AS emailAddress
             FROM fraud_blocked_orders bo
             LEFT JOIN \`order\` o ON o.id = bo.orderId
             LEFT JOIN customer c ON c.id = o.\`customerId\`
             ${where} ORDER BY bo.createdAt DESC LIMIT ${Math.min(take, 500)}`,
            params,
        ).catch(() => []);
    }

    /**
     * Close a review case. `rejected` also cancels the order through
     * Vendure (`OrderService.cancelOrder`, so the state machine, history
     * and every `OrderStateTransitionEvent` subscriber see it), voids
     * Authorized payments (card holds, bank transfers) and — unless
     * `refundOnReject` / `opts.refund` is false — refunds every settled
     * payment in full via the handler's `createRefund`. The order is also
     * marked inactive, as before. Vendure failures never block the case
     * decision: they are reported in `warnings` and logged.
     */
    async resolveCase(
        id: number,
        decision: 'approved' | 'rejected',
        notes?: string,
        opts: { cancel?: boolean; refund?: boolean } = {},
    ): Promise<ResolveCaseResult> {
        const rows = await this.db.query(`SELECT * FROM fraud_blocked_orders WHERE id = ?`, [id]);
        if (!rows.length) return { ok: false, message: 'Case not found' };
        const c = rows[0];
        if (c.status !== 'pending') return { ok: false, message: `Already ${c.status}` };
        await this.db.query(
            `UPDATE fraud_blocked_orders SET status = ?, reviewedAt = NOW(), reviewNotes = ? WHERE id = ?`,
            [decision, notes || null, id],
        );
        const result: ResolveCaseResult = { ok: true, message: `Case ${decision}`, caseRow: c };
        if (decision === 'rejected' && c.orderId) {
            const cancel = opts.cancel ?? this.options.cancelOnReject ?? true;
            const refund = opts.refund ?? this.options.refundOnReject ?? true;
            if (cancel) {
                const outcome = await this.cancelRejectedOrder(Number(c.orderId), Number(c.channelId), refund,
                    notes ? `Rejected by fraud review: ${notes}` : 'Rejected by fraud review');
                result.cancelled = outcome.cancelled;
                result.orderState = outcome.orderState;
                result.refunds = outcome.refunds;
                result.warnings = outcome.warnings;
            }
            await this.db.query(`UPDATE \`order\` SET active = FALSE WHERE id = ? AND active IS TRUE`, [c.orderId]);
        }
        await this.db.query(
            `INSERT INTO fraud_log (channelId, orderId, orderCode, ip, email, riskScore, riskLevel, reasons, action, createdAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [c.channelId, c.orderId, c.orderCode, c.ip, c.email, c.riskScore, decision,
                this.describeResolution(decision, notes, result), decision],
        );
        return result;
    }

    private describeResolution(decision: string, notes: string | undefined, r: ResolveCaseResult): string {
        const parts = [notes || `${decision} by admin`];
        if (r.cancelled) parts.push('order cancelled');
        for (const rf of r.refunds || []) parts.push(`refunded ${(rf.amount / 100).toFixed(2)} on payment #${rf.paymentId}`);
        for (const w of r.warnings || []) parts.push(`warning: ${w}`);
        return parts.join('; ');
    }

    /** An admin RequestContext bound to the channel the order lives in,
     *  so `OrderService.findOne` and friends can see it. */
    private async adminContextForOrder(orderId: number, preferredChannelId?: number): Promise<RequestContext> {
        let token: string | undefined;
        const rows = await this.db.query(
            `SELECT c.id, c.token FROM channel c JOIN order_channels_channel oc ON oc.\`channelId\` = c.id WHERE oc.\`orderId\` = ?`,
            [orderId],
        ).catch(() => []);
        if (rows.length) {
            const preferred = preferredChannelId ? rows.find((r: any) => Number(r.id) === Number(preferredChannelId)) : null;
            token = (preferred || rows[0]).token;
        }
        if (!token && preferredChannelId) {
            const [ch] = await this.db.query(`SELECT token FROM channel WHERE id = ?`, [preferredChannelId]).catch(() => []);
            token = ch?.token;
        }
        return this.requestContextService.create({ apiType: 'admin', channelOrToken: token });
    }

    /**
     * Cancel (and optionally refund) an order that failed fraud review.
     * Order of operations: void Authorized payments first (holds must not
     * capture), refund Settled payments (only valid while the order is
     * in a paid state, so before the cancel), then cancel the order.
     */
    private async cancelRejectedOrder(orderId: number, channelId: number, refund: boolean, reason: string): Promise<{
        cancelled: boolean; orderState?: string; refunds: Array<{ paymentId: number; amount: number }>; warnings: string[];
    }> {
        const refunds: Array<{ paymentId: number; amount: number }> = [];
        const warnings: string[] = [];
        let cancelled = false;
        let orderState: string | undefined;
        try {
            const ctx = await this.adminContextForOrder(orderId, channelId);
            const order = await this.orderService.findOne(ctx, orderId, ['payments', 'payments.refunds', 'lines']);
            if (!order) {
                warnings.push(`order #${orderId} not found in channel`);
                return { cancelled, orderState, refunds, warnings };
            }
            orderState = order.state;
            if (order.state === 'Cancelled') {
                return { cancelled: true, orderState, refunds, warnings };
            }

            for (const p of order.payments || []) {
                if (p.state !== 'Authorized') continue;
                const r: any = await this.orderService.cancelPayment(ctx, p.id);
                if (r && r.errorCode) warnings.push(`void payment #${p.id}: ${r.message || r.errorCode}`);
            }

            const refundable = order.state !== 'AddingItems' && order.state !== 'ArrangingPayment' && order.state !== 'PaymentAuthorized';
            if (refund && refundable) {
                for (const p of order.payments || []) {
                    if (p.state !== 'Settled') continue;
                    const already = (p.refunds || [])
                        .filter(rf => rf.state !== 'Failed')
                        .reduce((n, rf) => n + Number(rf.total || 0), 0);
                    const amount = Number(p.amount) - already;
                    if (amount <= 0) continue;
                    // `amount` is the v2.2+ way to refund; `lines` / `shipping` /
                    // `adjustment` are still written to the Refund row, so they
                    // must be present (0) or strict-mode MySQL rejects the insert.
                    const r: any = await this.orderService.refundOrder(ctx, {
                        paymentId: p.id, amount, lines: [], shipping: 0, adjustment: 0, reason,
                    });
                    if (r && r.errorCode) warnings.push(`refund payment #${p.id}: ${r.message || r.errorCode}`);
                    else refunds.push({ paymentId: Number(p.id), amount });
                }
            } else if (refund && !refundable && (order.payments || []).some(p => p.state === 'Settled')) {
                warnings.push(`order in state ${order.state} cannot be refunded`);
            }

            const cancelResult: any = await this.orderService.cancelOrder(ctx, { orderId, reason });
            if (cancelResult && cancelResult.errorCode) {
                warnings.push(`cancel: ${cancelResult.message || cancelResult.errorCode}`);
            } else {
                cancelled = true;
                orderState = cancelResult?.state || 'Cancelled';
            }
        } catch (e: any) {
            warnings.push(`cancel/refund threw: ${e?.message || e}`);
        }
        for (const w of warnings) Logger.warn(`Fraud reject for order #${orderId}: ${w}`, loggerCtx);
        return { cancelled, orderState, refunds, warnings };
    }

    /**
     * Failed-payment rows recorded by @huloglobal/vendure-plugin-checkout-guard
     * (`checkout_guard_payment_event`, kinds `failed` = gateway declined
     * before a Vendure Payment existed, `client_declined` = the storefront
     * reported a decline). Zero when that plugin is not installed; the
     * table check is cached so an absent table costs one metadata query
     * every ten minutes.
     */
    async countCheckoutGuardFailures(ip: string, windowMinutes = 60): Promise<number> {
        if (!ip || !(await this.checkoutGuardTableExists())) return 0;
        const mins = Math.max(1, Math.min(Math.floor(windowMinutes), 24 * 60));
        const [row] = await this.db.query(
            `SELECT COUNT(*) AS cnt FROM checkout_guard_payment_event
             WHERE ip = ? AND kind IN ('failed', 'client_declined')
               AND createdAt > DATE_SUB(NOW(), INTERVAL ${mins} MINUTE)`,
            [ip],
        ).catch(() => [{ cnt: 0 }]);
        return Number(row?.cnt || 0);
    }

    private checkoutGuardTable: { exists: boolean; checkedAt: number } | null = null;

    private async checkoutGuardTableExists(): Promise<boolean> {
        const now = Date.now();
        if (this.checkoutGuardTable && (this.checkoutGuardTable.exists || now - this.checkoutGuardTable.checkedAt < 10 * 60_000)) {
            return this.checkoutGuardTable.exists;
        }
        let exists = false;
        try {
            const schemaExpr = this.db.dialect === 'postgres' ? 'current_schema()' : 'DATABASE()';
            const rows = await this.db.query(
                `SELECT 1 AS present FROM information_schema.tables
                 WHERE table_schema = ${schemaExpr} AND table_name = 'checkout_guard_payment_event' LIMIT 1`,
            );
            exists = Array.isArray(rows) && rows.length > 0;
        } catch {
            exists = false;
        }
        this.checkoutGuardTable = { exists, checkedAt: now };
        return exists;
    }

    // ── Stats for the Overview tab ─────────────────────────────────────
    async stats(days = 7): Promise<any> {
        const d = Math.max(1, Math.min(Number(days) || 7, 90));
        return this.cached(`stats:${d}`, 30_000, () => this.computeStats(d));
    }

    private async computeStats(d: number): Promise<any> {
        const [totals] = await this.db.query(
            `SELECT COUNT(*) AS assessed,
                    SUM(CASE WHEN riskLevel IN ('review','blocked') THEN 1 ELSE 0 END) AS flagged,
                    SUM(CASE WHEN action = 'review' THEN 1 ELSE 0 END) AS held,
                    SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked
             FROM fraud_log WHERE createdAt > DATE_SUB(NOW(), INTERVAL ? DAY)
               AND action IN ('allow','flag','review','block')`,
            [d],
        );
        const daily = await this.db.query(
            `SELECT DATE(createdAt) AS day, COUNT(*) AS assessed,
                    SUM(CASE WHEN riskLevel IN ('review','blocked') THEN 1 ELSE 0 END) AS flagged
             FROM fraud_log WHERE createdAt > DATE_SUB(NOW(), INTERVAL ? DAY)
               AND action IN ('allow','flag','review','block')
             GROUP BY DATE(createdAt) ORDER BY day`,
            [d],
        );
        const topSignals = await this.db.query(
            `SELECT riskLevel, COUNT(*) AS n FROM fraud_log
             WHERE createdAt > DATE_SUB(NOW(), INTERVAL ? DAY)
               AND action IN ('allow','flag','review','block')
             GROUP BY riskLevel ORDER BY n DESC`,
            [d],
        );
        const [pending] = await this.db.query(
            `SELECT COUNT(*) AS n FROM fraud_blocked_orders WHERE status = 'pending'`,
        );
        const [orders24] = await this.db.query(
            `SELECT COUNT(*) AS totalOrders, COUNT(DISTINCT \`customFieldsIp\`) AS uniqueIps,
                    COALESCE(SUM(\`subTotalWithTax\`), 0) AS totalValue
             FROM \`order\` WHERE \`orderPlacedAt\` > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
        );
        const [failed24] = await this.db.query(
            `SELECT COUNT(*) AS n FROM payment WHERE state IN ('Declined','Error','Cancelled')
             AND \`createdAt\` > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
        );
        const topIps = await this.db.query(
            `SELECT \`customFieldsIp\` AS ip, COUNT(*) AS n FROM \`order\`
             WHERE \`orderPlacedAt\` > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND \`customFieldsIp\` IS NOT NULL AND \`customFieldsIp\` <> ''
             GROUP BY \`customFieldsIp\` ORDER BY n DESC LIMIT 8`,
        );
        return {
            totals: totals || {}, daily, byLevel: topSignals,
            pendingCases: Number(pending?.n || 0),
            orders24: orders24 || {}, failedPayments24: Number(failed24?.n || 0),
            topIps,
        };
    }

    /** Activity log. `signal` narrows to rows where a signal key with that
     *  prefix fired ('avs' = issuer AVS verdict), same as listCases. */
    async log(filter: { level?: string; action?: string; signal?: string; take?: number }): Promise<any[]> {
        const clauses: string[] = [`action IS NOT NULL`];
        const params: any[] = [];
        if (filter.level) { clauses.push(`riskLevel = ?`); params.push(filter.level); }
        if (filter.action) { clauses.push(`action = ?`); params.push(filter.action); }
        const prefix = (filter.signal || '').replace(/[^a-z0-9_]/gi, '');
        if (prefix) { clauses.push(`signals LIKE ?`); params.push(`%"key":"${prefix}%`); }
        return this.db.query(
            `SELECT * FROM fraud_log WHERE ${clauses.join(' AND ')}
             ORDER BY createdAt DESC LIMIT ${Math.min(filter.take || 100, 500)}`,
            params,
        ).catch(() => []);
    }

    async pruneLog(retentionDays: number): Promise<number> {
        if (!retentionDays || retentionDays <= 0) return 0;
        // Chunked so a big backlog never holds one long lock on a table the hot path reads.
        let removed = 0;
        for (;;) {
            const rows: any[] = await this.db.query(
                `SELECT id FROM fraud_log WHERE createdAt < DATE_SUB(NOW(), INTERVAL ? DAY) ORDER BY id LIMIT 5000`, [retentionDays]);
            if (!rows.length) return removed;
            const ids = rows.map(r => Number(r.id));
            await this.db.query(`DELETE FROM fraud_log WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
            removed += ids.length;
        }
    }

    // ── Lists ──────────────────────────────────────────────────────────
    async listEntries(list: 'whitelist' | 'blocklist', manualOnly = true): Promise<any[]> {
        if (list === 'whitelist') {
            return this.db.query(`SELECT * FROM fraud_whitelist ORDER BY createdAt DESC LIMIT 500`).catch(() => []);
        }
        const where = manualOnly ? `WHERE source = 'manual'` : '';
        return this.db.query(`SELECT * FROM fraud_blocklist ${where} ORDER BY createdAt DESC LIMIT 500`).catch(() => []);
    }

    async addEntry(list: 'whitelist' | 'blocklist', type: string, value: string, note?: string): Promise<void> {
        let v = String(value || '').trim().toLowerCase();
        if (!v) throw new Error('Empty value');
        if (!['ip', 'ip_range', 'email', 'email_domain'].includes(type)) throw new Error('Unknown list type');
        if (type === 'ip') v = normaliseIp(v);
        if (type === 'ip_range' && !isCidr(v)) throw new Error('Ranges must be CIDR notation, e.g. 203.0.113.0/24 or 2001:db8::/32');
        if (type === 'email') { const n = normalizeEmail(v); if (!n) throw new Error('Not an email address'); v = n.canonical || n.email; }
        if (type === 'email_domain' && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(v)) throw new Error('Not a domain');
        if (list === 'whitelist') {
            await this.db.query(
                `INSERT INTO fraud_whitelist (type, value, note, createdAt) VALUES (?, ?, ?, NOW())`,
                [type, v, note || ''],
            );
        } else {
            await this.db.query(
                `INSERT INTO fraud_blocklist (listType, value, source, note, createdAt, updatedAt)
                 VALUES (?, ?, 'manual', ?, NOW(), NOW())`,
                [type, v, note || ''],
            );
        }
    }

    async removeEntry(list: 'whitelist' | 'blocklist', id: number): Promise<void> {
        if (list === 'whitelist') {
            await this.db.query(`DELETE FROM fraud_whitelist WHERE id = ?`, [id]);
        } else {
            // Manual rows only — feed rows are managed by sync.
            await this.db.query(`DELETE FROM fraud_blocklist WHERE id = ? AND source = 'manual'`, [id]);
        }
    }

    async listStatus(): Promise<any> {
        const lists = await this.db.query(
            `SELECT listType, source, COUNT(*) AS entries, MAX(updatedAt) AS lastUpdated
             FROM fraud_blocklist GROUP BY listType, source ORDER BY entries DESC`,
        ).catch(() => []);
        const [wl] = await this.db.query(`SELECT COUNT(*) AS n FROM fraud_whitelist`).catch(() => [{ n: 0 }]);
        const [manual] = await this.db.query(
            `SELECT COUNT(*) AS n FROM fraud_blocklist WHERE source = 'manual'`,
        ).catch(() => [{ n: 0 }]);
        return { lists, whitelistCount: Number(wl?.n || 0), manualBlocklistCount: Number(manual?.n || 0) };
    }

    // ── Feed sync ──────────────────────────────────────────────────────
    async syncSource(sourceKey: string): Promise<{ success: boolean; entries: number; message: string }> {
        const source = FRAUD_SOURCES[sourceKey];
        if (!source) return { success: false, entries: 0, message: 'Unknown source' };
        try {
            const data = await this.fetchUrl(source.url);
            const inserted = await this.parseAndStore(sourceKey, source.type, data);
            Logger.info(`Synced ${inserted} entries from ${source.name}`, loggerCtx);
            return { success: true, entries: inserted, message: `Synced ${inserted} entries from ${source.name}` };
        } catch (e: any) {
            Logger.error(`Feed sync failed for ${source.name}: ${e.message}`, loggerCtx);
            return { success: false, entries: 0, message: `Failed: ${e.message}` };
        }
    }

    /** Retry a statement a few times when InnoDB / Postgres reports a deadlock or lock timeout. */
    private async withLockRetry<T>(fn: () => Promise<T>, what: string): Promise<T> {
        let last: any;
        for (let attempt = 1; attempt <= 4; attempt++) {
            try { return await fn(); } catch (e: any) {
                const code = String(e?.code || e?.errno || '');
                const msg = String(e?.message || '');
                const retryable = code === 'ER_LOCK_DEADLOCK' || code === 'ER_LOCK_WAIT_TIMEOUT' || code === '40P01' || code === '1213' || code === '1205' || /deadlock|lock wait timeout/i.test(msg);
                if (!retryable || attempt === 4) throw e;
                last = e;
                Logger.warn(`${what}: ${msg.slice(0, 80)} — retry ${attempt}/3`, loggerCtx);
                await new Promise(r => setTimeout(r, 250 * attempt * attempt));
            }
        }
        throw last;
    }

    /** Delete rows by source in id-chunks (portable, short locks). */
    private async deleteSourceRows(source: string): Promise<number> {
        let removed = 0;
        for (;;) {
            const rows: any[] = await this.db.query(`SELECT id FROM fraud_blocklist WHERE source = ? ORDER BY id LIMIT 2000`, [source]);
            if (!rows.length) return removed;
            const ids = rows.map(r => Number(r.id));
            await this.withLockRetry(() => this.db.query(`DELETE FROM fraud_blocklist WHERE id IN (${ids.map(() => '?').join(',')})`, ids), `delete ${source}`);
            removed += ids.length;
        }
    }

    /**
     * Parse a line-based feed and replace this source's blocklist rows.
     * Unchanged feeds (same content hash as last time) are skipped entirely;
     * changed feeds are loaded under a staging source key first and swapped
     * in afterwards, so the live rows are never absent and every statement is
     * small enough not to block the order-scoring reads.
     */
    private async parseAndStore(sourceKey: string, type: string, data: string): Promise<number> {
        const lines = Array.from(new Set(
            data.split('\n')
                .map(l => l.trim())
                // Spamhaus DROP lines look like "1.2.3.0/24 ; SBL12345" — keep the CIDR only.
                .map(l => l.split(';')[0].split(/\s+/)[0].trim())
                .filter(l => l && !l.startsWith('#') && !l.startsWith('//'))
                .map(l => l.toLowerCase()),
        ));
        const contentHash = createHash('sha256').update(lines.join('\n')).digest('hex');
        const [state]: any[] = await this.db.query(`SELECT contentHash, entries FROM fraud_feed_state WHERE source = ?`, [sourceKey]).catch(() => []);
        if (state && state.contentHash === contentHash && Number(state.entries) === lines.length) {
            const [{ n }]: any[] = await this.db.query(`SELECT COUNT(*) AS n FROM fraud_blocklist WHERE source = ?`, [sourceKey]);
            if (Number(n) === lines.length) {
                await this.db.query(`UPDATE fraud_feed_state SET syncedAt = NOW() WHERE source = ?`, [sourceKey]).catch(() => undefined);
                return lines.length;
            }
        }
        const staging = `${sourceKey}~staging`;
        await this.deleteSourceRows(staging);
        const batchSize = 500;
        for (let i = 0; i < lines.length; i += batchSize) {
            const batch = lines.slice(i, i + batchSize);
            const placeholders = batch.map(() => `(?, ?, ?, '', NOW(), NOW())`).join(',');
            const params = batch.flatMap(v => [type, v, staging]);
            await this.withLockRetry(() => this.db.query(
                `INSERT INTO fraud_blocklist (listType, value, source, note, createdAt, updatedAt) VALUES ${placeholders}`,
                params,
            ), `insert ${sourceKey}`);
        }
        // Swap: old rows out, staging rows in — both in id-chunks.
        await this.deleteSourceRows(sourceKey);
        for (;;) {
            const rows: any[] = await this.db.query(`SELECT id FROM fraud_blocklist WHERE source = ? ORDER BY id LIMIT 2000`, [staging]);
            if (!rows.length) break;
            const ids = rows.map(r => Number(r.id));
            await this.withLockRetry(() => this.db.query(`UPDATE fraud_blocklist SET source = ? WHERE id IN (${ids.map(() => '?').join(',')})`, [sourceKey, ...ids]), `swap ${sourceKey}`);
        }
        await this.db.query(`DELETE FROM fraud_feed_state WHERE source = ?`, [sourceKey]).catch(() => undefined);
        await this.db.query(`INSERT INTO fraud_feed_state (source, contentHash, entries, syncedAt) VALUES (?, ?, ?, NOW())`, [sourceKey, contentHash, lines.length]).catch(() => undefined);
        return lines.length;
    }

    private syncInFlight = false;

    async syncAll(): Promise<{ results: any[] }> {
        if (this.syncInFlight) return { results: [{ source: 'all', success: false, entries: 0, message: 'A feed sync is already running' }] };
        this.syncInFlight = true;
        // Cross-process lock (server + worker, several instances): a database advisory lock. Both MariaDB's
        // GET_LOCK and Postgres advisory locks are bound to the session that took them, so one query runner
        // (one pooled connection) is held for the whole sync and releases it — going through the pool would
        // release on a different connection and leave the lock behind until that connection closed.
        const runner = this.connection.rawConnection.createQueryRunner();
        let dbLock = false;
        try {
            await runner.connect();
            const acquired = this.db.dialect === 'postgres'
                ? await runner.query(`SELECT pg_try_advisory_lock(${FEED_SYNC_LOCK_KEY}) AS ok`).catch(() => null)
                : await runner.query(`SELECT GET_LOCK('hulo_fraud_feed_sync', 0) AS ok`).catch(() => null);
            const row = Array.isArray(acquired) ? acquired[0] : null;
            if (row && (row.ok === false || row.ok === 0 || row.ok === '0' || row.ok === 'f')) {
                return { results: [{ source: 'all', success: false, entries: 0, message: 'A feed sync is already running in another process' }] };
            }
            dbLock = !!row;
            return await this.syncAllInner();
        } finally {
            this.syncInFlight = false;
            if (dbLock) {
                await (this.db.dialect === 'postgres'
                    ? runner.query(`SELECT pg_advisory_unlock(${FEED_SYNC_LOCK_KEY})`)
                    : runner.query(`SELECT RELEASE_LOCK('hulo_fraud_feed_sync')`)).catch(() => undefined);
            }
            await runner.release().catch(() => undefined);
        }
    }

    private async syncAllInner(): Promise<{ results: any[] }> {
        const results = [];
        for (const key of Object.keys(FRAUD_SOURCES)) {
            results.push({ source: key, ...(await this.syncSource(key)) });
        }
        // User-defined feeds ride the same nightly sync.
        for (const feed of await this.listCustomFeeds()) {
            if (!feed.enabled) continue;
            results.push({ source: `custom:${feed.id}`, name: feed.name, ...(await this.syncCustomFeed(feed.id)) });
        }
        return { results };
    }

    // ── Custom (user-defined) feeds ─────────────────────────────────────
    private customSourceKey(id: number): string { return `custom-${id}`; }

    async listCustomFeeds(): Promise<any[]> {
        return this.db.query(`SELECT * FROM fraud_custom_feed ORDER BY createdAt DESC`).catch(() => []);
    }

    async addCustomFeed(name: string, url: string, listType: string): Promise<{ ok: boolean; id?: number; message?: string }> {
        const cleanName = String(name || '').trim().slice(0, 120);
        const cleanUrl = String(url || '').trim().slice(0, 1024);
        const type = ['ip', 'ip_range', 'email_domain', 'email'].includes(listType) ? listType : 'ip';
        if (!cleanName) return { ok: false, message: 'A name is required.' };
        const urlErr = this.validateFeedUrl(cleanUrl);
        if (urlErr) return { ok: false, message: urlErr };
        const res = await this.db.query(
            `INSERT INTO fraud_custom_feed (name, url, listType, enabled, createdAt, updatedAt)
             VALUES (?, ?, ?, 1, NOW(), NOW())`,
            [cleanName, cleanUrl, type],
            { needInsertId: true },
        );
        return { ok: true, id: res.insertId };
    }

    async updateCustomFeed(id: number, patch: { name?: string; url?: string; listType?: string; enabled?: boolean }): Promise<{ ok: boolean; message?: string }> {
        const sets: string[] = [];
        const params: any[] = [];
        if (patch.name !== undefined) { sets.push('name = ?'); params.push(String(patch.name).trim().slice(0, 120)); }
        if (patch.url !== undefined) {
            const err = this.validateFeedUrl(String(patch.url).trim());
            if (err) return { ok: false, message: err };
            sets.push('url = ?'); params.push(String(patch.url).trim().slice(0, 1024));
        }
        if (patch.listType !== undefined && ['ip', 'ip_range', 'email_domain', 'email'].includes(patch.listType)) {
            sets.push('listType = ?'); params.push(patch.listType);
        }
        if (typeof patch.enabled === 'boolean') { sets.push('enabled = ?'); params.push(patch.enabled ? 1 : 0); }
        if (!sets.length) return { ok: true };
        sets.push('updatedAt = NOW()');
        params.push(id);
        await this.db.query(`UPDATE fraud_custom_feed SET ${sets.join(', ')} WHERE id = ?`, params);
        return { ok: true };
    }

    async removeCustomFeed(id: number): Promise<void> {
        await this.db.query(`DELETE FROM fraud_blocklist WHERE source = ?`, [this.customSourceKey(id)]);
        await this.db.query(`DELETE FROM fraud_custom_feed WHERE id = ?`, [id]);
    }

    async syncCustomFeed(id: number): Promise<{ success: boolean; entries: number; message: string }> {
        const rows = await this.db.query(`SELECT * FROM fraud_custom_feed WHERE id = ?`, [id]);
        const feed = rows[0];
        if (!feed) return { success: false, entries: 0, message: 'Feed not found' };
        try {
            const data = await this.fetchUrl(feed.url);
            const inserted = await this.parseAndStore(this.customSourceKey(id), feed.listType, data);
            await this.db.query(
                `UPDATE fraud_custom_feed SET lastSyncedAt = NOW(), lastCount = ?, lastError = NULL, updatedAt = NOW() WHERE id = ?`,
                [inserted, id],
            );
            Logger.info(`Synced ${inserted} entries from custom feed "${feed.name}"`, loggerCtx);
            return { success: true, entries: inserted, message: `Synced ${inserted} entries from ${feed.name}` };
        } catch (e: any) {
            await this.db.query(
                `UPDATE fraud_custom_feed SET lastSyncedAt = NOW(), lastError = ?, updatedAt = NOW() WHERE id = ?`,
                [String(e.message).slice(0, 255), id],
            );
            Logger.error(`Custom feed sync failed for "${feed.name}": ${e.message}`, loggerCtx);
            return { success: false, entries: 0, message: `Failed: ${e.message}` };
        }
    }

    /** Reject non-http(s) schemes and obvious internal targets (SSRF guard). */
    private validateFeedUrl(url: string): string | null {
        let u: URL;
        try { u = new URL(url); } catch { return 'That doesn\'t look like a valid URL.'; }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'Only http(s) feed URLs are supported.';
        const host = u.hostname.toLowerCase();
        const isPrivate =
            host === 'localhost' || host.endsWith('.localhost') ||
            /^127\./.test(host) || host === '::1' || host === '0.0.0.0' ||
            /^10\./.test(host) || /^192\.168\./.test(host) ||
            /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
            /^169\.254\./.test(host) || /^fe80:/i.test(host) || /^f[cd][0-9a-f]{2}:/i.test(host);
        if (isPrivate) return 'Internal / private addresses are not allowed for feed URLs.';
        return null;
    }

    private fetchUrl(url: string, hops = 0): Promise<string> {
        return new Promise((resolve, reject) => {
            if (hops > 4) return reject(new Error('Too many redirects'));
            const client = url.startsWith('https') ? https : http;
            const req = client.get(url, { timeout: 30_000 }, res => {
                if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    res.resume();
                    this.fetchUrl(res.headers.location, hops + 1).then(resolve).catch(reject);
                    return;
                }
                if (res.statusCode && res.statusCode >= 400) {
                    res.resume();
                    return reject(new Error(`HTTP ${res.statusCode}`));
                }
                const MAX_BYTES = 30 * 1024 * 1024; // 30 MB cap
                const chunks: Buffer[] = [];
                let bytes = 0;
                res.on('data', (chunk: Buffer) => {
                    bytes += chunk.length;
                    if (bytes > MAX_BYTES) { req.destroy(); reject(new Error('Feed too large (>30 MB)')); return; }
                    chunks.push(chunk);
                });
                res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        });
    }

    // ── IP intelligence cache ──────────────────────────────────────────
    private async getIpIntel(ip: string): Promise<IpIntel> {
        ip = normaliseIp(ip);
        const rows = await this.db.query(
            `SELECT * FROM fraud_ip_intel WHERE ip = ? AND checkedAt > DATE_SUB(NOW(), INTERVAL 30 DAY)`,
            [ip],
        ).catch(() => []);
        if (rows.length) {
            return {
                ip, countryCode: rows[0].countryCode || null,
                isVpnOrProxy: !!rows[0].isVpnOrProxy, isHosting: !!rows[0].isHosting, resolved: true,
            };
        }
        const intel = await lookupIpIntel(ip);
        if (intel.resolved) {
            await this.db.query(
                `INSERT INTO fraud_ip_intel (ip, countryCode, isVpnOrProxy, isHosting, checkedAt)
                 VALUES (?, ?, ?, ?, NOW())
                 ON DUPLICATE KEY UPDATE countryCode=VALUES(countryCode), isVpnOrProxy=VALUES(isVpnOrProxy),
                    isHosting=VALUES(isHosting), checkedAt=NOW()`,
                [intel.ip, intel.countryCode, intel.isVpnOrProxy ? 1 : 0, intel.isHosting ? 1 : 0],
                { conflictColumns: ['ip'] },
            ).catch(() => undefined);
        }
        return intel;
    }

    // ── Customer dossier (Lookup tab) ──────────────────────────────────
    async customerProfile(email: string): Promise<any> {
        const norm = normalizeEmail(email);
        if (!norm) return { error: 'invalid email' };
        const like = norm.canonical === norm.email ? [norm.email] : [norm.email, norm.canonical];
        const ph = like.map(() => '?').join(',');

        const [totals] = await this.db.query(
            `SELECT COUNT(*) AS orders,
                    COALESCE(SUM(o.\`subTotalWithTax\`), 0) AS lifetimeValue,
                    SUM(CASE WHEN o.state IN ('PaymentSettled','Delivered') THEN 1 ELSE 0 END) AS settled,
                    SUM(CASE WHEN o.state = 'Cancelled' THEN 1 ELSE 0 END) AS cancelled,
                    MIN(o.\`orderPlacedAt\`) AS firstOrder, MAX(o.\`orderPlacedAt\`) AS lastOrder
             FROM \`order\` o JOIN customer c ON c.id = o.\`customerId\`
             WHERE c.\`emailAddress\` IN (${ph})`, like,
        );
        const recentOrders = await this.db.query(
            `SELECT o.code, o.state, o.\`subTotalWithTax\` AS subTotalWithTax, o.\`orderPlacedAt\` AS orderPlacedAt, o.\`customFieldsIp\` AS ip
             FROM \`order\` o JOIN customer c ON c.id = o.\`customerId\`
             WHERE c.\`emailAddress\` IN (${ph})
             ORDER BY o.\`orderPlacedAt\` DESC LIMIT 10`, like,
        );
        const [failedPayments] = await this.db.query(
            `SELECT COUNT(*) AS n FROM payment p
             JOIN \`order\` o ON o.id = p.\`orderId\` JOIN customer c ON c.id = o.\`customerId\`
             WHERE c.\`emailAddress\` IN (${ph}) AND p.state IN ('Declined','Error','Cancelled')`, like,
        );
        const cases = await this.db.query(
            `SELECT id, orderCode, riskScore, status, createdAt, reviewNotes
             FROM fraud_blocked_orders WHERE email IN (${ph}) ORDER BY createdAt DESC LIMIT 10`, like,
        ).catch(() => []);
        const logRows = await this.db.query(
            `SELECT createdAt, orderCode, riskScore, riskLevel, action FROM fraud_log
             WHERE email IN (${ph}) ORDER BY createdAt DESC LIMIT 10`, like,
        ).catch(() => []);
        const onAllowlist = await this.isAllowlisted(norm.email, norm.domain, undefined);
        const blocked = await this.db.query(
            `SELECT id FROM fraud_blocklist
             WHERE (listType = 'email' AND value = ?) OR (listType = 'email_domain' AND value = ?) LIMIT 1`,
            [norm.email, norm.domain],
        ).catch(() => []);

        return {
            email: norm.email, canonical: norm.canonical, domain: norm.domain,
            usedPlusAddressing: norm.usedPlusAddressing,
            totals: totals || {}, recentOrders,
            failedPayments: Number(failedPayments?.n || 0),
            cases, log: logRows,
            onAllowlist, onBlocklist: blocked.length > 0,
        };
    }

    /** Silently blocklist a case's identity (email + canonical + IP) so
     *  future attempts stop at the door — used with quiet rejections so
     *  a fraudster learns nothing. */
    async blocklistCaseIdentity(caseRow: any, caseId: number): Promise<string[]> {
        const added: string[] = [];
        const note = `rejected case #${caseId}`;
        const norm = caseRow.email ? normalizeEmail(caseRow.email) : null;
        const values: Array<[string, string]> = [];
        if (norm) {
            values.push(['email', norm.email]);
            if (norm.canonical !== norm.email) values.push(['email', norm.canonical]);
        }
        if (caseRow.ip) values.push(['ip', String(caseRow.ip)]);
        for (const [type, value] of values) {
            const exists = await this.db.query(
                `SELECT id FROM fraud_blocklist WHERE listType = ? AND value = ? LIMIT 1`, [type, value],
            ).catch(() => []);
            if (!exists.length) {
                await this.addEntry('blocklist', type, value, note);
                added.push(`${type}:${value}`);
            }
        }
        return added;
    }

    // ── Auto-release (weekend safety valve) ────────────────────────────
    async autoReleaseStale(): Promise<number> {
        const configs = await this.db.query(
            `SELECT channelId, autoApproveAfterHours FROM fraud_config WHERE autoApproveAfterHours > 0`,
        ).catch(() => []);
        let released = 0;
        for (const cfg of configs) {
            const stale = await this.db.query(
                `SELECT id FROM fraud_blocked_orders
                 WHERE status = 'pending' AND channelId = ?
                   AND createdAt < DATE_SUB(NOW(), INTERVAL ? HOUR)`,
                [cfg.channelId, cfg.autoApproveAfterHours],
            ).catch(() => []);
            for (const row of stale) {
                const r = await this.resolveCase(Number(row.id), 'approved',
                    `auto-approved after ${cfg.autoApproveAfterHours}h unreviewed`);
                if (r.ok) {
                    released++;
                    Logger.warn(`Fraud case #${row.id} auto-approved after ${cfg.autoApproveAfterHours}h`, loggerCtx);
                    if (r.caseRow?.email) {
                        await this.sendCustomerTemplate(Number(cfg.channelId), 'approved', r.caseRow.email,
                            { orderCode: r.caseRow.orderCode }).catch(() => undefined);
                    }
                    await this.notifyOps({
                        event: 'case.auto_released',
                        text: `⏱ Fraud case #${row.id} (order ${r.caseRow?.orderCode || '?'}) auto-approved after ${cfg.autoApproveAfterHours}h unreviewed`,
                        orderCode: r.caseRow?.orderCode,
                    }).catch(() => undefined);
                }
            }
        }
        return released;
    }

    // ── Ops notifications (Slack / Discord / Teams / Telegram / webhook) ─
    async notifyOps(ev: OpsEvent): Promise<void> {
        try {
            const rows = await this.db.query(`SELECT * FROM fraud_notification_config LIMIT 1`).catch(() => []);
            if (!rows.length) return;
            await fanOutOpsEvent(rows[0], ev);
        } catch (e: any) {
            Logger.debug(`Ops fan-out failed: ${e.message}`, loggerCtx);
        }
    }

    /** Back-compat alias for 0.2.0 callers. */
    async sendSlackAlert(text: string): Promise<void> {
        await this.notifyOps({ event: 'case.held', text });
    }

    // ── Customer message templates ─────────────────────────────────────
    async getTemplates(channelId: number): Promise<Record<MessageKind, { subject: string; body: string; isDefault: boolean }>> {
        const rows = await this.db.query(
            `SELECT kind, subject, body FROM fraud_message_templates WHERE channelId = ?`, [channelId],
        ).catch(() => []);
        const out: any = {};
        for (const kind of ['held', 'approved', 'rejected'] as MessageKind[]) {
            const row = rows.find((r: any) => r.kind === kind);
            out[kind] = row
                ? { subject: row.subject, body: row.body, isDefault: false }
                : { ...DEFAULT_TEMPLATES[kind], isDefault: true };
        }
        return out;
    }

    async saveTemplate(channelId: number, kind: MessageKind, subject: string, body: string): Promise<void> {
        await this.db.query(
            `INSERT INTO fraud_message_templates (channelId, kind, subject, body) VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE subject = VALUES(subject), body = VALUES(body)`,
            [channelId, kind, subject, body],
            { conflictColumns: ['channelId', 'kind'] },
        );
    }

    async resetTemplate(channelId: number, kind: MessageKind): Promise<void> {
        await this.db.query(
            `DELETE FROM fraud_message_templates WHERE channelId = ? AND kind = ?`, [channelId, kind],
        );
    }

    /** Render + send the customer message for a gating outcome. */
    async sendCustomerTemplate(
        channelId: number,
        kind: MessageKind,
        to: string,
        vars: { orderCode?: string; firstName?: string },
    ): Promise<void> {
        const templates = await this.getTemplates(channelId);
        const cfg = await this.getConfig(channelId);
        const notif = await this.getNotificationConfig();
        const allVars = {
            orderCode: vars.orderCode || '',
            firstName: vars.firstName || 'there',
            supportEmail: notif.adminEmail || this.options.defaultAdminEmail || '',
            reviewHours: cfg.reviewHours ?? 24,
        };
        const subject = renderTemplate(templates[kind].subject, allVars);
        const bodyHtml = renderBody(renderTemplate(templates[kind].body, allVars));
        await this.sendCustomerNotice(to, subject, bodyHtml);
    }

    // ── Notifications ──────────────────────────────────────────────────
    async getNotificationConfig(): Promise<any> {
        return this.cached('notif', 30_000, () => this.loadNotificationConfig());
    }

    private async loadNotificationConfig(): Promise<any> {
        const rows = await this.db.query(`SELECT * FROM fraud_notification_config LIMIT 1`).catch(() => []);
        const smtp = this.smtpSettings();
        return {
            adminEmail: rows[0]?.adminEmail || this.options.defaultAdminEmail || smtp?.from || '',
            notifyOnBlocked: rows[0] ? !!rows[0].notifyOnBlocked : true,
            notifyOnHighRisk: rows[0] ? !!rows[0].notifyOnHighRisk : true,
            notifyOnApproval: rows[0] ? !!rows[0].notifyOnApproval : true,
            notifyOnRejection: rows[0] ? (rows[0].notifyOnRejection == null ? true : !!rows[0].notifyOnRejection) : true,
            blocklistOnReject: rows[0] ? !!rows[0].blocklistOnReject : false,
            slackWebhookUrl: rows[0]?.slackWebhookUrl || '',
            discordWebhookUrl: rows[0]?.discordWebhookUrl || '',
            teamsWebhookUrl: rows[0]?.teamsWebhookUrl || '',
            telegramBotToken: rows[0]?.telegramBotToken || '',
            telegramChatId: rows[0]?.telegramChatId || '',
            genericWebhookUrl: rows[0]?.genericWebhookUrl || '',
            genericWebhookSecret: rows[0]?.genericWebhookSecret || '',
            smtpConfigured: !!smtp,
        };
    }

    async saveNotificationConfig(body: any): Promise<void> {
        this.forget('notif');
        await this.db.query(
            `INSERT INTO fraud_notification_config (id, adminEmail, notifyOnBlocked, notifyOnHighRisk, notifyOnApproval, notifyOnRejection, blocklistOnReject,
                slackWebhookUrl, discordWebhookUrl, teamsWebhookUrl, telegramBotToken, telegramChatId,
                genericWebhookUrl, genericWebhookSecret)
             VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE adminEmail=VALUES(adminEmail), notifyOnBlocked=VALUES(notifyOnBlocked),
                notifyOnHighRisk=VALUES(notifyOnHighRisk), notifyOnApproval=VALUES(notifyOnApproval),
                notifyOnRejection=VALUES(notifyOnRejection), blocklistOnReject=VALUES(blocklistOnReject),
                slackWebhookUrl=VALUES(slackWebhookUrl), discordWebhookUrl=VALUES(discordWebhookUrl),
                teamsWebhookUrl=VALUES(teamsWebhookUrl), telegramBotToken=VALUES(telegramBotToken),
                telegramChatId=VALUES(telegramChatId), genericWebhookUrl=VALUES(genericWebhookUrl),
                genericWebhookSecret=VALUES(genericWebhookSecret)`,
            [body.adminEmail || '', body.notifyOnBlocked ? 1 : 0, body.notifyOnHighRisk ? 1 : 0, body.notifyOnApproval ? 1 : 0,
             body.notifyOnRejection ? 1 : 0, body.blocklistOnReject ? 1 : 0,
             body.slackWebhookUrl || null, body.discordWebhookUrl || null, body.teamsWebhookUrl || null,
             body.telegramBotToken || null, body.telegramChatId || null,
             body.genericWebhookUrl || null, body.genericWebhookSecret || null],
            { conflictColumns: ['id'] },
        );
    }

    private smtpSettings() {
        if (this.options.smtp) return this.options.smtp;
        if (process.env.SMTP_SERVER && process.env.SMTP_USER) {
            return {
                host: process.env.SMTP_SERVER,
                port: Number(process.env.SMTP_PORT || 587),
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASSWORD || '',
                from: process.env.SMTP_FROM || process.env.SMTP_USER,
            };
        }
        return null;
    }

    private mailer: { key: string; transport: any } | null = null;
    private transporter(smtp: { host: string; port: number; user: string; pass: string }) {
        const key = `${smtp.host}:${smtp.port}:${smtp.user}`;
        if (this.mailer?.key !== key) {
            try { this.mailer?.transport?.close?.(); } catch { /* ignore */ }
            this.mailer = { key, transport: nodemailer.createTransport({
                host: smtp.host, port: smtp.port, secure: smtp.port === 465, auth: { user: smtp.user, pass: smtp.pass },
                pool: true, maxConnections: 2, maxMessages: 100, connectionTimeout: 10_000, greetingTimeout: 10_000, socketTimeout: 20_000,
            } as any) };
        }
        return this.mailer.transport;
    }
    private sendWithDeadline(message: any, ms = 25_000): Promise<void> {
        const smtp = this.smtpSettings();
        if (!smtp) return Promise.resolve();
        let timer: any;
        return Promise.race([
            this.transporter(smtp).sendMail(message).then(() => undefined),
            new Promise<void>((_, reject) => { timer = setTimeout(() => reject(new Error(`SMTP send timed out after ${ms / 1000}s`)), ms); }),
        ]).finally(() => clearTimeout(timer));
    }

    async sendAdminAlert(subject: string, html: string): Promise<void> {
        try {
            const smtp = this.smtpSettings();
            if (!smtp) return;
            const cfg = await this.getNotificationConfig();
            if (!cfg.adminEmail) return;
            await this.sendWithDeadline({
                from: smtp.from, to: cfg.adminEmail,
                subject: `[Fraud Alert] ${subject}`,
                html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">${html}</div>`,
            });
        } catch (e: any) {
            Logger.error(`Admin alert failed: ${e.message}`, loggerCtx);
        }
    }

    async sendCustomerNotice(to: string, subject: string, html: string): Promise<void> {
        try {
            const smtp = this.smtpSettings();
            if (!smtp || !to) return;
            await this.sendWithDeadline({
                from: smtp.from, to, subject,
                html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">${html}</div>`,
            });
        } catch (e: any) {
            Logger.error(`Customer notice failed: ${e.message}`, loggerCtx);
        }
    }
}

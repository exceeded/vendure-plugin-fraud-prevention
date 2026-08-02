import { Injectable, OnModuleInit } from '@nestjs/common';
import { Logger, TransactionalConnection } from '@vendure/core';
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
import { ipInCidr, normalizeEmail } from './net-util';

const loggerCtx = 'FraudPrevention';

export interface AssessInput {
    channelId: number;
    ip?: string;
    email?: string;
    orderValuePence: number;
    countryCode?: string;
    orderId?: number;
    orderCode?: string;
    /** True when this customer has at least one prior settled order. */
    isReturningCustomer?: boolean;
    /** Dry-run: skip logging + case creation (Simulate tab). */
    dryRun?: boolean;
}

@Injectable()
export class FraudPreventionService implements OnModuleInit {
    private options: FraudPreventionPluginOptions = {};

    constructor(private connection: TransactionalConnection) {}

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
        return this.connection.rawConnection;
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
            CREATE TABLE IF NOT EXISTS fraud_notification_config (
                id INT PRIMARY KEY DEFAULT 1,
                adminEmail VARCHAR(255),
                notifyOnBlocked TINYINT DEFAULT 1,
                notifyOnHighRisk TINYINT DEFAULT 1,
                notifyOnApproval TINYINT DEFAULT 1
            )`);
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

    async getConfig(channelId: number): Promise<FraudChannelConfig> {
        const rows = await this.db.query(`SELECT * FROM fraud_config WHERE channelId = ?`, [channelId]).catch(() => []);
        if (rows.length) return this.rowToConfig(rows[0]);
        return { ...DEFAULT_CONFIG, channelId };
    }

    async saveConfig(c: FraudChannelConfig): Promise<void> {
        await this.db.query(
            `INSERT INTO fraud_config (channelId, enabled, mode, reviewThreshold, blockThreshold, holdFulfilment,
                maxOrdersPerIpPerHour, maxOrdersPerIpPerDay, maxOrdersPerEmailPerDay, maxDailyValuePerEmailPence,
                maxOrderValuePence, requireEmailVerificationAbovePence, blockDisposableEmails, blockVpnProxy,
                blockHighRiskCountries, highRiskCountries, enforce3dSecure, maxFailedPaymentsPerIpPerHour,
                cooldownMinutesAfterFailedPayment, signalWeights)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                enabled=VALUES(enabled), mode=VALUES(mode), reviewThreshold=VALUES(reviewThreshold),
                blockThreshold=VALUES(blockThreshold), holdFulfilment=VALUES(holdFulfilment),
                maxOrdersPerIpPerHour=VALUES(maxOrdersPerIpPerHour), maxOrdersPerIpPerDay=VALUES(maxOrdersPerIpPerDay),
                maxOrdersPerEmailPerDay=VALUES(maxOrdersPerEmailPerDay), maxDailyValuePerEmailPence=VALUES(maxDailyValuePerEmailPence),
                maxOrderValuePence=VALUES(maxOrderValuePence), requireEmailVerificationAbovePence=VALUES(requireEmailVerificationAbovePence),
                blockDisposableEmails=VALUES(blockDisposableEmails), blockVpnProxy=VALUES(blockVpnProxy),
                blockHighRiskCountries=VALUES(blockHighRiskCountries), highRiskCountries=VALUES(highRiskCountries),
                enforce3dSecure=VALUES(enforce3dSecure), maxFailedPaymentsPerIpPerHour=VALUES(maxFailedPaymentsPerIpPerHour),
                cooldownMinutesAfterFailedPayment=VALUES(cooldownMinutesAfterFailedPayment), signalWeights=VALUES(signalWeights)`,
            [
                c.channelId, c.enabled ? 1 : 0, c.mode, c.reviewThreshold, c.blockThreshold, c.holdFulfilment ? 1 : 0,
                c.maxOrdersPerIpPerHour, c.maxOrdersPerIpPerDay, c.maxOrdersPerEmailPerDay, c.maxDailyValuePerEmailPence,
                c.maxOrderValuePence, c.requireEmailVerificationAbovePence, c.blockDisposableEmails ? 1 : 0,
                c.blockVpnProxy ? 1 : 0, c.blockHighRiskCountries ? 1 : 0, c.highRiskCountries || '',
                c.enforce3dSecure ? 1 : 0, c.maxFailedPaymentsPerIpPerHour, c.cooldownMinutesAfterFailedPayment,
                JSON.stringify(c.signalWeights || {}),
            ],
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
            if (points > 0) signals.push({ key, label, points, detail });
        };

        if (!cfg.enabled || cfg.mode === 'off') {
            return { score: 0, level: 'low', signals: [], allowlisted: false, action: 'allow', mode: cfg.mode };
        }

        const norm = input.email ? normalizeEmail(input.email) : null;

        // 0. Allowlist — trusted identities bypass everything.
        if (await this.isAllowlisted(norm?.email, norm?.domain, input.ip)) {
            return { score: 0, level: 'low', signals: [], allowlisted: true, action: 'allow', mode: cfg.mode };
        }

        // 1. Blocklists (manual + feeds), incl. CIDR ranges.
        if (norm) {
            const hits = await this.db.query(
                `SELECT listType, source, value FROM fraud_blocklist
                 WHERE (listType = 'email' AND value = ?) OR (listType = 'email_domain' AND value = ?) LIMIT 3`,
                [norm.email, norm.domain],
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
                // CIDR ranges: match the /8 prefix candidates in SQL first so we
                // never scan all rows, then verify precisely in JS.
                const firstOctet = input.ip.split('.')[0];
                const ranges = await this.db.query(
                    `SELECT source, value FROM fraud_blocklist
                     WHERE listType = 'ip_range' AND (value LIKE ? OR value LIKE '0.%')
                     LIMIT 2000`,
                    [`${firstOctet}.%`],
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
                 WHERE customFieldsIp = ? AND orderPlacedAt > DATE_SUB(NOW(), INTERVAL 1 HOUR)`,
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
                 WHERE customFieldsIp = ? AND orderPlacedAt > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
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
                `SELECT COUNT(*) AS cnt, COALESCE(SUM(o.subTotalWithTax), 0) AS totalValue
                 FROM \`order\` o JOIN customer c ON c.id = o.customerId
                 WHERE LOWER(c.emailAddress) IN (${like.map(() => '?').join(',')})
                   AND o.orderPlacedAt > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
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

        // 6. Order value.
        if (input.orderValuePence > cfg.maxOrderValuePence) {
            push('order_value', 'High order value',
                `£${(input.orderValuePence / 100).toFixed(2)} > £${(cfg.maxOrderValuePence / 100).toFixed(2)} limit`);
        }

        // 7. First order + high value.
        if (input.isReturningCustomer === false
            && input.orderValuePence > cfg.requireEmailVerificationAbovePence) {
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

        // 9. Failed payments from this IP.
        if (input.ip) {
            const [fpRow] = await this.db.query(
                `SELECT COUNT(*) AS cnt FROM payment p JOIN \`order\` o ON o.id = p.orderId
                 WHERE o.customFieldsIp = ? AND p.state IN ('Declined', 'Error', 'Cancelled')
                   AND p.createdAt > DATE_SUB(NOW(), INTERVAL 1 HOUR)`,
                [input.ip],
            );
            const cnt = Number(fpRow?.cnt || 0);
            if (cnt >= cfg.maxFailedPaymentsPerIpPerHour) {
                push('failed_payments', 'Failed payments', `${cnt} failed payments from IP in the last hour`);
            }
        }

        const score = Math.min(signals.reduce((s, x) => s + x.points, 0), 100);
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
            if (!FraudPreventionPlugin.isLicensed()) effectiveMode = 'monitor';
        }

        let action: FraudAssessment['action'] = 'allow';
        if (level === 'review' || level === 'blocked') {
            action = effectiveMode === 'enforce' ? (level === 'blocked' ? 'block' : 'review') : 'flag';
        }

        return { score, level, signals, allowlisted: false, action, mode: effectiveMode };
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
        }
        return false;
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
        const res = await this.db.query(
            `INSERT INTO fraud_blocked_orders (orderId, orderCode, channelId, ip, email, riskScore, riskLevel, reasons, signals, status, createdAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
            [
                input.orderId || null, input.orderCode || null, input.channelId,
                input.ip || '', input.email || '', a.score, a.level,
                a.signals.map(s => `${s.label}: ${s.detail}`).join('; '),
                JSON.stringify(a.signals),
            ],
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

    async listCases(status?: string, take = 100): Promise<any[]> {
        const where = status ? `WHERE bo.status = ?` : '';
        return this.db.query(
            `SELECT bo.*, o.code AS liveOrderCode, o.state AS orderState, o.subTotalWithTax,
                    c.firstName, c.lastName, c.emailAddress
             FROM fraud_blocked_orders bo
             LEFT JOIN \`order\` o ON o.id = bo.orderId
             LEFT JOIN customer c ON c.id = o.customerId
             ${where} ORDER BY bo.createdAt DESC LIMIT ${Math.min(take, 500)}`,
            status ? [status] : [],
        ).catch(() => []);
    }

    async resolveCase(id: number, decision: 'approved' | 'rejected', notes?: string): Promise<{ ok: boolean; message: string; caseRow?: any }> {
        const rows = await this.db.query(`SELECT * FROM fraud_blocked_orders WHERE id = ?`, [id]);
        if (!rows.length) return { ok: false, message: 'Case not found' };
        const c = rows[0];
        if (c.status !== 'pending') return { ok: false, message: `Already ${c.status}` };
        await this.db.query(
            `UPDATE fraud_blocked_orders SET status = ?, reviewedAt = NOW(), reviewNotes = ? WHERE id = ?`,
            [decision, notes || null, id],
        );
        if (decision === 'rejected' && c.orderId) {
            await this.db.query(`UPDATE \`order\` SET active = 0 WHERE id = ? AND active = 1`, [c.orderId]);
        }
        await this.db.query(
            `INSERT INTO fraud_log (channelId, orderId, orderCode, ip, email, riskScore, riskLevel, reasons, action, createdAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [c.channelId, c.orderId, c.orderCode, c.ip, c.email, c.riskScore, decision, notes || `${decision} by admin`, decision],
        );
        return { ok: true, message: `Case ${decision}`, caseRow: c };
    }

    // ── Stats for the Overview tab ─────────────────────────────────────
    async stats(days = 7): Promise<any> {
        const d = Math.max(1, Math.min(days, 90));
        const [totals] = await this.db.query(
            `SELECT COUNT(*) AS assessed,
                    SUM(riskLevel IN ('review','blocked')) AS flagged,
                    SUM(action = 'review') AS held,
                    SUM(action = 'block') AS blocked
             FROM fraud_log WHERE createdAt > DATE_SUB(NOW(), INTERVAL ? DAY)
               AND action IN ('allow','flag','review','block')`,
            [d],
        );
        const daily = await this.db.query(
            `SELECT DATE(createdAt) AS day, COUNT(*) AS assessed,
                    SUM(riskLevel IN ('review','blocked')) AS flagged
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
            `SELECT COUNT(*) AS totalOrders, COUNT(DISTINCT customFieldsIp) AS uniqueIps,
                    COALESCE(SUM(subTotalWithTax), 0) AS totalValue
             FROM \`order\` WHERE orderPlacedAt > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
        );
        const [failed24] = await this.db.query(
            `SELECT COUNT(*) AS n FROM payment WHERE state IN ('Declined','Error','Cancelled')
             AND createdAt > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
        );
        const topIps = await this.db.query(
            `SELECT customFieldsIp AS ip, COUNT(*) AS n FROM \`order\`
             WHERE orderPlacedAt > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND customFieldsIp IS NOT NULL AND customFieldsIp <> ''
             GROUP BY customFieldsIp ORDER BY n DESC LIMIT 8`,
        );
        return {
            totals: totals || {}, daily, byLevel: topSignals,
            pendingCases: Number(pending?.n || 0),
            orders24: orders24 || {}, failedPayments24: Number(failed24?.n || 0),
            topIps,
        };
    }

    async log(filter: { level?: string; action?: string; take?: number }): Promise<any[]> {
        const clauses: string[] = [`action IS NOT NULL`];
        const params: any[] = [];
        if (filter.level) { clauses.push(`riskLevel = ?`); params.push(filter.level); }
        if (filter.action) { clauses.push(`action = ?`); params.push(filter.action); }
        return this.db.query(
            `SELECT * FROM fraud_log WHERE ${clauses.join(' AND ')}
             ORDER BY createdAt DESC LIMIT ${Math.min(filter.take || 100, 500)}`,
            params,
        ).catch(() => []);
    }

    async pruneLog(retentionDays: number): Promise<number> {
        if (!retentionDays || retentionDays <= 0) return 0;
        const res = await this.db.query(
            `DELETE FROM fraud_log WHERE createdAt < DATE_SUB(NOW(), INTERVAL ? DAY)`,
            [retentionDays],
        );
        return res.affectedRows || 0;
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
        const v = value.trim().toLowerCase();
        if (!v) throw new Error('Empty value');
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
            const lines = data.split('\n')
                .map(l => l.trim())
                // Spamhaus DROP lines look like "1.2.3.0/24 ; SBL12345" — keep the CIDR only.
                .map(l => l.split(';')[0].trim())
                .filter(l => l && !l.startsWith('#') && !l.startsWith('//'));

            await this.db.query(`DELETE FROM fraud_blocklist WHERE source = ?`, [sourceKey]);

            const batchSize = 500;
            let inserted = 0;
            for (let i = 0; i < lines.length; i += batchSize) {
                const batch = lines.slice(i, i + batchSize);
                const placeholders = batch.map(() => `(?, ?, ?, '', NOW(), NOW())`).join(',');
                const params = batch.flatMap(v => [source.type, v.toLowerCase(), sourceKey]);
                await this.db.query(
                    `INSERT IGNORE INTO fraud_blocklist (listType, value, source, note, createdAt, updatedAt) VALUES ${placeholders}`,
                    params,
                );
                inserted += batch.length;
            }
            Logger.info(`Synced ${inserted} entries from ${source.name}`, loggerCtx);
            return { success: true, entries: inserted, message: `Synced ${inserted} entries from ${source.name}` };
        } catch (e: any) {
            Logger.error(`Feed sync failed for ${source.name}: ${e.message}`, loggerCtx);
            return { success: false, entries: 0, message: `Failed: ${e.message}` };
        }
    }

    async syncAll(): Promise<{ results: any[] }> {
        const results = [];
        for (const key of Object.keys(FRAUD_SOURCES)) {
            results.push({ source: key, ...(await this.syncSource(key)) });
        }
        return { results };
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
                let data = '';
                res.on('data', (chunk: Buffer) => (data += chunk.toString()));
                res.on('end', () => resolve(data));
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        });
    }

    // ── Notifications ──────────────────────────────────────────────────
    async getNotificationConfig(): Promise<any> {
        const rows = await this.db.query(`SELECT * FROM fraud_notification_config LIMIT 1`).catch(() => []);
        const smtp = this.smtpSettings();
        return {
            adminEmail: rows[0]?.adminEmail || this.options.defaultAdminEmail || smtp?.from || '',
            notifyOnBlocked: rows[0] ? !!rows[0].notifyOnBlocked : true,
            notifyOnHighRisk: rows[0] ? !!rows[0].notifyOnHighRisk : true,
            notifyOnApproval: rows[0] ? !!rows[0].notifyOnApproval : true,
            smtpConfigured: !!smtp,
        };
    }

    async saveNotificationConfig(body: any): Promise<void> {
        await this.db.query(
            `INSERT INTO fraud_notification_config (id, adminEmail, notifyOnBlocked, notifyOnHighRisk, notifyOnApproval)
             VALUES (1, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE adminEmail=VALUES(adminEmail), notifyOnBlocked=VALUES(notifyOnBlocked),
                notifyOnHighRisk=VALUES(notifyOnHighRisk), notifyOnApproval=VALUES(notifyOnApproval)`,
            [body.adminEmail || '', body.notifyOnBlocked ? 1 : 0, body.notifyOnHighRisk ? 1 : 0, body.notifyOnApproval ? 1 : 0],
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

    async sendAdminAlert(subject: string, html: string): Promise<void> {
        try {
            const smtp = this.smtpSettings();
            if (!smtp) return;
            const cfg = await this.getNotificationConfig();
            if (!cfg.adminEmail) return;
            const transporter = nodemailer.createTransport({
                host: smtp.host, port: smtp.port, secure: smtp.port === 465,
                auth: { user: smtp.user, pass: smtp.pass },
            });
            await transporter.sendMail({
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
            const transporter = nodemailer.createTransport({
                host: smtp.host, port: smtp.port, secure: smtp.port === 465,
                auth: { user: smtp.user, pass: smtp.pass },
            });
            await transporter.sendMail({
                from: smtp.from, to, subject,
                html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">${html}</div>`,
            });
        } catch (e: any) {
            Logger.error(`Customer notice failed: ${e.message}`, loggerCtx);
        }
    }
}

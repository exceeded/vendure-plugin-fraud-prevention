/**
 * Shared types for @huloglobal/vendure-plugin-fraud-prevention.
 *
 * The engine is signal-based: every check contributes a weighted number
 * of points; the total maps to a level via per-channel thresholds, and
 * the channel's mode decides what actually happens.
 */

export type FraudMode = 'off' | 'monitor' | 'enforce';

export type RiskLevel = 'low' | 'medium' | 'review' | 'blocked';

/** One fired signal in an assessment — the audit trail's atom. */
export interface FraudSignal {
    key: string;
    label: string;
    points: number;
    detail: string;
}

export interface FraudAssessment {
    score: number;
    level: RiskLevel;
    signals: FraudSignal[];
    allowlisted: boolean;
    /** What the engine decided to do given the channel mode. */
    action: 'allow' | 'flag' | 'review' | 'block';
    mode: FraudMode;
}

/** Per-channel configuration row (table `fraud_config`). */
export interface FraudChannelConfig {
    channelId: number;
    channelCode?: string;
    enabled: boolean;
    mode: FraudMode;
    // Thresholds — score >= reviewThreshold => review; >= blockThreshold => blocked
    reviewThreshold: number;
    blockThreshold: number;
    // When a case is pending, hold licence-key fulfilment (host integrates)
    holdFulfilment: boolean;
    // Velocity limits
    maxOrdersPerIpPerHour: number;
    maxOrdersPerIpPerDay: number;
    maxOrdersPerEmailPerDay: number;
    maxDailyValuePerEmailPence: number;
    // Value limits
    maxOrderValuePence: number;
    requireEmailVerificationAbovePence: number;
    // Signals toggles
    blockDisposableEmails: boolean;
    blockVpnProxy: boolean;
    blockHighRiskCountries: boolean;
    highRiskCountries: string;
    enforce3dSecure: boolean;
    // Failed payments
    maxFailedPaymentsPerIpPerHour: number;
    cooldownMinutesAfterFailedPayment: number;
    /** Auto-approve pending cases after N hours (0 = never). Weekend
     *  safety valve so held orders don't strand while nobody reviews. */
    autoApproveAfterHours: number;
    /** JSON map of signal key -> points override. Empty = defaults. */
    signalWeights: Record<string, number>;
}

/** Default signal weights — overridable per channel via signalWeights. */
export const DEFAULT_WEIGHTS: Record<string, number> = {
    disposable_email: 50,
    vpn_proxy: 35,
    hosting_ip: 30,
    geo_mismatch: 30,
    email_no_mx: 45,
    identity_fanout: 45,
    gibberish_email: 10,
    country_mismatch: 10,
    returning_customer_2: -12,
    returning_customer_3plus: -25,
    blocklist_email: 60,
    blocklist_email_domain: 45,
    blocklist_ip: 55,
    blocklist_ip_range: 55,
    ip_velocity_hour: 40,
    ip_velocity_day: 30,
    ip_velocity_warm: 15,
    email_velocity_day: 35,
    email_value_day: 30,
    order_value: 25,
    high_risk_country: 40,
    failed_payments: 45,
    plus_addressing: 12,
    new_customer_high_value: 18,
};

export const DEFAULT_CONFIG: Omit<FraudChannelConfig, 'channelId' | 'channelCode'> = {
    enabled: true,
    mode: 'monitor',
    reviewThreshold: 40,
    blockThreshold: 70,
    holdFulfilment: true,
    maxOrdersPerIpPerHour: 5,
    maxOrdersPerIpPerDay: 20,
    maxOrdersPerEmailPerDay: 10,
    maxDailyValuePerEmailPence: 1_000_000,
    maxOrderValuePence: 500_000,
    requireEmailVerificationAbovePence: 100_000,
    blockDisposableEmails: true,
    blockVpnProxy: false,
    blockHighRiskCountries: false,
    highRiskCountries: '',
    enforce3dSecure: true,
    maxFailedPaymentsPerIpPerHour: 3,
    cooldownMinutesAfterFailedPayment: 15,
    autoApproveAfterHours: 0,
    signalWeights: {},
};

export interface FraudPreventionPluginOptions {
    /** Public-facing host, used in admin notification links. */
    publicBaseUrl?: string;
    /** Where fraud-alert admin emails go when no per-install setting exists. */
    defaultAdminEmail?: string;
    /** SMTP transport. Falls back to SMTP_SERVER/SMTP_PORT/SMTP_USER/
     *  SMTP_PASSWORD/SMTP_FROM env vars when omitted. */
    smtp?: {
        host: string;
        port: number;
        user: string;
        pass: string;
        from: string;
    };
    /** Rate limit for the public /fraud-prevention/check endpoint. */
    rateLimit?: { capacity: number; windowMs: number };
    /** Prune fraud_log rows older than this many days. Default 180; 0 = keep forever. */
    logRetentionDays?: number;
    /** Disable the daily threat-feed sync cron (default false). */
    disableFeedSync?: boolean;
}

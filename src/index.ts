/**
 * `@huloglobal/vendure-plugin-fraud-prevention` — public exports.
 *
 * `FraudPreventionPlugin` registers the assessment engine, the order
 * guard, the admin REST surface and the multi-tab admin UI.
 * `FraudPreventionService` is exported so host projects can integrate —
 * most importantly `pendingOrderIds()` for gating fulfilment on open
 * review cases, and `assess()` for custom checkout flows.
 */

export { FraudPreventionPlugin, FraudPluginInitOptions, getOptions } from './plugin';
export { FraudPreventionService, AssessInput } from './fraud-prevention.service';
export {
    DEFAULT_CONFIG,
    DEFAULT_WEIGHTS,
    FraudAssessment,
    FraudChannelConfig,
    FraudMode,
    FraudPreventionPluginOptions,
    FraudSignal,
    RiskLevel,
} from './types';
export { FRAUD_SOURCES, CUSTOM_FEED_PRESETS } from './fraud-sources';
export { ipInCidr, ipv4ToInt, normalizeEmail } from './net-util';

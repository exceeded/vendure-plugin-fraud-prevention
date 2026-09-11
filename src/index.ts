/**
 * `@huloglobal/vendure-plugin-fraud-prevention` — public exports.
 *
 * `FraudPreventionPlugin` registers the assessment engine, the order
 * guard, the admin REST surface and the multi-tab admin UI.
 * `FraudPreventionService` is exported so host projects can integrate —
 * most importantly `pendingOrderIds()` / `heldOrderIds()` and
 * `isAssessed()` for gating fulfilment on review cases, and `assess()`
 * for custom checkout flows.
 */

export { FraudPreventionPlugin, FraudPluginInitOptions, getOptions } from './plugin';
export { FraudPreventionService, AssessInput, ResolveCaseResult } from './fraud-prevention.service';
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
export {
    AvsCheck,
    AvsResult,
    CardChecks,
    RadarRiskLevel,
    ThreeDsResult,
    avsFromMetadata,
    avsFromStripeCharge,
    cardChecksFromMetadata,
    cardChecksFromStripeCharge,
    fetchStripeAvs,
    fetchStripeCardChecks,
    normalisePostcode,
    parseAvsCheck,
    parseRiskLevel,
    parseThreeDsAuthenticated,
    postcodesDiffer,
    threeDsFailed,
} from './avs';

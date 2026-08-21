import { PluginCommonModule, Type, VendurePlugin } from '@vendure/core';
import {
    fingerprintPublicKey,
    Heartbeat,
    LicenceStatus,
    RevocationChecker,
    UpdateChecker,
    verifyLicence,
    warnIfIncompatibleVendure, EvaluationClient, EvaluationState } from '@huloglobal/vendure-licence-sdk';

import { FraudPreventionService } from './fraud-prevention.service';
import { FraudPreventionController } from './fraud-prevention.controller';
import { FraudOrderGuard } from './order-guard';
import { FraudCrons } from './crons';
import { FraudPreventionPluginOptions } from './types';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const PKG_VERSION: string = require('../package.json').version;
const PKG_NAME = '@huloglobal/vendure-plugin-fraud-prevention';
const PLUGIN_ID = 'vendure-plugin-fraud-prevention';

const HULO_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoLmNM5UljRqe71drM6lR
Ba5vXrLOcV3GAHkYvnVFQSqdE0avrge/jsD7WdA6x8qQFNRugxQcxDJa2l0+C+BH
SbU9TimGwhA1yusHHfuz9LAXks5IQ48+2e6Pulh7iThXPJUnIKqKZUN5HhL79aaK
vrZKIgSfVhwE5PMPXWZ+Ij5IRf74PLIUn1Er75qhBXlDJ4vF8y8/3owURNC1XiUB
DGElwV/LYNoqAQei4oixe4EAxPGvFi11pgHiGuRxuWckA88y6ZHLt6urfAY9sCkj
kF+2dc2yS3j7lD+SYAaV5LQYYjePP1CYvxCZ7HHRKqthHopxY1hsK2tBtni3f7/c
UwIDAQAB
-----END PUBLIC KEY-----`;

const REVOCATION_URL = process.env.HULO_LICENCE_REVOCATION_URL
    || 'https://elite.charity/licence/revoked.json';

export interface FraudPluginInitOptions extends FraudPreventionPluginOptions {
    /** JWT licence key from huloglobal.com. Without a valid licence the
     *  plugin runs in the FREE tier: monitor mode + manual lists +
     *  simulate. `enforce` mode, threat-feed sync, email alerts and
     *  custom signal weights require a licence. */
    licenceKey?: string;
}

let cachedOptions: FraudPluginInitOptions = {};
export function getOptions(): FraudPluginInitOptions { return cachedOptions; }

/**
 * `@huloglobal/vendure-plugin-fraud-prevention`
 *
 * Signal-based order risk scoring with real enforcement. Every placed
 * order is assessed server-side (velocity, disposable emails,
 * block/allow lists incl. CIDR feeds, high-risk countries, failed
 * payments, plus-addressing abuse); per-channel thresholds decide
 * allow / review / block, and a manual review queue with an
 * approve/reject workflow holds licence fulfilment until a human
 * decides. Threat feeds (FireHOL, Spamhaus DROP, Tor exits,
 * disposable-email domains) sync daily.
 */
@VendurePlugin({
    imports: [PluginCommonModule],
    controllers: [FraudPreventionController],
    providers: [FraudPreventionService, FraudOrderGuard, FraudCrons],
    compatibility: '^3.0.0',
})
export class FraudPreventionPlugin {
    private static evalClientInternal: EvaluationClient | null = null;
    static getEvalState(): EvaluationState | null { return FraudPreventionPlugin.evalClientInternal?.getState() ?? null; }
    static getEvalInstanceId(): string | null { return FraudPreventionPlugin.evalClientInternal?.getInstanceId() ?? null; }
    /** Licensed installs AND installs inside the 14-day server-anchored
     *  evaluation window get the full feature set. After the window the
     *  plugin drops to the free tier. */
    static hasPremiumAccess(): boolean {
        if (FraudPreventionPlugin.licenceStatus?.valid) return true;
        return !!FraudPreventionPlugin.evalClientInternal?.getState()?.active;
    }
    static startEvaluation(): void {
        if (!FraudPreventionPlugin.evalClientInternal) {
            FraudPreventionPlugin.evalClientInternal = new EvaluationClient({ packageName: PKG_NAME, packageVersion: PKG_VERSION });
            FraudPreventionPlugin.evalClientInternal.start();
        }
    }

    constructor(service: FraudPreventionService) {
        // Anonymous aggregates for the (opt-in) evaluation reminder emails.
        FraudPreventionPlugin.evalClientInternal?.setStatsProvider(() => service.evalStats());
    }

    private static revocation: RevocationChecker | null = null;
    private static updateChecker: UpdateChecker | null = null;
    private static heartbeat: Heartbeat | null = null;
    private static licenceStatus: LicenceStatus | null = null;

    static getUpdateChecker(): UpdateChecker | null { return FraudPreventionPlugin.updateChecker; }
    static getPackageVersion(): string { return PKG_VERSION; }
    static getPackageName(): string { return PKG_NAME; }
    /** Read by controller + service to gate premium features. */
    static getLicenceStatus(): LicenceStatus | null { return FraudPreventionPlugin.licenceStatus; }
    static isLicensed(): boolean { return !!FraudPreventionPlugin.licenceStatus?.valid; }

    static init(options: FraudPluginInitOptions = {}): Type<FraudPreventionPlugin> {
        cachedOptions = options;

        warnIfIncompatibleVendure({
            pluginPackageName: PKG_NAME,
            pluginPackageVersion: PKG_VERSION,
            supportedRange: { min: '3.5.0', max: '4.0.0' },
        });

        if (!FraudPreventionPlugin.revocation) {
            FraudPreventionPlugin.revocation = new RevocationChecker(REVOCATION_URL);
            FraudPreventionPlugin.revocation.start();
        }
        if (!FraudPreventionPlugin.updateChecker) {
            FraudPreventionPlugin.updateChecker = new UpdateChecker(PKG_NAME, PKG_VERSION);
            FraudPreventionPlugin.updateChecker.start();
        }

        const host = (options.publicBaseUrl || '')
            .replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        const status = verifyLicence({
            licenceKey: options.licenceKey,
            pluginId: PLUGIN_ID,
            host,
            publicKey: HULO_PUBLIC_KEY,
            revokedIds: FraudPreventionPlugin.revocation.getRevokedIds(),
        });
        FraudPreventionPlugin.licenceStatus = status;

        if (!status.valid) {
            // Unlicensed: start the server-anchored 14-day full-featured
            // evaluation; premium paths stay on until it expires.
            FraudPreventionPlugin.startEvaluation();
            // eslint-disable-next-line no-console
            console.warn(
                `[${PKG_NAME}] ${status.message}` +
                ` — Running in FREE tier: monitor mode, manual lists and simulate only.` +
                ` Enforce mode, review-queue holds, threat-feed sync and email alerts` +
                ` require a licence: https://huloglobal.com/vendure-plugins/fraud-prevention/`,
            );
        }

        if (!FraudPreventionPlugin.heartbeat) {
            FraudPreventionPlugin.heartbeat = new Heartbeat({
                packageName: PKG_NAME,
                packageVersion: PKG_VERSION,
                licenceKey: options.licenceKey,
                publicKeyFingerprint: fingerprintPublicKey(HULO_PUBLIC_KEY),
            });
            FraudPreventionPlugin.heartbeat.start();
        }

        return FraudPreventionPlugin;
    }

    static uiExtensions = {
        extensionPath: __dirname + '/../ui',
        ngModules: [
            {
                type: 'lazy' as const,
                route: 'fraud-prevention',
                ngModuleFileName: 'fraud-prevention.module.ts',
                ngModuleName: 'FraudPreventionModule',
            },
        ],
    };
}

import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { Logger, ProcessContext } from '@vendure/core';
import { FraudPreventionService } from './fraud-prevention.service';
import { FraudPreventionPlugin, getOptions } from './plugin';

const loggerCtx = 'FraudPrevention';

@Injectable()
export class FraudCrons {
    constructor(
        private service: FraudPreventionService,
        private processContext: ProcessContext,
    ) {}

    /** Daily threat-feed refresh (licensed installs only). */
    @Cron(CronExpression.EVERY_DAY_AT_3AM)
    async syncFeeds() {
        if (this.processContext.isServer) return; // worker only
        if (getOptions().disableFeedSync) return;
        if (!FraudPreventionPlugin.isLicensed()) return;
        Logger.info('Daily threat-feed sync starting…', loggerCtx);
        const { results } = await this.service.syncAll();
        for (const r of results) {
            if (r.success) Logger.info(`  ✓ ${r.source}: ${r.entries} entries`, loggerCtx);
            else Logger.warn(`  ✗ ${r.source}: ${r.message}`, loggerCtx);
        }
    }

    /** Hourly auto-release of stale pending cases (per-channel opt-in). */
    @Cron(CronExpression.EVERY_HOUR)
    async autoRelease() {
        if (this.processContext.isServer) return;
        const n = await this.service.autoReleaseStale();
        if (n > 0) Logger.info(`Auto-released ${n} stale fraud case(s)`, loggerCtx);
    }

    /** Nightly audit-log retention. */
    @Cron(CronExpression.EVERY_DAY_AT_4AM)
    async pruneLog() {
        if (this.processContext.isServer) return;
        const days = getOptions().logRetentionDays ?? 180;
        const removed = await this.service.pruneLog(days);
        if (removed > 0) Logger.info(`Pruned ${removed} fraud_log rows older than ${days}d`, loggerCtx);
    }
}

import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { EventBus, Logger, OrderPlacedEvent, ProcessContext } from '@vendure/core';
import { FraudPreventionService, AssessInput } from './fraud-prevention.service';

const loggerCtx = 'FraudPrevention';

/**
 * The enforcement point the old implementation never had: every placed
 * order is assessed server-side. What happens then depends on the
 * channel's mode:
 *
 *   off      -> nothing, not even a log row
 *   monitor  -> assessment logged; flagged orders marked 'flag' but never held
 *   enforce  -> score >= reviewThreshold opens a pending review case
 *               (hosts gate fulfilment on pendingOrderIds()); score >=
 *               blockThreshold additionally tells the customer the order
 *               is under verification and alerts the admin
 *
 * Runs on the server process only — the worker would double-assess.
 */
@Injectable()
export class FraudOrderGuard implements OnApplicationBootstrap {
    constructor(
        private eventBus: EventBus,
        private service: FraudPreventionService,
        private processContext: ProcessContext,
    ) {}

    onApplicationBootstrap() {
        if (!this.processContext.isServer) return;
        this.eventBus.ofType(OrderPlacedEvent).subscribe(async event => {
            try {
                await this.handleOrderPlaced(event);
            } catch (e: any) {
                Logger.error(`Order assessment failed for ${event.order?.code}: ${e.message}`, loggerCtx);
            }
        });
    }

    private async handleOrderPlaced(event: OrderPlacedEvent) {
        const order = event.order;
        const channelId = Number(event.ctx.channelId || 1);
        const email = order.customer?.emailAddress || '';

        const input: AssessInput = {
            channelId,
            ip: (order.customFields as any)?.ip || undefined,
            email,
            orderValuePence: order.subTotalWithTax || 0,
            countryCode: order.billingAddress?.countryCode || order.shippingAddress?.countryCode || undefined,
            shippingCountryCode: order.shippingAddress?.countryCode || undefined,
            orderId: Number(order.id),
            orderCode: order.code,
            // customer history is computed inside the service by canonical
            // email, so plus-tag variants share one track record
        };

        const assessment = await this.service.assess(input);

        // Always log — shadow assessments included, so the score history
        // has no blind spots even while protection is switched off.
        await this.service.logAssessment(input, assessment);

        if (assessment.protectionActive === false) {
            if (assessment.action === 'shadow') {
                Logger.warn(
                    `Order ${order.code} scored ${assessment.score}/100 (${assessment.level}) but fraud protection is OFF — no action taken. ` +
                    `Signals: ${assessment.signals.map(s => s.label).join(', ')}`,
                    loggerCtx,
                );
                await this.service.notifyOps({
                    event: 'shadow.risky',
                    text: `⚠️ Fraud protection is OFF, but order ${order.code} scored ${assessment.score}/100 (${assessment.level}). ` +
                        `No action was taken. Signals: ${assessment.signals.map(s => s.label).join(', ')}. ` +
                        `Enable protection in the Fraud Prevention settings to act on orders like this.`,
                    orderCode: order.code,
                    email,
                    score: assessment.score,
                    level: assessment.level,
                    signals: assessment.signals.map(s => ({ key: s.key, label: s.label, points: s.points })),
                });
                const notif = await this.service.getNotificationConfig();
                if (notif.notifyOnHighRisk) {
                    await this.service.sendAdminAlert(
                        `Protection inactive: order ${order.code} scored ${assessment.score}/100`,
                        `<h2>⚠️ Fraud protection scored this order — but is switched OFF</h2>
                         <p><strong>Order:</strong> ${order.code}</p>
                         <p><strong>Customer:</strong> ${email}</p>
                         <p><strong>Risk score:</strong> ${assessment.score}/100 (${assessment.level})</p>
                         <ul>${assessment.signals.map(s => `<li>${s.label} (+${s.points}): ${s.detail}</li>`).join('')}</ul>
                         <p><strong>No action was taken</strong> because protection is disabled for this channel.
                         Enable it in Fraud Prevention → Settings to hold orders like this automatically.</p>`,
                    );
                }
            }
            return;
        }

        if (assessment.action === 'allow' || assessment.action === 'flag') {
            if (assessment.action === 'flag') {
                Logger.warn(
                    `Order ${order.code} flagged (score ${assessment.score}, monitor mode): ` +
                    assessment.signals.map(s => s.label).join(', '),
                    loggerCtx,
                );
            }
            return;
        }

        // enforce mode, review or block
        const caseId = await this.service.createCase(input, assessment);
        Logger.warn(
            `Order ${order.code} held for review (case #${caseId}, score ${assessment.score}, action ${assessment.action})`,
            loggerCtx,
        );

        await this.service.notifyOps({
            event: 'case.held',
            text: `🚨 Order ${order.code} held for review — score ${assessment.score}/100 (${assessment.level}). ` +
                assessment.signals.map(s => s.label).join(', '),
            orderCode: order.code,
            email,
            score: assessment.score,
            level: assessment.level,
            signals: assessment.signals.map(s => ({ key: s.key, label: s.label, points: s.points })),
        });

        const notif = await this.service.getNotificationConfig();
        const wantAdminMail = assessment.action === 'block' ? notif.notifyOnBlocked : notif.notifyOnHighRisk;
        if (wantAdminMail) {
            const base = this.service.getOptions().publicBaseUrl || '';
            await this.service.sendAdminAlert(
                `Order ${order.code} held for review (score ${assessment.score})`,
                `<h2>${assessment.action === 'block' ? '🚫 High-risk order held' : '⚠️ Order held for review'}</h2>
                 <p><strong>Order:</strong> ${order.code}</p>
                 <p><strong>Customer:</strong> ${email}</p>
                 <p><strong>Risk score:</strong> ${assessment.score}/100 (${assessment.level})</p>
                 <ul>${assessment.signals.map(s => `<li>${s.label} (+${s.points}): ${s.detail}</li>`).join('')}</ul>
                 <p>Licence fulfilment is held until the case is resolved.</p>
                 ${base ? `<p><a href="${base}/admin/extensions/fraud-prevention">Review in Admin →</a></p>` : ''}`,
            );
        }

        // Customer-facing held notice — per-channel policy + template.
        const cfg = await this.service.getConfig(channelId);
        const policy = (cfg as any).notifyCustomerOnHold || 'block';
        const shouldTell = policy === 'always' || (policy === 'block' && assessment.action === 'block');
        if (shouldTell && email) {
            await this.service.sendCustomerTemplate(channelId, 'held', email, {
                orderCode: order.code,
                firstName: (order.customer as any)?.firstName || undefined,
            });
        }
    }
}

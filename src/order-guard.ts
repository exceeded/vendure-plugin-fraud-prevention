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

        let isReturning: boolean | undefined;
        try {
            if (order.customer?.id) {
                const rows = await (this.service as any).connection.rawConnection.query(
                    `SELECT COUNT(*) AS n FROM \`order\`
                     WHERE customerId = ? AND id <> ? AND state IN ('PaymentSettled', 'Delivered')`,
                    [order.customer.id, order.id],
                );
                isReturning = Number(rows[0]?.n || 0) > 0;
            }
        } catch { /* signal simply won't fire */ }

        const input: AssessInput = {
            channelId,
            ip: (order.customFields as any)?.ip || undefined,
            email,
            orderValuePence: order.subTotalWithTax || 0,
            countryCode: order.billingAddress?.countryCode || order.shippingAddress?.countryCode || undefined,
            orderId: Number(order.id),
            orderCode: order.code,
            isReturningCustomer: isReturning,
        };

        const assessment = await this.service.assess(input);
        if (assessment.mode === 'off') return;

        await this.service.logAssessment(input, assessment);

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

        if (assessment.action === 'block' && email) {
            await this.service.sendCustomerNotice(
                email,
                'Your order is being verified',
                `<h2>Order verification</h2>
                 <p>Thanks for your order <strong>${order.code}</strong>. As part of our standard security
                 checks it has been selected for a quick manual verification, which usually completes
                 within a few business hours. You'll receive your licence keys as soon as it's approved —
                 no action is needed from you.</p>`,
            );
        }
    }
}

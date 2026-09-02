import { Body, Controller, Delete, Get, Param, Post, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { Ctx, Permission, RequestContext } from '@vendure/core';
import { RateLimiter, performSelfUpdate, selfUpdateEnv } from '@huloglobal/vendure-licence-sdk';

import { FraudPreventionService } from './fraud-prevention.service';
import { FraudPreventionPlugin } from './plugin';
import { CUSTOM_FEED_PRESETS, FRAUD_SOURCES } from './fraud-sources';
import { FraudChannelConfig } from './types';

/** Admin surface requires a logged-in admin with catalog permissions —
 *  same convention as the rest of the HULO suite. Returns true when the
 *  request was rejected (response already sent). */
function denyUnlessAdmin(ctx: RequestContext, res: Response, write: boolean): boolean {
    const needed = write ? [Permission.UpdateCatalog] : [Permission.ReadCatalog];
    if (!ctx.userHasPermissions(needed)) {
        res.status(403).json({ error: 'forbidden' });
        return true;
    }
    return false;
}

@Controller('fraud-prevention')
export class FraudPreventionController {
    private limiter = new RateLimiter({ capacity: 60, windowMs: 60_000 });

    constructor(private service: FraudPreventionService) {}

    // ── Public: storefront pre-check (rate limited) ────────────────────
    @Post('check')
    async check(@Req() req: Request, @Res() res: Response, @Body() body: any) {
        const ip = (req.headers['cf-connecting-ip'] as string)
            || (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
            || req.socket.remoteAddress || '';
        if (!this.limiter.allow(`check:${ip}`)) {
            return res.status(429).json({ error: 'rate_limited' });
        }
        const assessment = await this.service.assess({
            channelId: Number(body.channelId || 1),
            ip: body.ip || ip,
            email: body.email,
            orderValuePence: Number(body.orderValuePence || 0),
            countryCode: body.countryCode || (req.headers['cf-ipcountry'] as string) || undefined,
            dryRun: true,
        });
        // Public shape stays minimal — no signal internals for attackers to
        // probe. Explicit 200: a risk check is a read, not a 201 "create"
        // (Nest's default status for a POST handler).
        return res.status(200).json({
            allowed: assessment.action !== 'block',
            riskLevel: assessment.level,
        });
    }

    // ── Admin: meta (version + update banner) ──────────────────────────
    @Get('meta')
    async meta(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        const updater = FraudPreventionPlugin.getUpdateChecker();
        const licence = FraudPreventionPlugin.getLicenceStatus();
        return res.json({
            name: FraudPreventionPlugin.getPackageName(),
            version: FraudPreventionPlugin.getPackageVersion(),
            update: updater ? updater.getStatus() : null,
            selfUpdate: selfUpdateEnv(),
            licensed: !!licence?.valid,
            licenceMessage: licence?.valid ? '' : (licence?.message || 'No licence key configured'),
            tier: licence?.valid ? 'paid' : (FraudPreventionPlugin.getEvalState()?.active ? 'trial' : 'free'),
            eval: FraudPreventionPlugin.getEvalState(),
        });
    }

    /** One-click in-app update (owner-approved feature): installs a
     *  registry-verified version of THIS plugin via the host's package
     *  manager and restarts under the process supervisor. Admin-only;
     *  package name is hard-coded; HULO_SELF_UPDATE=off disables. */
    @Post('update/run')
    async updateRun(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: any) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const updater = FraudPreventionPlugin.getUpdateChecker();
        const target = String(body?.version || updater?.getStatus()?.latest || '').trim();
        if (!target) return res.status(400).json({ ok: false, message: 'No target version known yet — the registry check runs daily; try again shortly.' });
        const result = await performSelfUpdate({ packageName: FraudPreventionPlugin.getPackageName(), targetVersion: target });
        return res.status(result.ok ? 200 : 400).json(result);
    }

    /** Admin-UI licence activation: paste the key from the purchase
     *  email, verified with exactly the boot-time checks, applied
     *  immediately (no .env edit, no redeploy) and persisted. */
    @Post('licence/activate')
    async licenceActivate(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: any) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const key = String(body?.key || '').trim();
        if (!key) return res.status(400).json({ licensed: false, message: 'Paste your licence key first.' });
        const status = FraudPreventionPlugin.activateRuntimeLicence(key);
        if (!status.valid) return res.status(400).json({ licensed: false, message: status.message || 'Invalid licence key.' });
        await this.service.saveStoredLicenceKey(key);
        return res.json({ licensed: true, message: status.message });
    }

    /** Remove an admin-activated key (env-configured keys are unaffected). */
    @Post('licence/deactivate')
    async licenceDeactivate(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        await this.service.clearStoredLicenceKey();
        FraudPreventionPlugin.deactivateRuntimeLicence();
        return res.json({ licensed: false });
    }

    /** Buy-from-admin: mint a claim token and return the HULO buy-page
     *  URL. Once checkout completes the licence server binds the claim to
     *  the minted key and `licence/claim-status` installs it — no email
     *  round-trip, no .env edit, no restart. */
    @Post('licence/purchase-link')
    async licencePurchaseLink(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: any) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const plan = (['monthly', 'annual', 'lifetime'].includes(String(body?.plan)) ? String(body.plan) : 'annual') as 'monthly' | 'annual' | 'lifetime';
        try {
            const r = await this.purchaseClaimClient().createPurchaseLink(plan, String(body?.email || '').trim() || undefined);
            return res.json({ url: r.url, state: 'pending' });
        } catch (e: any) {
            return res.status(500).json({ message: e?.message || 'Could not start the purchase — try again shortly.' });
        }
    }

    /** Poll target for the admin page while a purchase is pending; with
     *  `?check=1` it asks the licence server right now and installs the
     *  key if it is ready. Installed claims are re-checked daily so a
     *  renewed subscription key lands automatically too. */
    @Get('licence/claim-status')
    async licenceClaimStatus(@Ctx() ctx: RequestContext, @Res() res: Response, @Query('check') check?: string) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        const client = this.purchaseClaimClient();
        const st = check ? await client.checkNow() : await client.status();
        return res.json({ ...st, licensed: FraudPreventionPlugin.isLicensed() });
    }

    /** Buy-from-admin auto-install client (hooks live here so the service
     *  never has to import the plugin class). */
    private purchaseClaimClient() {
        return this.service.initPurchaseClaim({
            packageName: FraudPreventionPlugin.getPackageName(),
            instanceId: () => FraudPreventionPlugin.getEvalInstanceId(),
            onLicence: async (key: string) => {
                const status = FraudPreventionPlugin.activateRuntimeLicence(key);
                if (!status.valid) return false;
                await this.service.saveStoredLicenceKey(key);
                return true;
            },
        });
    }

    async onApplicationBootstrap() {
        await this.purchaseClaimClient().resume().catch(() => undefined);
    }

    /** Admin opt-in: "email me before my evaluation ends". Proxied
     *  server-to-server to the HULO licence server, which sends a
     *  welcome email and runs the reminder drip. Explicit consent only. */
    @Post('eval/remind-me')
    async evalRemindMe(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: any) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const email = String(body?.email || '').trim();
        const instanceId = FraudPreventionPlugin.getEvalInstanceId();
        if (!email || !instanceId) return res.status(400).json({ error: 'bad-request' });
        try {
            const base = (process.env.HULO_LICENCE_EVAL_URL || 'https://elite.charity/licence/eval/register').replace(/\/register$/, '');
            const resp = await fetch(`${base}/lead`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ plugin: FraudPreventionPlugin.getPackageName(), instanceId, email }),
            });
            if (!resp.ok) return res.status(502).json({ error: 'upstream', status: resp.status });
            return res.json({ ok: true });
        } catch {
            return res.status(502).json({ error: 'unreachable' });
        }
    }

    // ── Admin: config ──────────────────────────────────────────────────
    @Get('config')
    async getConfig(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.getAllConfigs());
    }

    @Post('config')
    async saveConfig(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: { configs: FraudChannelConfig[] }) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        let saved = 0;
        for (const cfg of body.configs || []) {
            await this.service.saveConfig(cfg);
            saved++;
        }
        return res.json({ success: true, saved });
    }

    // ── Admin: overview stats ──────────────────────────────────────────
    @Get('stats')
    async stats(@Ctx() ctx: RequestContext, @Res() res: Response, @Query('days') days?: string) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.stats(Number(days || 7)));
    }

    // ── Admin: activity log ────────────────────────────────────────────
    @Get('log')
    async log(
        @Ctx() ctx: RequestContext, @Res() res: Response,
        @Query('level') level?: string, @Query('action') action?: string, @Query('take') take?: string,
    ) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.log({ level, action, take: Number(take || 100) }));
    }

    // ── Admin: review queue ────────────────────────────────────────────
    @Get('cases')
    async cases(@Ctx() ctx: RequestContext, @Res() res: Response, @Query('status') status?: string) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.listCases(status || undefined));
    }

    @Post('cases/:id/approve')
    async approve(
        @Ctx() ctx: RequestContext, @Res() res: Response, @Param('id') id: string,
        @Body() body: { notes?: string; notifyCustomer?: boolean },
    ) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const result = await this.service.resolveCase(Number(id), 'approved', body?.notes);
        if (result.ok && result.caseRow?.email) {
            const notif = await this.service.getNotificationConfig();
            // Per-case override wins; otherwise the settings default.
            const notify = body?.notifyCustomer !== undefined ? !!body.notifyCustomer : !!notif.notifyOnApproval;
            if (notify) {
                await this.service.sendCustomerTemplate(
                    Number(result.caseRow.channelId), 'approved', result.caseRow.email,
                    { orderCode: result.caseRow.orderCode },
                );
            }
            await this.service.notifyOps({
                event: 'case.approved',
                text: `✅ Fraud case approved — order ${result.caseRow.orderCode || ''} released${notify ? '' : ' (customer not notified)'}`,
                orderCode: result.caseRow.orderCode,
            });
        }
        return res.json(result);
    }

    @Post('cases/:id/reject')
    async reject(
        @Ctx() ctx: RequestContext, @Res() res: Response, @Param('id') id: string,
        @Body() body: { notes?: string; notifyCustomer?: boolean; blocklistIdentity?: boolean },
    ) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const result = await this.service.resolveCase(Number(id), 'rejected', body?.notes);
        if (result.ok && result.caseRow) {
            const notif = await this.service.getNotificationConfig();
            const notify = body?.notifyCustomer !== undefined ? !!body.notifyCustomer : !!notif.notifyOnRejection;
            if (notify && result.caseRow.email) {
                await this.service.sendCustomerTemplate(
                    Number(result.caseRow.channelId), 'rejected', result.caseRow.email,
                    { orderCode: result.caseRow.orderCode },
                );
            }
            const doBlock = body?.blocklistIdentity !== undefined ? !!body.blocklistIdentity : !!notif.blocklistOnReject;
            let blocked: string[] = [];
            if (doBlock) {
                blocked = await this.service.blocklistCaseIdentity(result.caseRow, Number(id));
            }
            await this.service.notifyOps({
                event: 'case.rejected',
                text: `🚫 Fraud case rejected — order ${result.caseRow.orderCode || ''} cancelled` +
                    `${notify ? '' : ' (customer not notified)'}${blocked.length ? ` — identity blocklisted (${blocked.join(', ')})` : ''}`,
                orderCode: result.caseRow.orderCode,
            });
            return res.json({ ...result, blocklisted: blocked });
        }
        return res.json(result);
    }

    // ── Admin: simulate (dry-run, full signal breakdown) ───────────────
    @Post('simulate')
    async simulate(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: any) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        const assessment = await this.service.assess({
            channelId: Number(body.channelId || 1),
            ip: body.ip || undefined,
            email: body.email || undefined,
            orderValuePence: Number(body.orderValuePence || 0),
            countryCode: body.countryCode || undefined,
            shippingCountryCode: body.shippingCountryCode || undefined,
            isReturningCustomer: body.isReturningCustomer,
            dryRun: true,
        });
        return res.json(assessment);
    }

    // ── Admin: customer dossier (Lookup tab) ───────────────────────────
    @Get('customer-profile')
    async customerProfile(@Ctx() ctx: RequestContext, @Res() res: Response, @Query('email') email?: string) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        if (!email) return res.status(400).json({ error: 'email required' });
        return res.json(await this.service.customerProfile(email));
    }

    // ── Admin: customer message templates ──────────────────────────────
    @Get('templates')
    async getTemplates(@Ctx() ctx: RequestContext, @Res() res: Response, @Query('channelId') channelId?: string) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.getTemplates(Number(channelId || 1)));
    }

    @Post('templates')
    async saveTemplates(
        @Ctx() ctx: RequestContext, @Res() res: Response,
        @Body() body: { channelId: number; kind: string; subject: string; body: string; reset?: boolean },
    ) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        if (!['held', 'approved', 'rejected'].includes(body.kind)) {
            return res.status(400).json({ error: 'bad kind' });
        }
        if (body.reset) {
            await this.service.resetTemplate(Number(body.channelId), body.kind as any);
        } else {
            await this.service.saveTemplate(Number(body.channelId), body.kind as any, body.subject || '', body.body || '');
        }
        return res.json({ success: true });
    }

    @Post('templates/preview')
    async previewTemplate(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: { subject: string; body: string; channelId?: number }) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        const { renderTemplate, renderBody } = await import('./templates');
        const notif = await this.service.getNotificationConfig();
        const cfg = await this.service.getConfig(Number(body.channelId || 1));
        const vars = {
            orderCode: 'DEMO12345678', firstName: 'Sam',
            supportEmail: notif.adminEmail || 'support@example.com',
            reviewHours: (cfg as any).reviewHours ?? 24,
        };
        return res.json({
            subject: renderTemplate(body.subject || '', vars),
            html: renderBody(renderTemplate(body.body || '', vars)),
        });
    }

    // ── Admin: lists ───────────────────────────────────────────────────
    @Get('lists/sources')
    async sources(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(Object.entries(FRAUD_SOURCES).map(([key, s]) => ({ key, ...s })));
    }

    @Get('lists/status')
    async listStatus(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.listStatus());
    }

    @Get('lists/:list')
    async listEntries(@Ctx() ctx: RequestContext, @Res() res: Response, @Param('list') list: string) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        if (list !== 'whitelist' && list !== 'blocklist') return res.status(400).json({ error: 'bad list' });
        return res.json(await this.service.listEntries(list));
    }

    @Post('lists/:list')
    async addEntry(
        @Ctx() ctx: RequestContext, @Res() res: Response,
        @Param('list') list: string, @Body() body: { type: string; value: string; note?: string },
    ) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        if (list !== 'whitelist' && list !== 'blocklist') return res.status(400).json({ error: 'bad list' });
        await this.service.addEntry(list, body.type, body.value, body.note);
        return res.json({ success: true });
    }

    @Delete('lists/:list/:id')
    async removeEntry(@Ctx() ctx: RequestContext, @Res() res: Response, @Param('list') list: string, @Param('id') id: string) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        if (list !== 'whitelist' && list !== 'blocklist') return res.status(400).json({ error: 'bad list' });
        await this.service.removeEntry(list, Number(id));
        return res.json({ success: true });
    }

    /** Fraud panel on the admin order-detail page. */
    @Get('order-assessment/:orderId')
    async orderAssessment(@Ctx() ctx: RequestContext, @Res() res: Response, @Param('orderId') orderId: string) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        const id = Number(orderId);
        if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'bad-order-id' });
        return res.json(await this.service.orderAssessment(id));
    }

    // ── Custom feeds (user-defined threat-list URLs) ───────────────────
    /** Curated well-known feeds for one-click adding in the UI. */
    @Get('feeds/presets')
    async feedPresets(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(CUSTOM_FEED_PRESETS);
    }

    @Get('feeds/custom')
    async customFeeds(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.listCustomFeeds());
    }

    @Post('feeds/custom')
    async addCustomFeed(
        @Ctx() ctx: RequestContext, @Res() res: Response,
        @Body() body: { name: string; url: string; listType: string },
    ) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        if (!FraudPreventionPlugin.hasPremiumAccess()) {
            return res.status(402).json({ error: 'licence_required', message: 'Custom feeds require a licence.' });
        }
        const result = await this.service.addCustomFeed(body.name, body.url, body.listType);
        return res.status(result.ok ? 200 : 400).json(result);
    }

    @Post('feeds/custom/:id')
    async updateCustomFeed(
        @Ctx() ctx: RequestContext, @Res() res: Response, @Param('id') id: string,
        @Body() body: { name?: string; url?: string; listType?: string; enabled?: boolean; sync?: boolean },
    ) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        if (body?.sync) {
            if (!FraudPreventionPlugin.hasPremiumAccess()) {
                return res.status(402).json({ error: 'licence_required', message: 'Feed sync requires a licence.' });
            }
            return res.json(await this.service.syncCustomFeed(Number(id)));
        }
        const result = await this.service.updateCustomFeed(Number(id), body);
        return res.status(result.ok ? 200 : 400).json(result);
    }

    @Delete('feeds/custom/:id')
    async removeCustomFeed(@Ctx() ctx: RequestContext, @Res() res: Response, @Param('id') id: string) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        await this.service.removeCustomFeed(Number(id));
        return res.json({ ok: true });
    }

    @Post('lists/sync')
    async sync(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: { sourceKey?: string }) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        if (!FraudPreventionPlugin.hasPremiumAccess()) {
            return res.status(402).json({
                error: 'licence_required',
                message: 'Threat-feed sync requires a licence — https://huloglobal.com/vendure-plugins/fraud-prevention/',
            });
        }
        if (body?.sourceKey) return res.json(await this.service.syncSource(body.sourceKey));
        return res.json(await this.service.syncAll());
    }

    // ── Admin: notifications ───────────────────────────────────────────
    @Get('notification-config')
    async getNotif(@Ctx() ctx: RequestContext, @Res() res: Response) {
        if (denyUnlessAdmin(ctx, res, false)) return;
        return res.json(await this.service.getNotificationConfig());
    }

    @Post('notification-config')
    async saveNotif(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: any) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        await this.service.saveNotificationConfig(body);
        return res.json({ success: true });
    }
}

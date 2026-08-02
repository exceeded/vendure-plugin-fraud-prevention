import { Body, Controller, Delete, Get, Param, Post, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { Ctx, Permission, RequestContext } from '@vendure/core';
import { RateLimiter } from '@huloglobal/vendure-licence-sdk';

import { FraudPreventionService } from './fraud-prevention.service';
import { FraudPreventionPlugin } from './plugin';
import { FRAUD_SOURCES } from './fraud-sources';
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
        // Public shape stays minimal — no signal internals for attackers to probe.
        return res.json({
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
            licensed: !!licence?.valid,
            licenceMessage: licence?.valid ? '' : (licence?.message || 'No licence key configured'),
        });
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
        const { renderTemplate, textToHtml } = await import('./templates');
        const notif = await this.service.getNotificationConfig();
        const cfg = await this.service.getConfig(Number(body.channelId || 1));
        const vars = {
            orderCode: 'DEMO12345678', firstName: 'Sam',
            supportEmail: notif.adminEmail || 'support@example.com',
            reviewHours: (cfg as any).reviewHours ?? 24,
        };
        return res.json({
            subject: renderTemplate(body.subject || '', vars),
            html: textToHtml(renderTemplate(body.body || '', vars)),
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

    @Post('lists/sync')
    async sync(@Ctx() ctx: RequestContext, @Res() res: Response, @Body() body: { sourceKey?: string }) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        if (!FraudPreventionPlugin.isLicensed()) {
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

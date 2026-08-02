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
    async approve(@Ctx() ctx: RequestContext, @Res() res: Response, @Param('id') id: string, @Body() body: { notes?: string }) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const result = await this.service.resolveCase(Number(id), 'approved', body?.notes);
        if (result.ok && result.caseRow?.email) {
            const notif = await this.service.getNotificationConfig();
            if (notif.notifyOnApproval) {
                await this.service.sendCustomerNotice(
                    result.caseRow.email,
                    'Your order has been approved',
                    `<h2>✅ Order approved</h2>
                     <p>Your order <strong>${result.caseRow.orderCode || ''}</strong> passed verification
                     and is being fulfilled now. Your licence keys are on their way.</p>`,
                );
            }
        }
        return res.json(result);
    }

    @Post('cases/:id/reject')
    async reject(@Ctx() ctx: RequestContext, @Res() res: Response, @Param('id') id: string, @Body() body: { notes?: string }) {
        if (denyUnlessAdmin(ctx, res, true)) return;
        const result = await this.service.resolveCase(Number(id), 'rejected', body?.notes);
        if (result.ok && result.caseRow?.email) {
            await this.service.sendCustomerNotice(
                result.caseRow.email,
                'Order update',
                `<h2>Order update</h2>
                 <p>Unfortunately we were unable to process your recent order
                 <strong>${result.caseRow.orderCode || ''}</strong>. Any payment taken will be refunded.
                 If you believe this is an error, please reply to this email and we'll help.</p>`,
            );
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

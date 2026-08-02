import { createHmac } from 'crypto';
import { Logger } from '@vendure/core';

const loggerCtx = 'FraudPrevention';

/**
 * Ops-alert fan-out. Every configured channel gets the same event;
 * each transport is fire-and-forget with its own try/catch so one dead
 * webhook never silences the others.
 *
 * Config fields (fraud_notification_config):
 *   slackWebhookUrl    — hooks.slack.com incoming webhook
 *   discordWebhookUrl  — discord.com/api/webhooks/…
 *   teamsWebhookUrl    — *.webhook.office.com incoming webhook
 *   telegramBotToken + telegramChatId
 *   genericWebhookUrl + genericWebhookSecret — POST JSON, HMAC-SHA256
 *     signature of the raw body in X-Hulo-Signature (hex)
 */
export interface OpsChannels {
    slackWebhookUrl?: string | null;
    discordWebhookUrl?: string | null;
    teamsWebhookUrl?: string | null;
    telegramBotToken?: string | null;
    telegramChatId?: string | null;
    genericWebhookUrl?: string | null;
    genericWebhookSecret?: string | null;
}

export interface OpsEvent {
    event: 'case.held' | 'case.approved' | 'case.rejected' | 'case.auto_released';
    text: string;
    orderCode?: string;
    email?: string;
    score?: number;
    level?: string;
    signals?: Array<{ key: string; label: string; points: number }>;
}

async function post(url: string, body: unknown, headers: Record<string, string> = {}): Promise<void> {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6000);
    try {
        await fetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...headers },
            body: typeof body === 'string' ? body : JSON.stringify(body),
            signal: controller.signal,
        });
    } finally {
        clearTimeout(t);
    }
}

export async function fanOutOpsEvent(channels: OpsChannels, ev: OpsEvent): Promise<void> {
    const jobs: Array<Promise<void>> = [];

    if (channels.slackWebhookUrl && /^https:\/\/hooks\.slack\.com\//.test(channels.slackWebhookUrl)) {
        jobs.push(post(channels.slackWebhookUrl, { text: ev.text }));
    }
    if (channels.discordWebhookUrl && /^https:\/\/(discord\.com|discordapp\.com)\/api\/webhooks\//.test(channels.discordWebhookUrl)) {
        // Discord rejects Slack-style markdown-ish asterisks less gracefully; send as-is, content max 2000
        jobs.push(post(channels.discordWebhookUrl, { content: ev.text.slice(0, 1990) }));
    }
    if (channels.teamsWebhookUrl && /^https:\/\/[\w.-]+\.webhook\.office\.com\//.test(channels.teamsWebhookUrl)) {
        jobs.push(post(channels.teamsWebhookUrl, { text: ev.text }));
    }
    if (channels.telegramBotToken && channels.telegramChatId
        && /^[0-9]+:[\w-]+$/.test(channels.telegramBotToken)) {
        jobs.push(post(
            `https://api.telegram.org/bot${channels.telegramBotToken}/sendMessage`,
            { chat_id: channels.telegramChatId, text: ev.text },
        ));
    }
    if (channels.genericWebhookUrl && /^https:\/\//.test(channels.genericWebhookUrl)) {
        const payload = JSON.stringify({ ...ev, ts: new Date().toISOString() });
        const headers: Record<string, string> = {};
        if (channels.genericWebhookSecret) {
            headers['X-Hulo-Signature'] = createHmac('sha256', channels.genericWebhookSecret)
                .update(payload).digest('hex');
        }
        jobs.push(post(channels.genericWebhookUrl, payload, headers));
    }

    const results = await Promise.allSettled(jobs);
    for (const r of results) {
        if (r.status === 'rejected') {
            Logger.debug(`Ops notification transport failed: ${r.reason?.message || r.reason}`, loggerCtx);
        }
    }
}

/**
 * Customer-facing message templates for the three gating outcomes.
 *
 * Stored per channel (multi-storefront installs speak with different
 * voices), edited in the admin Settings tab, rendered with simple
 * {{variable}} substitution. Bodies are plain text — blank lines become
 * paragraphs — so an admin can't break their own email with half-closed
 * HTML, and the tone stays theirs.
 *
 * The defaults are written to be honest without being alarming: a held
 * order is "a quick security check", never "suspected fraud" — the
 * overwhelming majority of held orders are legitimate customers who
 * tripped a velocity rule.
 */

export type MessageKind = 'held' | 'approved' | 'rejected';

export interface MessageTemplate {
    subject: string;
    body: string;
}

export const TEMPLATE_VARS: Array<{ name: string; description: string }> = [
    { name: 'orderCode', description: 'The order code, e.g. Q6Y23UJU2BM3JHX8' },
    { name: 'firstName', description: "Customer's first name (falls back to 'there')" },
    { name: 'supportEmail', description: 'Your support address (from notification settings)' },
    { name: 'reviewHours', description: 'Expected review turnaround in hours (from channel settings)' },
];

export const DEFAULT_TEMPLATES: Record<MessageKind, MessageTemplate> = {
    held: {
        subject: 'A quick security check on your order {{orderCode}}',
        body: `Hi {{firstName}},

Thanks for your order {{orderCode}} — we've received it and your payment is safe.

As part of our standard security checks, this order has been picked for a quick manual review. This happens routinely and usually means nothing more than an unusually large order or a new address. No action is needed from you.

A member of our team will complete the review within {{reviewHours}} hours (usually much sooner), and your order will be on its way the moment it clears.

If you'd like to speed things up or have any questions, just reply to this email or contact {{supportEmail}} — a short note confirming your order details is often all we need.`,
    },
    approved: {
        subject: 'Your order {{orderCode}} is confirmed and on its way',
        body: `Hi {{firstName}},

Good news — the security check on your order {{orderCode}} is complete and everything is confirmed. Your order is being fulfilled right now.

Thanks for bearing with us. These checks keep prices down for everyone by keeping fraud out, and we appreciate your patience.

If anything doesn't arrive as expected, contact us at {{supportEmail}} and we'll sort it straight away.`,
    },
    rejected: {
        subject: 'About your order {{orderCode}}',
        body: `Hi {{firstName}},

Unfortunately we weren't able to complete your order {{orderCode}} after our security review, and it has been cancelled. Any payment taken will be refunded in full to the original payment method — refunds typically appear within 3–5 business days.

Security reviews can occasionally catch genuine orders. If you believe this is a mistake, we'd genuinely like to fix it: reply to this email or contact {{supportEmail}} with your order details and we'll take a second look with a human, not a machine.`,
    },
};

/** {{var}} substitution. Unknown variables render as empty string. */
export function renderTemplate(tpl: string, vars: Record<string, string | number | undefined>): string {
    return tpl.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, key) => {
        const v = vars[key];
        return v === undefined || v === null ? '' : String(v);
    });
}

/** Plain text -> simple paragraph HTML (blank-line separated). */
export function textToHtml(text: string): string {
    const esc = (s: string) => s
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return text
        .split(/\n\s*\n/)
        .map(p => `<p style="margin:0 0 14px;line-height:1.6">${esc(p.trim()).replace(/\n/g, '<br/>')}</p>`)
        .join('');
}

/**
 * Public threat feeds synced into `fraud_blocklist`. Keys and types are
 * unchanged from the pre-plugin implementation so previously synced rows
 * (source column) stay valid.
 */

export interface FraudSource {
    name: string;
    url: string;
    type: 'email_domain' | 'ip' | 'ip_range';
    description: string;
}

export const FRAUD_SOURCES: Record<string, FraudSource> = {
    disposableEmails: {
        name: 'Disposable Email Domains',
        url: 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
        type: 'email_domain',
        description: 'Community-maintained list of ~3,500 disposable email domains',
    },
    torExitNodes: {
        name: 'Tor Exit Nodes',
        url: 'https://check.torproject.org/torbulkexitlist',
        type: 'ip',
        description: 'Official Tor Project exit node IP list',
    },
    firehol1: {
        name: 'FireHOL Level 1 (High Confidence)',
        url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
        type: 'ip_range',
        description: 'High-confidence malicious IPs and ranges from multiple security sources',
    },
    spamhausDropList: {
        name: 'Spamhaus DROP List',
        url: 'https://www.spamhaus.org/drop/drop.txt',
        type: 'ip_range',
        description: "Spamhaus Don't Route Or Peer list — hijacked/leased ranges used for abuse",
    },
};

/** Built-in fallback of common disposable domains — used before the first
 *  feed sync has ever run, and merged with feed data afterwards. */
export const BUILTIN_DISPOSABLE_DOMAINS = new Set([
    'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
    'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
    'dispostable.com', 'maildrop.cc', 'temp-mail.org', 'fakeinbox.com',
    'trashmail.com', 'mailnesia.com', 'mytemp.email', 'tempail.com',
    'mohmal.com', 'getnada.com', 'emailondeck.com', 'burnermail.io',
    '10minutemail.com', 'mintemail.com', 'mailcatch.com', 'getairmail.com',
    'tempinbox.com', 'spamgourmet.com', 'mailsac.com', 'inboxkitten.com',
    '33mail.com', 'anonaddy.me', 'duck.com.disposable.invalid',
]);

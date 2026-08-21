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

/**
 * Curated, well-known public feeds offered as one-click presets in the
 * Custom feeds UI (the built-in FRAUD_SOURCES above sync automatically;
 * these are opt-in extras). Every URL verified live at publish time.
 */
export const CUSTOM_FEED_PRESETS: Array<{ key: string; name: string; url: string; listType: 'ip' | 'ip_range' | 'email_domain'; description: string }> = [
    { key: 'ipsum3', name: 'IPsum (level 3+)', url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', listType: 'ip', description: 'IPs seen on 3+ blacklists — good signal/noise balance (~13k)' },
    { key: 'blocklistDe', name: 'blocklist.de (all)', url: 'https://lists.blocklist.de/lists/all.txt', listType: 'ip', description: 'IPs reported attacking fail2ban users in the last 48h (~23k)' },
    { key: 'firehol2', name: 'FireHOL Level 2', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset', listType: 'ip_range', description: 'Attacks seen in the last 2 days (~16k ranges)' },
    { key: 'firehol3', name: 'FireHOL Level 3', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset', listType: 'ip_range', description: 'Attacks/malware seen in the last 30 days (~13k ranges)' },
    { key: 'etCompromised', name: 'Emerging Threats compromised', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', listType: 'ip', description: 'Known-compromised hosts (~500, high confidence)' },
    { key: 'cinsArmy', name: 'CINS Army', url: 'https://cinsscore.com/list/ci-badguys.txt', listType: 'ip', description: 'CINS Active Threat Intelligence bad actors (~15k)' },
    { key: 'sfsToxicDomains', name: 'StopForumSpam toxic domains', url: 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt', listType: 'email_domain', description: 'Email domains seen in spam signups (~75k — large)' },
];

// DataGhost Background Service Worker (Manifest V3)
// Multi-Database Legitimacy Engine, Data Detective & Vault Breach Monitor

const tabDataStore = new Map();
const domainReputationCache = new Map();
const alertedTabIds = new Set();

// Common two-part TLD suffixes
const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz',
    'co.jp', 'ne.jp', 'or.jp',
    'com.br', 'org.br', 'net.br',
    'co.in', 'net.in', 'org.in', 'gen.in',
    'com.sg', 'edu.sg', 'gov.sg',
    'com.mx', 'org.mx',
    'co.za', 'org.za',
    'com.tr', 'edu.tr',
    'com.hk', 'org.hk'
]);

// Helper: Extract primary root domain (eTLD+1)
function getPrimaryDomain(hostname) {
    if (!hostname) return '';
    hostname = hostname.toLowerCase();

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':')) {
        return hostname;
    }

    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;

    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
        return parts.slice(-3).join('.');
    }

    return parts.slice(-2).join('.');
}

// Built-in Recognition Dictionary for Major Domains (Finance, Trading, Tech, Media)
const KNOWN_CATEGORIES = {
    // Financial & Trading (Resolves xm.com, binance, etc.)
    'xm.com': { category: 'Financial Trading / Broker', verified: true },
    'binance.com': { category: 'Cryptocurrency Exchange', verified: true },
    'coinbase.com': { category: 'Cryptocurrency Platform', verified: true },
    'etoro.com': { category: 'Trading & Investing', verified: true },
    'robinhood.com': { category: 'Financial Services', verified: true },
    'interactivebrokers.com': { category: 'Online Brokerage', verified: true },
    'ig.com': { category: 'Financial Trading', verified: true },
    'plus500.com': { category: 'Financial Trading', verified: true },
    'oanda.com': { category: 'Currency Trading', verified: true },
    'paypal.com': { category: 'Payment Services', verified: true },
    'stripe.com': { category: 'Payment Processing', verified: true },

    // Tech & Cloud
    'google.com': { category: 'Search & Technology', verified: true },
    'github.com': { category: 'Software Development', verified: true },
    'apple.com': { category: 'Consumer Technology', verified: true },
    'microsoft.com': { category: 'Software & Cloud', verified: true },
    'cloudflare.com': { category: 'Cloud Infrastructure', verified: true },
    'amazon.com': { category: 'E-Commerce & Cloud', verified: true },
    'gitlab.com': { category: 'Software Development', verified: true },

    // Social & Communication
    'facebook.com': { category: 'Social Network', verified: true },
    'twitter.com': { category: 'Social Network', verified: true },
    'x.com': { category: 'Social Network', verified: true },
    'linkedin.com': { category: 'Professional Network', verified: true },
    'reddit.com': { category: 'Community Forum', verified: true },
    'discord.com': { category: 'Communications', verified: true }
};

// Search engine filter check
function isSearchEnginePage(urlStr) {
    if (!urlStr) return false;
    try {
        const u = new URL(urlStr);
        const host = u.hostname.toLowerCase();
        const path = u.pathname.toLowerCase();
        const search = u.search.toLowerCase();

        if ((host.includes('google.') || host.includes('google.co.')) && (path.startsWith('/search') || search.includes('q='))) return true;
        if (host.includes('duckduckgo.com') && (search.includes('q=') || path.length > 1)) return true;
        if (host.includes('bing.com') && (path.startsWith('/search') || search.includes('q='))) return true;
        if (host.includes('search.yahoo.com') || (host.includes('yahoo.com') && path.startsWith('/search'))) return true;
        if (host.includes('ecosia.org') && search.includes('q=')) return true;
        if (host.includes('search.brave.com')) return true;

        return false;
    } catch {
        return false;
    }
}

// =========================================================================
// MULTI-DATABASE LEGITIMACY ENGINE
// Checks Cloudflare Security DoH, Google DNS DoH, ICANN RDAP, and Local Heuristics
// =========================================================================
async function verifyWebsiteLegitimacy(hostname) {
    const primary = getPrimaryDomain(hostname);
    if (!primary) {
        return { isLegit: false, isThreat: true, reason: 'Invalid Host' };
    }

    // Check memory cache
    if (domainReputationCache.has(primary)) {
        return domainReputationCache.get(primary);
    }

    const result = {
        domain: primary,
        isLegit: true,
        isThreat: false,
        threatType: null,
        threatReason: '',
        category: 'General Web',
        registrationYear: null,
        checks: { dns: 'unknown', rdap: 'unknown' },
        verifiedSources: []
    };

    // 1. Check Known Category Dictionary (Immediate Match for xm.com, etc.)
    if (KNOWN_CATEGORIES[primary]) {
        result.category = KNOWN_CATEGORIES[primary].category;
        result.isLegit = true;
        result.verifiedSources.push('Verified Industry Registry');
    }

    // 2. Query Cloudflare 1.1.1.1 for Families (Security DoH Threat Filter)
    try {
        const cfRes = await fetch(`https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(primary)}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
        });
        if (cfRes.ok) {
            const cfData = await cfRes.json();
            // Cloudflare returns 0.0.0.0 or NXDOMAIN when blocking malware/phishing
            if (cfData.Answer) {
                const isBlocked = cfData.Answer.some(a => a.data === '0.0.0.0' || a.data === '127.0.0.1');
                if (isBlocked) {
                    result.checks.dns = 'blocked';
                    result.isThreat = true;
                    result.threatType = 'malware_phishing';
                    result.threatReason = 'Domain is actively blocked by Cloudflare Security Threat Database';
                } else {
                    result.checks.dns = 'clean';
                    result.verifiedSources.push('Cloudflare Security DNS');
                }
            }
        }
    } catch {}

    // 3. Query Open ICANN RDAP Database (Registration History & Age)
    try {
        const rdapRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(primary)}`, {
            headers: { 'Accept': 'application/json, application/rdap+json' }
        });
        if (rdapRes.ok) {
            const rdapData = await rdapRes.json();
            result.checks.rdap = 'checked';
            if (rdapData.events) {
                const regEvent = rdapData.events.find(e => e.eventAction === 'registration');
                if (regEvent && regEvent.eventDate) {
                    result.checks.rdap = 'registered';
                    const regDate = new Date(regEvent.eventDate);
                    result.registrationYear = regDate.getFullYear();
                    const ageYears = new Date().getFullYear() - result.registrationYear;

                    if (ageYears >= 2) {
                        result.isLegit = true;
                        result.verifiedSources.push(`ICANN RDAP (Registered ${result.registrationYear})`);
                    } else if (ageYears === 0) {
                        // Brand new domain (< 1 year old)
                        const ageDays = (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
                        if (ageDays < 30) {
                            result.isThreat = true;
                            result.threatType = 'new_domain_risk';
                            result.threatReason = `Domain was created only ${Math.round(ageDays)} days ago (common in throwaway phishing attacks).`;
                        }
                    }
                }
            }
        }
    } catch {}

    // 4. Local Heuristic Checks: Raw IP addresses and Brand Spoofing
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        result.isThreat = true;
        result.threatType = 'raw_ip';
        result.threatReason = 'Host is a raw IP address rather than a registered domain name.';
    }

    // Cache the result
    domainReputationCache.set(primary, result);
    return result;
}

// Initialize clean tab state
function initTabState(tabId, url = '') {
    let hostname = '';
    let protocol = 'https:';
    let primaryDomain = '';

    if (url) {
        try {
            const parsed = new URL(url);
            hostname = parsed.hostname;
            protocol = parsed.protocol;
            primaryDomain = getPrimaryDomain(hostname);
        } catch {}
    }

    const state = {
        tabId,
        pageUrl: url,
        pageHost: hostname,
        pageProtocol: protocol,
        primaryDomain,
        isSearchEngine: isSearchEnginePage(url),
        legitimacy: {
            isLegit: true,
            isThreat: false,
            threatType: null,
            threatReason: '',
            category: 'Analyzing...',
            registrationYear: null,
            verifiedSources: []
        },
        loginData: {
            hasLogin: false,
            authType: null,
            hasPassword: false,
            hasSSO: false,
            primaryFormTarget: null,
            isFormTargetCrossOrigin: false,
            signals: []
        },
        nodes: {},
        connections: [],
        posts: [],
        lastUpdated: Date.now()
    };

    if (hostname) {
        state.nodes[hostname] = {
            id: hostname,
            host: hostname,
            category: 'Primary',
            count: 1,
            isSecure: protocol === 'https:',
            isPrimary: true
        };

        // Run multi-database legitimacy verification
        verifyWebsiteLegitimacy(hostname).then((legitData) => {
            state.legitimacy = legitData;
            handleLegitimacyAlert(tabId, hostname, protocol, legitData);
            syncStorage(tabId);
        });
    }

    tabDataStore.set(tabId, state);
    syncStorage(tabId);
    return state;
}

// User Rule: "if its a good website dont say anything if its bad website (spam, phishing) give a popup to the user to inform them"
function handleLegitimacyAlert(tabId, hostname, protocol, legitData) {
    if (tabId < 0) return;

    const isHttp = protocol === 'http:';
    const isBad = legitData.isThreat || isHttp;

    if (isBad) {
        // Red badge on icon
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#D93025', tabId });

        // Alert user via Chrome Notification Popup once per tab
        const alertKey = `${tabId}_${hostname}`;
        if (!alertedTabIds.has(alertKey) && hostname) {
            alertedTabIds.add(alertKey);

            let alertTitle = '⚠️ Security Warning: Untrusted Website';
            let alertMsg = `${hostname} may be unsafe.`;

            if (isHttp) {
                alertTitle = '⚠️ Insecure Website (Unencrypted HTTP)';
                alertMsg = `${hostname} does not use encryption. Passwords and personal data can be intercepted by third parties.`;
            } else if (legitData.threatReason) {
                alertTitle = '🚨 Threat Detected: Suspicious Site';
                alertMsg = legitData.threatReason;
            }

            try {
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="%23D93025"><path d="M12 2L1 21h22L12 2zm1 14h-2v-2h2v2zm0-4h-2V8h2v4z"/></svg>',
                    title: alertTitle,
                    message: alertMsg
                });
            } catch {}
        }
    } else {
        // "if its a good website dont say anything" -> Keep toolbar badge completely clean, no notification popup!
        chrome.action.setBadgeText({ text: '', tabId });
    }
}

function syncStorage(tabId) {
    const state = tabDataStore.get(tabId);
    if (!state) return;
    chrome.storage.local.set({ [`tab_${tabId}`]: state }).catch(() => {});
}

// -------------------------------------------------------------
// WebRequest: Intercepts Outbound Traffic
// -------------------------------------------------------------
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.tabId < 0) return;

        let urlObj;
        try {
            urlObj = new URL(details.url);
        } catch {
            return;
        }

        if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') return;

        let state = tabDataStore.get(details.tabId);
        if (!state) state = initTabState(details.tabId, details.initiator || '');

        if (state.isSearchEngine) return;

        const host = urlObj.hostname;
        const isSecure = urlObj.protocol === 'https:';
        const method = (details.method || 'GET').toUpperCase();
        const fromHost = state.pageHost || state.primaryDomain || 'Client';

        // Categorize destination
        let category = 'Unknown';
        if (state.primaryDomain && getPrimaryDomain(host) === state.primaryDomain) {
            category = 'Primary';
        } else if (KNOWN_CATEGORIES[getPrimaryDomain(host)]) {
            category = 'Service';
        } else if (host.includes('auth') || host.includes('login') || host.includes('identity')) {
            category = 'Auth';
        } else if (host.includes('analytics') || host.includes('telemetry') || host.includes('metric')) {
            category = 'Analytics';
        } else if (host.includes('ad') || host.includes('track') || host.includes('pixel')) {
            category = 'Tracking';
        } else if (host.includes('cdn') || host.includes('static') || host.includes('font') || host.includes('cloud')) {
            category = 'Essential';
        }

        // Add node
        if (!state.nodes[host]) {
            state.nodes[host] = {
                id: host,
                host: host,
                category: category,
                count: 1,
                isSecure: isSecure,
                isPrimary: category === 'Primary'
            };
        } else {
            state.nodes[host].count++;
        }

        // Add connection
        const connKey = `${fromHost}->${host}`;
        let conn = state.connections.find(c => c.key === connKey);
        if (conn) {
            conn.count++;
        } else {
            state.connections.push({
                key: connKey,
                from: fromHost,
                to: host,
                category: category,
                count: 1,
                isSecure: isSecure
            });
        }

        // Record POSTs
        if (method === 'POST' || method === 'PUT') {
            state.posts.unshift({
                id: `post_${Date.now()}`,
                timestamp: Date.now(),
                url: details.url,
                host: host,
                path: urlObj.pathname,
                isSecure: isSecure,
                category: category
            });
            if (state.posts.length > 25) state.posts.pop();

            // Alert immediately if credential POST occurs over plaintext HTTP
            if (!isSecure && state.loginData.hasLogin) {
                handleLegitimacyAlert(details.tabId, host, 'http:', {
                    isThreat: true,
                    threatType: 'plaintext_login_post',
                    threatReason: `Form data was submitted over unencrypted HTTP to ${host}!`
                });
            }
        }

        syncStorage(details.tabId);

        // Realtime pulse message for graph view
        chrome.runtime.sendMessage({
            type: 'REALTIME_GRAPH_PULSE',
            tabId: details.tabId,
            request: {
                from: fromHost,
                to: host,
                category: category,
                isSecure: isSecure
            }
        }).catch(() => {});
    },
    { urls: ['<all_urls>'] }
);

// -------------------------------------------------------------
// Navigation & Lifecycle
// -------------------------------------------------------------
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0 && details.tabId >= 0) {
        initTabState(details.tabId, details.url);
    }
});

chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0 && details.tabId >= 0) {
        let state = tabDataStore.get(details.tabId);
        if (!state) {
            initTabState(details.tabId, details.url);
        } else if (!state.pageUrl || state.pageUrl !== details.url) {
            state.pageUrl = details.url;
            state.isSearchEngine = isSearchEnginePage(details.url);
            try {
                const u = new URL(details.url);
                state.pageHost = u.hostname;
                state.pageProtocol = u.protocol;
                state.primaryDomain = getPrimaryDomain(u.hostname);
                verifyWebsiteLegitimacy(u.hostname).then((legitData) => {
                    state.legitimacy = legitData;
                    handleLegitimacyAlert(details.tabId, u.hostname, u.protocol, legitData);
                    syncStorage(details.tabId);
                });
            } catch {}
            syncStorage(details.tabId);
        }
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    tabDataStore.delete(tabId);
    chrome.storage.local.remove(`tab_${tabId}`).catch(() => {});
});

// =========================================================================
// VAULT — Daily Site Breach Monitoring
// Stores domains only; password field values are never read or sent.
// =========================================================================

const VAULT_STORAGE_KEY = 'dg_vault_sites';
const VAULT_ALARM_NAME  = 'dg_vault_daily_check';
// Tracks which domains we've already notified this session (avoid spam)
const vaultNotifiedDomains = new Set();

function updateVaultDailyAlarm(sites) {
    if (sites.length === 0) {
        chrome.alarms.clear(VAULT_ALARM_NAME);
        return;
    }

    chrome.alarms.get(VAULT_ALARM_NAME, existing => {
        if (!existing) {
            chrome.alarms.create(VAULT_ALARM_NAME, {
                delayInMinutes: 24 * 60,
                periodInMinutes: 24 * 60
            });
        }
    });
}

chrome.storage.local.get(VAULT_STORAGE_KEY, data => {
    updateVaultDailyAlarm(data[VAULT_STORAGE_KEY] || []);
});

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes[VAULT_STORAGE_KEY]) {
        updateVaultDailyAlarm(changes[VAULT_STORAGE_KEY].newValue || []);
    }
});

chrome.runtime.onInstalled.addListener(details => {
    if (details.reason !== 'install' && details.reason !== 'update') return;
    chrome.alarms.clear(VAULT_ALARM_NAME, () => {
        chrome.storage.local.get(VAULT_STORAGE_KEY, data => {
            updateVaultDailyAlarm(data[VAULT_STORAGE_KEY] || []);
        });
    });
});

let vaultSiteWriteQueue = Promise.resolve();

function normalizeVaultDomain(raw) {
    if (typeof raw !== 'string' || !raw.trim()) return null;

    try {
        const value = raw.trim();
        const parsed = new URL(value.includes('://') ? value : `https://${value}`);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
        if (parsed.username || parsed.password || parsed.port) return null;

        const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
        const labels = hostname.split('.');
        if (labels.length < 2 || hostname.length > 253 ||
            /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':')) return null;
        if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
        if (labels.length === 2 && MULTI_PART_SUFFIXES.has(hostname)) return null;
        if (!/[a-z]/.test(labels[labels.length - 1])) return null;

        const domain = getPrimaryDomain(hostname);
        return domain && domain.includes('.') ? { hostname, domain } : null;
    } catch {
        return null;
    }
}

async function verifyVaultDomain(raw) {
    const normalized = normalizeVaultDomain(raw);
    if (!normalized) return { valid: false, error: 'Enter a valid website domain, such as netflix.com.' };

    try {
        const results = await Promise.all(['A', 'AAAA'].map(async type => {
            const response = await fetch(
                `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(normalized.domain)}&type=${type}`,
                { headers: { 'Accept': 'application/dns-json' } }
            );
            if (!response.ok) throw new Error('DNS lookup failed');
            return response.json();
        }));

        const resolves = results.some(result => result.Status === 0 &&
            (result.Answer || []).some(answer => answer.type === 1 || answer.type === 28));
        return resolves
            ? { valid: true, domain: normalized.domain }
            : { valid: false, error: 'That domain did not resolve. Check the spelling and try again.' };
    } catch {
        return { valid: false, error: 'Could not verify the domain right now. Try again shortly.' };
    }
}

function addPasswordDetectedSite(hostname) {
    const normalized = normalizeVaultDomain(hostname);
    if (!normalized) return Promise.resolve(null);
    const { domain } = normalized;

    vaultSiteWriteQueue = vaultSiteWriteQueue.catch(() => {}).then(async () => {
        const data = await chrome.storage.local.get(VAULT_STORAGE_KEY);
        const sites = data[VAULT_STORAGE_KEY] || [];
        const existing = sites.find(site => site.domain === domain);
        if (existing) {
            if (existing.autoDetected) return { domain, alreadyTracked: true };
            existing.autoDetected = true;
            existing.lastDetectedAt = Date.now();
            if (!existing.nextCheckAt) existing.nextCheckAt = Date.now() + 24 * 60 * 60 * 1000;
        } else {
            sites.push({
                domain,
                status: 'scheduled',
                lastChecked: null,
                nextCheckAt: Date.now() + 24 * 60 * 60 * 1000,
                breaches: [],
                autoDetected: true,
                lastDetectedAt: Date.now(),
                notifiedBreach: false
            });
        }
        await chrome.storage.local.set({ [VAULT_STORAGE_KEY]: sites });
        return { domain, alreadyTracked: false };
    });
    return vaultSiteWriteQueue;
}

async function verifyAndAddManualVaultDomain(raw) {
    const verification = await verifyVaultDomain(raw);
    if (!verification.valid) return verification;

    const domain = verification.domain;
    let alreadyTracked = false;
    vaultSiteWriteQueue = vaultSiteWriteQueue.catch(() => {}).then(async () => {
        const data = await chrome.storage.local.get(VAULT_STORAGE_KEY);
        const sites = data[VAULT_STORAGE_KEY] || [];
        const existing = sites.find(site => site.domain === domain);
        if (existing) {
            alreadyTracked = true;
            return;
        }
        sites.push({
            domain,
            status: null,
            lastChecked: null,
            nextCheckAt: Date.now() + 24 * 60 * 60 * 1000,
            breaches: [],
            autoDetected: false,
            notifiedBreach: false
        });
        await chrome.storage.local.set({ [VAULT_STORAGE_KEY]: sites });
    });
    await vaultSiteWriteQueue;
    return { valid: true, domain, alreadyTracked };
}

// The public catalogue reports site incidents, not individual account exposure.
async function fetchBreachCatalog() {
    try {
        const res = await fetch('https://haveibeenpwned.com/api/v3/breaches', {
            headers: { 'Accept': 'application/json' }
        });
        if (!res.ok) {
            return { catalog: null, errorCode: res.status === 429 ? 'rate_limited' : 'service_error' };
        }
        return { catalog: await res.json(), errorCode: null };
    } catch {
        return { catalog: null, errorCode: 'network_error' };
    }
}

function findSiteBreaches(domain, catalog) {
    const normalizedDomain = getPrimaryDomain(domain).toLowerCase();
    return catalog.filter(breach => {
        const breachDomain = (breach.Domain || '').toLowerCase();
        return breachDomain &&
            (normalizedDomain === breachDomain || normalizedDomain.endsWith(`.${breachDomain}`)) &&
            breach.IsVerified === true &&
            !breach.IsFabricated &&
            !breach.IsSpamList &&
            !breach.IsMalware &&
            !breach.IsRetired;
    }).map(breach => ({
        name: breach.Name,
        title: breach.Title || breach.Name,
        domain: breach.Domain,
        breachDate: breach.BreachDate
    }));
}

// Run the full vault check for all stored sites
async function runVaultBreachCheck() {
    const data = await chrome.storage.local.get(VAULT_STORAGE_KEY);
    const sites = data[VAULT_STORAGE_KEY] || [];
    if (sites.length === 0) return;

    const { catalog, errorCode } = await fetchBreachCatalog();
    const updated = [...sites];
    for (const site of updated) {
        site.lastChecked = Date.now();
        if (!catalog) {
            site.notifiedBreach = site.notifiedBreach || site.status === 'breached';
            site.status = 'unknown';
            site.checkError = errorCode || 'service_error';
            continue;
        }

        const breaches = findSiteBreaches(site.domain, catalog);
        site.nextCheckAt = Date.now() + 24 * 60 * 60 * 1000;
        if (breaches.length > 0) {
            const alreadyNotified = site.notifiedBreach || site.status === 'breached';
            site.status = 'breached';
            site.breaches = breaches;

            if (!alreadyNotified && !vaultNotifiedDomains.has(site.domain)) {
                vaultNotifiedDomains.add(site.domain);
                fireVaultBreachNotification(site.domain, breaches);
            }
            site.notifiedBreach = true;
            site.checkError = null;
        } else {
            site.status = 'safe';
            site.breaches = [];
            site.notifiedBreach = false;
            site.checkError = null;
        }
    }

    await chrome.storage.local.set({ [VAULT_STORAGE_KEY]: updated });
}

// Show a Chrome notification for a breached vault site
function fireVaultBreachNotification(domain, breachNames) {
    const breachList = breachNames.slice(0, 3).map(breach => breach.title || breach.name || breach).join(', ');
    const extra = breachNames.length > 3 ? ` +${breachNames.length - 3} more` : '';
    try {
        chrome.notifications.create(`vault_breach_${domain}_${Date.now()}`, {
            type: 'basic',
            iconUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="%23f28b82"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm1 14h-2v-2h2v2zm0-4h-2V7h2v4z"/></svg>',
            title: `Known site breach: ${domain}`,
            message: `HIBP lists: ${breachList}${extra}. If you have an account there, review it and change any reused passwords.`
        });
    } catch {}
}

// Daily alarm handler
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === VAULT_ALARM_NAME) {
        runVaultBreachCheck();
    }
});

// -------------------------------------------------------------
// Messages
// -------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const tabId = sender.tab ? sender.tab.id : message.tabId;

    if (message.type === 'VERIFY_AND_ADD_VAULT_DOMAIN') {
        verifyAndAddManualVaultDomain(message.domain)
            .then(sendResponse)
            .catch(() => sendResponse({ valid: false, error: 'Could not verify the domain right now. Try again shortly.' }));
        return true;
    }

    if (message.type === 'PASSWORD_FIELD_USED') {
        if (!sender.tab?.url) {
            sendResponse({ ok: false });
            return false;
        }
        let hostname = '';
        try { hostname = new URL(sender.tab.url).hostname; } catch {}
        addPasswordDetectedSite(hostname)
            .then(result => sendResponse({ ok: Boolean(result), domain: result?.domain, alreadyTracked: result?.alreadyTracked }))
            .catch(() => sendResponse({ ok: false }));
        return true;
    }

    if (message.type === 'PAGE_FORMS_ANALYSIS' && tabId >= 0) {
        let state = tabDataStore.get(tabId);
        if (!state) state = initTabState(tabId, message.payload.pageUrl);

        state.isSearchEngine = Boolean(message.payload.isSearchEngine);
        state.loginData = message.payload.loginData || state.loginData;

        // If a login form has an unencrypted or external target, re-evaluate safety
        if (state.loginData.hasLogin && state.pageProtocol === 'http:') {
            handleLegitimacyAlert(tabId, state.pageHost, 'http:', {
                isThreat: true,
                threatType: 'http_login',
                threatReason: 'Login form found on unencrypted HTTP page. Passwords are exposed.'
            });
        }

        syncStorage(tabId);
        sendResponse({ success: true });
        return true;
    }

    if (message.type === 'GET_TAB_DATA') {
        const targetTabId = message.tabId;
        const state = tabDataStore.get(targetTabId);
        if (state) {
            sendResponse({ state });
        } else {
            chrome.storage.local.get(`tab_${targetTabId}`, (res) => {
                sendResponse({ state: res[`tab_${targetTabId}`] || null });
            });
            return true;
        }
    }

    // Vault breach alert forwarded from vault.js
    if (message.type === 'VAULT_BREACH_ALERT') {
        const { domain, breaches } = message;
        if (domain && !vaultNotifiedDomains.has(domain)) {
            vaultNotifiedDomains.add(domain);
            fireVaultBreachNotification(domain, breaches || []);
        }
        sendResponse({ ok: true });
        return true;
    }
});

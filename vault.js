// DataGhost Vault — Password Site Monitor
// Tracks site domains only and compares them with HIBP's public breach catalogue.

const STORAGE_KEY = 'dg_vault_sites';

// ── Utilities ──────────────────────────────────────────────────────────────

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function cleanDomain(raw) {
    raw = raw.trim().toLowerCase().replace(/^https?:\/\//i, '').split('/')[0];
    return raw;
}

function timeAgo(ts) {
    if (!ts) return 'Never checked';
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1)  return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24)  return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

function timeUntil(ts) {
    if (!ts) return 'in about 24 hours';
    const hours = Math.max(1, Math.ceil((ts - Date.now()) / 3600000));
    return hours < 24 ? `in ${hours}h` : 'in about 24 hours';
}

function truncate(str, n) {
    return str && str.length > n ? str.slice(0, n) + '…' : (str || '');
}

// ── Load & Save ────────────────────────────────────────────────────────────

async function loadSites() {
    return new Promise(resolve => {
        chrome.storage.local.get(STORAGE_KEY, data => {
            resolve(data[STORAGE_KEY] || []);
        });
    });
}

async function saveSites(sites) {
    return new Promise(resolve => {
        chrome.storage.local.set({ [STORAGE_KEY]: sites }, resolve);
    });
}

// ── HIBP API — Public Site Breach Catalogue ────────────────────────────────

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
    if (!Array.isArray(catalog)) return [];
    const normalizedDomain = cleanDomain(domain).replace(/^www\./, '');
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

function breachTitle(breach) {
    return typeof breach === 'string' ? breach : (breach.title || breach.name || 'Known breach');
}

// ── Check All Sites ────────────────────────────────────────────────────────

async function checkAllSites(sites, onProgress) {
    const updated = [...sites];
    updated.forEach((site, index) => onProgress && onProgress(index, site.domain, 'checking'));
    const { catalog, errorCode } = await fetchBreachCatalog();
    for (let i = 0; i < updated.length; i++) {
        const site = updated[i];
        site.lastChecked = Date.now();
        site.nextCheckAt = Date.now() + 24 * 60 * 60 * 1000;
        if (!catalog) {
            site.notifiedBreach = site.notifiedBreach || site.status === 'breached';
            site.status = 'unknown';
            site.checkError = errorCode || 'service_error';
        } else {
            const breaches = findSiteBreaches(site.domain, catalog);
            if (breaches.length > 0) {
                site.status = 'breached';
                site.breaches = breaches;
                site.checkError = null;
            } else {
                site.status = 'safe';
                site.breaches = [];
                site.notifiedBreach = false;
                site.checkError = null;
            }
        }

        onProgress && onProgress(i, site.domain, site.status);
    }
    return updated;
}

// ── DOM Render ─────────────────────────────────────────────────────────────

const siteListEl    = document.getElementById('siteList');
const emptyStateEl  = document.getElementById('emptyState');
const siteCountEl   = document.getElementById('siteCountLabel');
const breachBanner  = document.getElementById('breachBanner');
const bannerTitle   = document.getElementById('breachBannerTitle');
const bannerSub     = document.getElementById('breachBannerSub');
const siteInputEl   = document.getElementById('siteInput');
const addHintEl     = document.getElementById('addSiteHint');
const btnAddSite    = document.getElementById('btnAddSite');
const btnCheckNow   = document.getElementById('btnCheckNow');

let vaultSites = [];
let isChecking  = false;

function renderSiteRow(site) {
    const row = document.createElement('div');
    row.className = `site-row ${site.status || 'checking'}`;
    row.dataset.domain = site.domain;

    let statusText = 'Checking…';
    if (site.status === 'scheduled') statusText = `First breach check ${timeUntil(site.nextCheckAt)}`;
    if (site.status === 'scheduled') statusText = `First breach check ${timeUntil(site.nextCheckAt)}`;
    if (site.status === 'safe')     statusText = 'No verified site breach listed';
    if (site.status === 'breached') statusText = `${site.breaches?.length || 1} verified site breach${site.breaches?.length !== 1 ? 'es' : ''} listed`;
    if (site.status === 'unknown') {
        if (site.checkError === 'authorization_required') statusText = 'HIBP authorization required';
        else if (site.checkError === 'rate_limited') statusText = 'Rate limited — check later';
        else statusText = 'Could not verify — check later';
    }

    let breachChipsHtml = '';
    if (site.status === 'breached' && site.breaches && site.breaches.length) {
        const shown = site.breaches.slice(0, 4);
        const extra = site.breaches.length - shown.length;
        breachChipsHtml = `<div class="breach-chips">
            ${shown.map(b => `<span class="breach-chip" title="${escapeHtml(breachTitle(b))}">${escapeHtml(truncate(breachTitle(b), 18))}</span>`).join('')}
            ${extra > 0 ? `<span class="breach-chip">+${extra} more</span>` : ''}
        </div>`;
    }

    row.innerHTML = `
        <div class="site-status-dot"></div>
        <div class="site-info">
            <div class="site-domain-line">
                <div class="site-domain">${escapeHtml(site.domain)}</div>
                <span class="site-source-chip ${site.autoDetected ? 'auto' : ''}">${site.autoDetected ? 'AUTO' : 'MANUAL'}</span>
            </div>
            <div class="site-status-text">${escapeHtml(statusText)}</div>
            ${breachChipsHtml}
        </div>
        <div class="site-last-checked">${timeAgo(site.lastChecked)}</div>
        <button class="site-remove-btn" title="Remove">×</button>
    `;

    syncReviewButton(row, site.domain, site.status);
    row.querySelector('.site-remove-btn').addEventListener('click', async (e) => {
        e.stopPropagation();
        vaultSites = vaultSites.filter(s => s.domain !== site.domain);
        await saveSites(vaultSites);
        renderAll();
    });

    return row;
}

function createReviewButton(domain) {
    const button = document.createElement('button');
    button.className = 'site-review-btn';
    button.type = 'button';
    button.textContent = 'Review';
    button.title = 'Open this site to review your account security';
    button.addEventListener('click', () => {
        chrome.tabs.create({ url: `https://${domain}` });
    });
    return button;
}

function syncReviewButton(row, domain, status) {
    const existing = row.querySelector('.site-review-btn');
    if (status === 'breached' && !existing) {
        row.insertBefore(createReviewButton(domain), row.querySelector('.site-last-checked'));
    } else if (status !== 'breached' && existing) {
        existing.remove();
    }
}

function updateBannerFromSites(sites) {
    const breachedSites = sites.filter(s => s.status === 'breached');
    if (breachedSites.length > 0) {
        breachBanner.style.display = 'flex';
        bannerTitle.textContent = `${breachedSites.length} Known Site Breach${breachedSites.length > 1 ? 'es' : ''}`;
        bannerSub.textContent = `HIBP lists records for ${breachedSites.map(s => s.domain).join(', ')}. If you have an account there, review it and change any reused passwords.`;
    } else {
        breachBanner.style.display = 'none';
    }
}

function renderAll() {
    // Clear existing site rows (not empty state)
    Array.from(siteListEl.querySelectorAll('.site-row')).forEach(el => el.remove());

    if (vaultSites.length === 0) {
        emptyStateEl.style.display = 'flex';
        siteCountEl.textContent = '0 sites';
        breachBanner.style.display = 'none';
        return;
    }

    emptyStateEl.style.display = 'none';
    siteCountEl.textContent = `${vaultSites.length} site${vaultSites.length !== 1 ? 's' : ''}`;

    vaultSites.forEach(site => {
        siteListEl.appendChild(renderSiteRow(site));
    });

    updateBannerFromSites(vaultSites);
}

function updateSiteRow(domain, status, breaches, checkError) {
    const row = Array.from(siteListEl.querySelectorAll('.site-row')).find(el => el.dataset.domain === domain);
    if (!row) return;

    row.className = `site-row ${status}`;
    syncReviewButton(row, domain, status);

    const dot = row.querySelector('.site-status-dot');
    if (dot) dot.className = 'site-status-dot';

    const statusTextEl = row.querySelector('.site-status-text');
    if (statusTextEl) {
        if (status === 'safe') statusTextEl.textContent = 'No verified site breach listed';
        else if (status === 'breached') statusTextEl.textContent = `${breaches?.length || 1} verified site breach${breaches?.length !== 1 ? 'es' : ''} listed`;
        else if (status === 'checking') statusTextEl.textContent = 'Checking…';
        else if (checkError === 'authorization_required') statusTextEl.textContent = 'HIBP authorization required';
        else if (checkError === 'rate_limited') statusTextEl.textContent = 'Rate limited — check later';
        else statusTextEl.textContent = 'Could not verify — check later';
    }

    const timeEl = row.querySelector('.site-last-checked');
    if (timeEl) timeEl.textContent = 'Just now';

    // Update breach chips
    let chipsEl = row.querySelector('.breach-chips');
    if (status === 'breached' && breaches && breaches.length) {
        if (!chipsEl) {
            chipsEl = document.createElement('div');
            chipsEl.className = 'breach-chips';
            row.querySelector('.site-info').appendChild(chipsEl);
        }
        const shown = breaches.slice(0, 4);
        const extra = breaches.length - shown.length;
        chipsEl.innerHTML = shown.map(b => `<span class="breach-chip" title="${escapeHtml(breachTitle(b))}">${escapeHtml(truncate(breachTitle(b), 18))}</span>`).join('') +
            (extra > 0 ? `<span class="breach-chip">+${extra} more</span>` : '');
    } else if (chipsEl) {
        chipsEl.remove();
    }
}

// ── Add Site ───────────────────────────────────────────────────────────────

function verifyAndAddDomain(rawDomain) {
    return new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'VERIFY_AND_ADD_VAULT_DOMAIN', domain: rawDomain }, response => {
            const runtimeError = chrome.runtime.lastError;
            resolve(response || {
                valid: false,
                error: runtimeError?.message || 'Could not verify the domain right now. Try again shortly.'
            });
        });
    });
}

async function addSite() {
    const raw = siteInputEl.value.trim();
    if (!raw) return;

    btnAddSite.disabled = true;
    siteInputEl.disabled = true;
    addHintEl.textContent = 'Checking domain syntax and DNS…';
    addHintEl.className = 'add-site-hint';

    try {
        const result = await verifyAndAddDomain(raw);
        if (!result.valid) {
            addHintEl.textContent = result.error || 'Domain verification failed.';
            addHintEl.className = 'add-site-hint err';
            return;
        }
        if (result.alreadyTracked) {
            addHintEl.textContent = `${result.domain} is already in the Vault.`;
            addHintEl.className = 'add-site-hint err';
            return;
        }

        siteInputEl.value = '';
        addHintEl.textContent = `Verified ${result.domain}. Checking breach records…`;
        addHintEl.className = 'add-site-hint ok';
        vaultSites = await loadSites();
        renderAll();
        await runManualCheck();
    } finally {
        if (!isChecking) {
            btnAddSite.disabled = false;
            siteInputEl.disabled = false;
        }
    }
}

// ── Check Now Button ───────────────────────────────────────────────────────

async function runManualCheck() {
    if (isChecking || vaultSites.length === 0) return;
    isChecking = true;
    const previousStatuses = new Map(vaultSites.map(site => [site.domain, site.status]));
    btnCheckNow.style.opacity = '0.5';
    btnCheckNow.disabled = true;
    btnAddSite.disabled = true;
    siteInputEl.disabled = true;

    // Mark all as checking
    vaultSites.forEach(s => { s.status = 'checking'; });
    renderAll();

    const updated = await checkAllSites(vaultSites, (i, domain, status) => {
        const site = vaultSites.find(s => s.domain === domain);
        const breaches = site ? site.breaches : [];
        updateSiteRow(domain, status, status === 'breached' ? breaches : [], site?.checkError);
        updateBannerFromSites(vaultSites);
    });

    vaultSites = updated;
    vaultSites.filter(s => s.status === 'breached' && !s.notifiedBreach && previousStatuses.get(s.domain) !== 'breached').forEach(s => {
        s.notifiedBreach = true;
        chrome.runtime.sendMessage({
            type: 'VAULT_BREACH_ALERT',
            domain: s.domain,
            breaches: s.breaches
        }).catch(() => {});
    });
    await saveSites(vaultSites);
    renderAll();

    isChecking = false;
    btnCheckNow.style.opacity = '1';
    btnCheckNow.disabled = false;
    btnAddSite.disabled = false;
    siteInputEl.disabled = false;
}

// ── Init ───────────────────────────────────────────────────────────────────

async function init() {
    vaultSites = await loadSites();
    renderAll();
}

btnAddSite.addEventListener('click', addSite);
siteInputEl.addEventListener('keydown', e => { if (e.key === 'Enter') addSite(); });
btnCheckNow.addEventListener('click', runManualCheck);

document.addEventListener('DOMContentLoaded', init);

chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !changes[STORAGE_KEY]) return;
    vaultSites = changes[STORAGE_KEY].newValue || [];
    renderAll();
});

// DataGhost Google Material Controller
// Manages: Multi-Database Legitimacy Informant, Login Scanner, & Data Detective

let currentTabId = null;
let currentTabState = null;

// DOM Elements
const hostNameEl = document.getElementById('hostName');
const lockIconEl = document.getElementById('lockIcon');

const informantCardEl = document.getElementById('informantCard');
const statusAvatarEl = document.getElementById('statusAvatar');
const statusTitleEl = document.getElementById('statusTitle');
const statusCategoryEl = document.getElementById('statusCategory');
const chipCategoryEl = document.getElementById('chipCategory');
const chipDnsEl = document.getElementById('chipDns');
const chipRdapEl = document.getElementById('chipRdap');
const threatAlertBoxEl = document.getElementById('threatAlertBox');
const threatAlertTextEl = document.getElementById('threatAlertText');

const loginCardEl = document.getElementById('loginCard');
const loginBadgeTextEl = document.getElementById('loginBadgeText');
const loginSafetyTagEl = document.getElementById('loginSafetyTag');
const loginDescEl = document.getElementById('loginDesc');

const metricDestinationsEl = document.getElementById('metricDestinations');
const metricTrackersEl = document.getElementById('metricTrackers');
const metricPostsEl = document.getElementById('metricPosts');

const btnOpenGraph = document.getElementById('btnOpenGraph');
const btnRefresh = document.getElementById('btnRefresh');
const btnOpenVault = document.getElementById('btnOpenVault');
const miniCanvas = document.getElementById('miniCanvas');
const miniPreviewEmptyEl = document.getElementById('miniPreviewEmpty');

let miniCtx = null;

function setupMiniCanvas() {
    if (!miniCanvas) return;
    miniCtx = miniCanvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = miniCanvas.getBoundingClientRect();
    miniCanvas.width = rect.width * dpr;
    miniCanvas.height = rect.height * dpr;
    miniCtx.scale(dpr, dpr);
}

function drawMiniCanvas() {
    if (!miniCtx || !miniCanvas) return;
    const rect = miniCanvas.getBoundingClientRect();
    const w = rect.width;
    const h = rect.height;
    const stateNodes = Object.values(currentTabState?.nodes || {});

    miniCtx.save();
    miniCtx.setTransform(1, 0, 0, 1, 0, 0);
    miniCtx.clearRect(0, 0, miniCanvas.width, miniCanvas.height);
    miniCtx.restore();

    miniPreviewEmptyEl.style.display = stateNodes.length > 1 ? 'none' : 'flex';
    if (stateNodes.length < 2) return;

    const cx = w / 2;
    const cy = h / 2;
    const primary = stateNodes.find(node => node.isPrimary || node.host === currentTabState.pageHost) || stateNodes[0];
    const destinations = stateNodes.filter(node => node !== primary).slice(0, 8);
    const positions = new Map([[primary.host, { x: cx, y: cy }]]);
    const categoryColors = {
        Primary: '#8ab4f8',
        Auth: '#55d6be',
        Tracking: '#fdd663',
        API: '#ffad66',
        Service: '#81c995',
        Analytics: '#65d8ff',
        Essential: '#a7e8a1',
        Unknown: '#a0a2aa'
    };

    destinations.forEach((node, index) => {
        const angle = (index / destinations.length) * Math.PI * 2;
        const distance = Math.min(w * 0.32, h * 0.34);
        positions.set(node.host, {
            x: cx + Math.cos(angle) * distance,
            y: cy + Math.sin(angle) * distance
        });
    });

    for (const connection of currentTabState.connections || []) {
        const from = positions.get(connection.from);
        const to = positions.get(connection.to);
        if (!from || !to) continue;
        miniCtx.beginPath();
        miniCtx.moveTo(from.x, from.y);
        miniCtx.lineTo(to.x, to.y);
        miniCtx.strokeStyle = categoryColors[connection.category] || 'rgba(255, 255, 255, 0.12)';
        miniCtx.globalAlpha = 0.3;
        miniCtx.lineWidth = 1;
        miniCtx.stroke();
        miniCtx.globalAlpha = 1;
    }

    for (const node of [primary, ...destinations]) {
        const position = positions.get(node.host);
        miniCtx.beginPath();
        miniCtx.arc(position.x, position.y, node === primary ? 5 : 3.5, 0, Math.PI * 2);
        miniCtx.shadowColor = categoryColors[node.category] || categoryColors.Unknown;
        miniCtx.shadowBlur = 8;
        miniCtx.fillStyle = categoryColors[node.category] || categoryColors.Unknown;
        miniCtx.fill();
        miniCtx.shadowBlur = 0;
    }
}

// Init
async function init() {
    try {
        setupMiniCanvas();

        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.id) return;

        currentTabId = tab.id;

        chrome.runtime.sendMessage({ type: 'GET_TAB_DATA', tabId: currentTabId }, (res) => {
            if (res && res.state) {
                currentTabState = res.state;
                render();
            } else {
                chrome.storage.local.get(`tab_${currentTabId}`, (data) => {
                    currentTabState = data[`tab_${currentTabId}`] || null;
                    render();
                });
            }
        });
    } catch (err) {
        console.error('Init error:', err);
    }
}

function render() {
    if (!currentTabState) {
        miniPreviewEmptyEl.style.display = 'flex';
        metricDestinationsEl.textContent = '0';
        metricTrackersEl.textContent = '0';
        metricPostsEl.textContent = '0';
        return;
    }

    const host = currentTabState.pageHost || 'Active Site';
    const isHttp = currentTabState.pageProtocol === 'http:';
    const legit = currentTabState.legitimacy || {};
    const isBad = Boolean(legit.isThreat || isHttp);
    const verifiedSources = legit.verifiedSources || [];
    const hasLookupEvidence = legit.checks?.dns === 'clean' || legit.checks?.rdap === 'checked' || legit.checks?.rdap === 'registered' ||
        verifiedSources.some(source => source.startsWith('Cloudflare') || source.startsWith('ICANN RDAP'));

    renderVerificationChips(legit);

    // Host Chip
    hostNameEl.textContent = host;
    lockIconEl.classList.toggle('is-http', isHttp);

    // 1. Website Informant
    if (isBad) {
        informantCardEl.className = 'card informant-card threat';
        statusAvatarEl.innerHTML = `
            <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
            </svg>
        `;
        statusTitleEl.textContent = isHttp ? 'Insecure HTTP Website' : 'Security Warning: Untrusted Site';
        statusCategoryEl.textContent = isHttp ? 'Unencrypted connection — data is vulnerable' : (legit.threatReason || 'Flagged by security filter');

        threatAlertBoxEl.style.display = 'flex';
        threatAlertTextEl.textContent = legit.threatReason || 'Unencrypted HTTP! Do not enter passwords or personal information.';

    } else if (hasLookupEvidence) {
        informantCardEl.className = 'card informant-card safe';
        statusAvatarEl.innerHTML = `
            <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
            </svg>
        `;
        statusTitleEl.textContent = 'No Known Threat Detected';

        const yearText = legit.registrationYear ? ` • Est. ${legit.registrationYear}` : '';
        statusCategoryEl.textContent = `${legit.category || 'General Web'}${yearText}`;

        threatAlertBoxEl.style.display = 'none';

    } else {
        informantCardEl.className = 'card informant-card unknown';
        statusAvatarEl.innerHTML = `
            <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm1 15h-2v-2h2v2zm0-4h-2c0-2 2-2.5 2-4a2 2 0 0 0-4 0H7a4 4 0 0 1 8 0c0 2.5-2 3-2 4z"/>
            </svg>
        `;
        statusTitleEl.textContent = 'Unable to Verify';
        statusCategoryEl.textContent = 'Reputation sources returned no conclusive result';
        threatAlertBoxEl.style.display = 'none';
    }

    // 2. Login & Sign-in Scanner Feature
    const login = currentTabState.loginData || {};
    if (login.hasLogin) {
        loginCardEl.style.display = 'flex';
        const isSignup = login.authType === 'signup';
        loginBadgeTextEl.textContent = login.hasPassword ? 'Password Field Detected' : (isSignup ? 'Sign-up Page Detected' : 'Sign-in Page Detected');

        if (login.hasPassword && login.isFormTargetCrossOrigin) {
            loginSafetyTagEl.textContent = 'Cross-Origin ⚠️';
            loginSafetyTagEl.style.color = '#f28b82';
            loginSafetyTagEl.style.background = 'rgba(242, 139, 130, 0.2)';
            loginDescEl.textContent = `This site is saved after password entry. Password contents are never read. Form targets "${login.primaryFormTarget}".`;
        } else if (login.hasPassword) {
            loginSafetyTagEl.textContent = 'Vault Auto';
            loginSafetyTagEl.style.color = '#8ab4f8';
            loginSafetyTagEl.style.background = 'rgba(138, 180, 248, 0.2)';
            loginDescEl.textContent = 'This site is saved after password entry. Only the domain is stored; password contents are never read.';
        } else if (login.isFormTargetCrossOrigin) {
            loginSafetyTagEl.textContent = 'Cross-Origin ⚠️';
            loginSafetyTagEl.style.color = '#f28b82';
            loginSafetyTagEl.style.background = 'rgba(242, 139, 130, 0.2)';
            loginDescEl.textContent = `Sign-in flow points to external domain "${login.primaryFormTarget}".`;
        } else {
            loginSafetyTagEl.textContent = 'First-Party';
            loginSafetyTagEl.style.color = '#81c995';
            loginSafetyTagEl.style.background = 'rgba(129, 201, 149, 0.2)';
            loginDescEl.textContent = 'No password value is read by DataGhost.';
        }
    } else {
        loginCardEl.style.display = 'none';
    }

    // 3. Data Detective Metrics
    const nodes = Object.values(currentTabState.nodes || {});
    const posts = currentTabState.posts || [];
    let trackerCount = 0;

    nodes.forEach(n => {
        if (n.category === 'Tracking') trackerCount++;
    });

    metricDestinationsEl.textContent = nodes.length > 0 ? nodes.length : 1;
    metricTrackersEl.textContent = trackerCount;
    metricPostsEl.textContent = posts.length;
    drawMiniCanvas();
}

function renderVerificationChips(legit) {
    const sources = legit.verifiedSources || [];
    const checks = legit.checks || {};
    chipCategoryEl.textContent = legit.category || 'General Web';

    const dns = checks.dns || (sources.some(source => source.startsWith('Cloudflare')) ? 'clean' : 'unknown');
    chipDnsEl.className = dns === 'blocked' ? 'chip chip-red' : dns === 'clean' ? 'chip chip-green' : 'chip chip-muted';
    chipDnsEl.textContent = dns === 'blocked' ? 'DNS: Threat reported' : dns === 'clean' ? 'DNS: No block found' : 'DNS: Not confirmed';

    const rdapChecked = checks.rdap === 'checked' || checks.rdap === 'registered' || sources.some(source => source.startsWith('ICANN RDAP'));
    chipRdapEl.className = rdapChecked ? 'chip chip-green' : 'chip chip-muted';
    chipRdapEl.textContent = rdapChecked ? `RDAP: ${legit.registrationYear || 'Checked'}` : 'RDAP: Not confirmed';
}

// Open cropped standalone window (NOT a new tab!)
btnOpenGraph.addEventListener('click', () => {
    chrome.windows.create({
        url: chrome.runtime.getURL(`graph.html?tabId=${currentTabId || ''}`),
        type: 'popup',
        width: 680,
        height: 500,
        focused: true
    });
});

btnRefresh.addEventListener('click', () => {
    init();
});

// Open Vault window
btnOpenVault.addEventListener('click', () => {
    chrome.windows.create({
        url: chrome.runtime.getURL('vault.html'),
        type: 'popup',
        width: 680,
        height: 500,
        focused: true
    });
});

chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'REALTIME_GRAPH_PULSE' && msg.tabId === currentTabId) {
        init();
    }
});

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && currentTabId && changes[`tab_${currentTabId}`]) {
        currentTabState = changes[`tab_${currentTabId}`].newValue;
        render();
    }
});

document.addEventListener('DOMContentLoaded', init);

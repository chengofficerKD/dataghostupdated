// DataGhost Cropped Graph Window Engine — Google Material Palette
// Clean 60fps vector canvas without buffer leaks or bottom artifacts.

let canvas = null;
let ctx = null;
let tabId = null;

// Telemetry
const graphTitle = document.getElementById('graphTitle');
const nodeCountEl = document.getElementById('nodeCount');
const connectionCountEl = document.getElementById('connectionCount');
const btnResetView = document.getElementById('btnResetView');

// Inspector
const inspectorCard = document.getElementById('inspectorCard');
const inspectCat = document.getElementById('inspectCat');
const inspectHost = document.getElementById('inspectHost');
const inspectCount = document.getElementById('inspectCount');
const inspectSec = document.getElementById('inspectSec');
const btnCloseInspect = document.getElementById('btnCloseInspect');

// Google Material Color Palette
const CATEGORY_COLORS = {
    'Primary': '#8ab4f8',
    'Auth': '#55d6be',
    'Tracking': '#fdd663',
    'API': '#ffad66',
    'Service': '#81c995',
    'Analytics': '#65d8ff',
    'Essential': '#a7e8a1',
    'Unknown': '#a0a2aa'
};

let nodes = [];
let connections = [];
let pulses = [];
let hoveredNode = null;
let selectedNode = null;

// Transform (Pan & Zoom)
let scale = 1.0;
let panX = 0;
let panY = 0;
let isDragging = false;
let startX = 0;
let startY = 0;

function init() {
    canvas = document.getElementById('brainCanvas');
    ctx = canvas.getContext('2d');

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const urlParams = new URLSearchParams(window.location.search);
    const paramTabId = urlParams.get('tabId');

    if (paramTabId) {
        tabId = parseInt(paramTabId, 10);
        loadGraphData(tabId);
    } else {
        chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
            if (tabs && tabs[0]) {
                tabId = tabs[0].id;
                loadGraphData(tabId);
            } else {
                loadEmptyGraph();
            }
        });
    }

    setupInteractions();
    requestAnimationFrame(renderLoop);
}

// Pixel-perfect canvas sizing matching bounding rect and device pixel ratio
function resizeCanvas() {
    if (!canvas || !ctx) return;
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;

    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
}

function loadGraphData(targetTabId) {
    chrome.runtime.sendMessage({ type: 'GET_TAB_DATA', tabId: targetTabId }, (res) => {
        if (res && res.state && Object.keys(res.state.nodes || {}).length > 0) {
            buildGraphFromState(res.state);
        } else {
            loadEmptyGraph();
        }
    });
}

function loadEmptyGraph() {
    graphTitle.textContent = 'DataGhost — Waiting for observed traffic';
    nodes = [];
    connections = [];
    pulses = [];
    updateStats();
}

function buildGraphFromState(state) {
    const primary = state.pageHost || state.primaryDomain || 'Active Site';
    graphTitle.textContent = `DataGhost — ${primary}`;

    nodes = [];
    connections = [];
    pulses = [];

    const rect = canvas.getBoundingClientRect();
    const cx = rect.width / 2;
    const cy = rect.height / 2;

    const hub = {
        id: primary,
        host: primary,
        category: 'Primary',
        x: cx,
        y: cy,
        radius: 18,
        count: 1,
        color: CATEGORY_COLORS['Primary'],
        isPrimary: true
    };
    nodes.push(hub);

    const rawNodes = Object.values(state.nodes || {}).filter(n => n.host !== primary);
    const count = rawNodes.length;
    const minDim = Math.min(rect.width, rect.height);
    const baseDist = Math.max(90, Math.min(160, minDim * 0.32));

    rawNodes.forEach((n, i) => {
        const angle = (i / Math.max(1, count)) * Math.PI * 2 + 0.1;
        const dist = baseDist + (i % 3) * 35;
        const color = CATEGORY_COLORS[n.category] || CATEGORY_COLORS['Unknown'];

        const newNode = {
            id: n.host,
            host: n.host,
            category: n.category,
            x: cx + Math.cos(angle) * dist,
            y: cy + Math.sin(angle) * dist,
            radius: Math.min(14, 6 + Math.log2(n.count || 1) * 2),
            count: n.count || 1,
            color: color,
            isSecure: n.isSecure !== false,
            isPrimary: false
        };
        nodes.push(newNode);
    });

    const nodeByHost = new Map(nodes.map(node => [node.host, node]));
    const seenConnections = new Set();
    for (const connection of state.connections || []) {
        const from = nodeByHost.get(connection.from);
        const to = nodeByHost.get(connection.to);
        const key = `${connection.from}->${connection.to}`;
        if (!from || !to || seenConnections.has(key)) continue;
        seenConnections.add(key);
        connections.push({ from, to, color: CATEGORY_COLORS[connection.category] || CATEGORY_COLORS['Unknown'] });
    }

    updateStats();
}

function updateStats() {
    nodeCountEl.textContent = nodes.length;
    connectionCountEl.textContent = connections.length;
}

function setupInteractions() {
    canvas.addEventListener('mousedown', (e) => {
        isDragging = true;
        startX = e.clientX - panX;
        startY = e.clientY - panY;
    });

    window.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        const mouseX = (e.clientX - rect.left - panX) / scale;
        const mouseY = (e.clientY - rect.top - panY) / scale;

        if (isDragging) {
            panX = e.clientX - startX;
            panY = e.clientY - startY;
        }

        hoveredNode = null;
        for (const n of nodes) {
            const dx = n.x - mouseX;
            const dy = n.y - mouseY;
            if (Math.sqrt(dx * dx + dy * dy) < n.radius + 6) {
                hoveredNode = n;
                break;
            }
        }
    });

    window.addEventListener('mouseup', () => {
        isDragging = false;
    });

    canvas.addEventListener('wheel', (e) => {
        e.preventDefault();
        const factor = 1.08;
        if (e.deltaY < 0) {
            scale = Math.min(2.5, scale * factor);
        } else {
            scale = Math.max(0.4, scale / factor);
        }
    }, { passive: false });

    canvas.addEventListener('click', () => {
        if (hoveredNode) {
            selectedNode = hoveredNode;
            inspectorCard.style.display = 'block';
            inspectCat.textContent = selectedNode.category;
            inspectCat.style.backgroundColor = selectedNode.color;
            inspectHost.textContent = selectedNode.host;
            inspectCount.textContent = selectedNode.count;
            inspectSec.textContent = selectedNode.isSecure !== false ? 'HTTPS; TLS version unavailable' : 'HTTP; unencrypted';
        }
    });

    btnCloseInspect.addEventListener('click', () => {
        inspectorCard.style.display = 'none';
        selectedNode = null;
    });

    btnResetView.addEventListener('click', () => {
        scale = 1.0;
        panX = 0;
        panY = 0;
    });
}

// Real-Time Requests Pulse
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'REALTIME_GRAPH_PULSE' && (!tabId || msg.tabId === tabId)) {
        const req = msg.request;
        const fromHost = req.from;
        let source = nodes.find(n => n.host === fromHost);
        if (!source && fromHost) {
            const rect = canvas.getBoundingClientRect();
            const angle = Math.random() * Math.PI * 2;
            source = {
                id: fromHost,
                host: fromHost,
                category: 'Unknown',
                x: rect.width / 2 + Math.cos(angle) * 90,
                y: rect.height / 2 + Math.sin(angle) * 70,
                radius: 6,
                count: 1,
                color: CATEGORY_COLORS['Unknown'],
                isSecure: true,
                isPrimary: false
            };
            nodes.push(source);
            updateStats();
        }

        let dest = nodes.find(n => n.host === req.to);

        if (!dest) {
            const rect = canvas.getBoundingClientRect();
            const cx = rect.width / 2;
            const cy = rect.height / 2;
            const angle = Math.random() * Math.PI * 2;
            const dist = 100 + Math.random() * 50;
            const color = CATEGORY_COLORS[req.category] || CATEGORY_COLORS['Unknown'];

            dest = {
                id: req.to,
                host: req.to,
                category: req.category,
                x: cx + Math.cos(angle) * dist,
                y: cy + Math.sin(angle) * dist,
                radius: 8,
                count: 1,
                color: color,
                isSecure: req.isSecure,
                isPrimary: false
            };
            nodes.push(dest);

            updateStats();
        } else {
            dest.count++;
        }

        if (source && source !== dest) {
            const edge = connections.find(c => c.from === source && c.to === dest);
            if (!edge) connections.push({ from: source, to: dest, color: dest.color });
            pulses.push({
                fromX: source.x,
                fromY: source.y,
                toX: dest.x,
                toY: dest.y,
                progress: 0,
                speed: 0.025,
                color: dest.color
            });
        }
    }
});

// Render Loop: Completely clears the entire physical canvas buffer every frame
function renderLoop() {
    if (!canvas || !ctx) return;
    const dpr = window.devicePixelRatio || 1;

    // 1. Wipe the entire hardware buffer cleanly with reset transform
    ctx.save();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.restore();

    // 2. Set coordinate transform for drawing
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.translate(panX, panY);
    ctx.scale(scale, scale);

    if (nodes.length === 0) {
        ctx.font = '12px "Google Sans", "Roboto", sans-serif';
        ctx.fillStyle = '#9aa0a6';
        ctx.textAlign = 'center';
        ctx.fillText('Waiting for observed traffic', canvas.clientWidth / 2, canvas.clientHeight / 2);
    }

    // 3. Draw Connecting Links
    for (const c of connections) {
        ctx.beginPath();
        ctx.moveTo(c.from.x, c.from.y);
        ctx.lineTo(c.to.x, c.to.y);
        ctx.strokeStyle = c.color || 'rgba(255, 255, 255, 0.12)';
        ctx.globalAlpha = 0.3;
        ctx.lineWidth = 1.2;
        ctx.stroke();
        ctx.globalAlpha = 1;
    }

    // 4. Draw Traveling Data Pulses
    for (let i = pulses.length - 1; i >= 0; i--) {
        const p = pulses[i];
        p.progress += p.speed;
        if (p.progress >= 1.0) {
            pulses.splice(i, 1);
            continue;
        }

        const px = p.fromX + (p.toX - p.fromX) * p.progress;
        const py = p.fromY + (p.toY - p.fromY) * p.progress;

        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 10;
        ctx.fillStyle = p.color;
        ctx.fill();
        ctx.shadowBlur = 0;
    }

    // 5. Draw Nodes & Labels
    for (const n of nodes) {
        const isHover = hoveredNode === n || selectedNode === n;

        // Hover Ring
        if (isHover) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius + 4, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(255, 255, 255, 0.1)';
            ctx.fill();
        }

        // Node Circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.shadowColor = n.color;
        ctx.shadowBlur = isHover ? 18 : 10;
        ctx.fillStyle = n.color;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Node Label
        ctx.font = '500 10px "JetBrains Mono", monospace';
        ctx.fillStyle = isHover ? '#ffffff' : 'rgba(235, 235, 245, 0.65)';
        ctx.textAlign = 'left';
        ctx.fillText(n.host, n.x + n.radius + 6, n.y + 3);
    }

    ctx.restore();
    requestAnimationFrame(renderLoop);
}

document.addEventListener('DOMContentLoaded', init);

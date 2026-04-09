// Get DOM elements
const scanBtn = document.getElementById('scanBtn');
const currentUrlEl = document.getElementById('currentUrl');
const resultDiv = document.getElementById('result');
const loadingDiv = document.getElementById('loading');
const errorDiv = document.getElementById('error');
const errorText = document.getElementById('errorText');
const dismissErrorBtn = document.getElementById('dismissError');
const resultContent = document.getElementById('resultContent');

let currentUrl = '';
let isScanning = false;

// Cache stored in chrome.storage.session (cleared when browser closes)
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// --- Safe storage abstraction ---
const memoryCache = new Map(); // fallback when chrome.storage.session is unavailable

const storage = {
    async get(key) {
        try {
            if (typeof chrome !== 'undefined' && chrome.storage?.session) {
                const result = await chrome.storage.session.get(key);
                return result[key] ?? null;
            }
        } catch (e) { /* fall through */ }
        return memoryCache.get(key) ?? null;
    },
    async set(key, value) {
        try {
            if (typeof chrome !== 'undefined' && chrome.storage?.session) {
                await chrome.storage.session.set({ [key]: value });
                return;
            }
        } catch (e) { /* fall through */ }
        memoryCache.set(key, value);
    },
    async remove(key) {
        try {
            if (typeof chrome !== 'undefined' && chrome.storage?.session) {
                await chrome.storage.session.remove(key);
                return;
            }
        } catch (e) { /* fall through */ }
        memoryCache.delete(key);
    }
};

async function getCached(url) {
    const key = 'cache_' + btoa(url).replace(/[^a-zA-Z0-9]/g, '_');
    const entry = await storage.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
        await storage.remove(key);
        return null;
    }
    return entry.data;
}

async function setCached(url, data) {
    const key = 'cache_' + btoa(url).replace(/[^a-zA-Z0-9]/g, '_');
    await storage.set(key, { data, timestamp: Date.now() });
}

document.addEventListener('DOMContentLoaded', async () => {
    await getCurrentUrl();
    scanBtn.addEventListener('click', () => scanUrl(false)); // manual = bypass cache
    dismissErrorBtn.addEventListener('click', dismissError);

    await new Promise(resolve => setTimeout(resolve, 300));
    if (currentUrl && !currentUrl.startsWith('chrome://')) {
        scanUrl(true); // auto-scan = use cache
    }
});

async function getCurrentUrl() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        currentUrl = tab.url;
        currentUrlEl.textContent = currentUrl;
    } catch (err) {
        console.error('Error getting URL:', err);
        currentUrlEl.textContent = 'Unable to get URL';
        showError('Could not retrieve the current URL');
    }
}

async function scanUrl(useCache = true) {
    if (isScanning || !currentUrl) return;

    // Check cache first (only on auto-scan or if useCache=true)
    if (useCache) {
        const cached = await getCached(currentUrl);
        if (cached) {
            hideResult();
            hideError();
            displayResult(cached, true); // true = show cached badge
            return;
        }
    }

    isScanning = true;
    scanBtn.disabled = true;
    hideResult();
    hideError();
    showLoading();

    try {
        const res = await fetch("http://127.0.0.1:8000/check/url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: currentUrl, model: "threat-detection" })
        });

        if (!res.ok) throw new Error(`Server error: ${res.status}`);

        const data = await res.json();
        await setCached(currentUrl, data);
        hideLoading();
        displayResult(data, false);
    } catch (err) {
        hideLoading();
        console.error('Scan error:', err);
        if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
            showError(
                'Could not connect to ThreatAdvisor server. ' +
                'Make sure the backend is running at http://127.0.0.1:8000'
            );
        } else {
            showError(`Error during scan: ${err.message}`);
        }
    } finally {
        isScanning = false;
        scanBtn.disabled = false;
    }
}

function displayResult(data, fromCache = false) {
    let html = '<div class="result-header">';

    const label = (data.label || data.threat_level || 'unknown').toLowerCase();
    const emoji = data.emoji || getEmojiForLabel(label);
    const isSafe = label === 'safe';
    const isDanger = label === 'danger' || label === 'malicious';
    const isWarning = label === 'warning';

    let statusClass = isSafe ? 'safe' : isDanger ? 'danger' : isWarning ? 'warning' : 'safe';
    let statusText = `${emoji} ${label.charAt(0).toUpperCase() + label.slice(1)}`;

    html += `<span class="result-status ${statusClass}">${statusText}</span>`;

    // Cached badge + rescan button
    if (fromCache) {
        html += `<span class="cached-badge" title="Cached result">⚡ Cached</span>`;
        html += `<button class="rescan-btn" onclick="scanUrl(false)">Rescan</button>`;
    }

    html += '</div>';
    html += '<div class="result-details">';

    if (data.reason) {
        html += `<p><strong>Assessment:</strong> ${escapeHtml(data.reason)}</p>`;
    } else if (data.message) {
        html += `<p><strong>Assessment:</strong> ${escapeHtml(data.message)}</p>`;
    }

    if (data.url) {
        html += `<p><strong>URL Checked:</strong><br><code style="word-break:break-all;font-size:11px;color:#666">${escapeHtml(data.url)}</code></p>`;
    }

    if (data.confidence) {
        let confidenceText = typeof data.confidence === 'number'
            ? Math.round(data.confidence * 100) + '%'
            : data.confidence;
        html += `<p><strong>Confidence:</strong> ${escapeHtml(String(confidenceText))}</p>`;
    }

    if (data.threats && Array.isArray(data.threats) && data.threats.length > 0) {
        html += '<strong>Detected Threats:</strong><ul class="threat-list">';
        data.threats.forEach(threat => {
            const threatName = typeof threat === 'string' ? threat : threat.name || 'Unknown threat';
            html += `<li>${escapeHtml(threatName)}</li>`;
        });
        html += '</ul>';
    }

    if (data.details) {
        html += `<p><strong>Details:</strong> ${escapeHtml(data.details)}</p>`;
    }

    html += '</div>';
    resultContent.innerHTML = html;
    showResult();
}

function getEmojiForLabel(label) {
    const emojiMap = { safe: '✅', warning: '⚠️', danger: '🚨', malicious: '🚨', suspicious: '⚠️' };
    return emojiMap[label] || '❓';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showLoading() { loadingDiv.classList.remove('hidden'); }
function hideLoading() { loadingDiv.classList.add('hidden'); }
function showResult() { resultDiv.classList.remove('hidden'); }
function hideResult() { resultDiv.classList.add('hidden'); }
function showError(message) { errorText.textContent = message; errorDiv.classList.remove('hidden'); }
function dismissError() { errorDiv.classList.add('hidden'); }
function hideError() { errorDiv.classList.add('hidden'); }
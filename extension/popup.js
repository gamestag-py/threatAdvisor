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
    scanBtn.addEventListener('click', () => scanUrl(false));
    dismissErrorBtn.addEventListener('click', dismissError);

    await new Promise(resolve => setTimeout(resolve, 300));
    if (currentUrl && !currentUrl.startsWith('chrome://')) {
        scanUrl(true);
        check_email();
    }
});


async function check_email() {
    const emailResultEl = document.getElementById('emailResult');
    const gmailMessagePattern = /https:\/\/mail\.google\.com\/mail\/u\/\d+\/#inbox\/[A-Za-z0-9]+/;

    // Not a Gmail message page — hide the card and bail
    if (!gmailMessagePattern.test(currentUrl)) {
        emailResultEl.style.display = 'none';
        return;
    }

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
                const emailBody = document.querySelector('.ii.gt .a3s');
                return emailBody ? emailBody.innerText : null;
            }
        });

        const emailText = results?.[0]?.result;
        if (!emailText) {
            console.warn('Email body not found in Gmail tab');
            emailResultEl.style.display = 'none';
            return;
        }

        const res = await fetch("http://127.0.0.1:8000/check/email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: emailText })
        });

        if (!res.ok) throw new Error(`Server error: ${res.status}`);

        const data = await res.json();
        console.log(data);
        showEmailResult(data);
        return data;

    } catch (err) {
        console.error('Email check error:', err);
        emailResultEl.style.display = 'none';
        showError(`Email scan failed: ${err.message}`);
    }
}

function showEmailResult(data) {
    const container = document.getElementById('emailResult');
    const inputEl    = document.getElementById('emailInput');
    const labelEl    = document.getElementById('emailLabel');
    const phishingEl = document.getElementById('emailPhishing');
    const confEl     = document.getElementById('emailConfidence');

    // Populate fields
    inputEl.textContent    = data.input      || '—';
    labelEl.textContent    = data.label      || '—';
    phishingEl.textContent = data.is_phishing || '—';
    confEl.textContent     = data.confidence  || '—';

    // Apply safe/danger class to verdict badge
    phishingEl.className = 'field-value verdict-badge';
    if (data.is_phishing === 'Safe') {
        phishingEl.classList.add('verdict-safe');
    } else {
        phishingEl.classList.add('verdict-danger');
    }

    container.style.display = 'block';
}

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
            await injectWarningIntoActiveTab(cached); // Inject warning if threat detected
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
            body: JSON.stringify({ url: currentUrl, model: "2" })
        });

        if (!res.ok) throw new Error(`Server error: ${res.status}`);

        const data = await res.json();
        await setCached(currentUrl, data);
        hideLoading();
        displayResult(data, false);
        await injectWarningIntoActiveTab(data); // Inject warning if threat detected
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
    const isDanger = label === 'danger' || label === 'malicious' || label === 'phishing';
    const isWarning = label === 'warning' || label === 'unverified';

    let statusClass = isSafe ? 'safe' : isDanger ? 'danger' : isWarning ? 'warning' : 'safe';
    let statusText = `${emoji} ${label.charAt(0).toUpperCase() + label.slice(1)}`;

    html += `<span class="result-status ${statusClass}">${statusText}</span>`;

    if (fromCache) {
        html += `<span class="cached-badge" title="Cached result">⚡ Cached</span>`;
        html += `<button class="rescan-btn" onclick="scanUrl(false)">Rescan</button>`;
    }

    html += '</div>';
    html += '<div class="result-details">';

    if (data.url) {
        html += `<p><strong>URL Checked:</strong><br>
                 <code style="word-break:break-all;font-size:11px;color:#666">
                   ${escapeHtml(data.url)}
                 </code></p>`;
    }

    if (data.confidence) {
        const confidenceText = typeof data.confidence === 'number'
            ? Math.round(data.confidence * 100) + '%'
            : data.confidence;
        html += `<p><strong>Confidence:</strong> ${escapeHtml(String(confidenceText))}</p>`;
    }

    // ── Reasons (array from new API) ──────────────────────────────────────────
    const reasons = Array.isArray(data.reasons) && data.reasons.length > 0
        ? data.reasons
        : data.reason                           // legacy single-string fallback
            ? [data.reason]
            : data.message
                ? [data.message]
                : [];

    if (reasons.length > 0) {
        html += `<div>
                   <strong>Assessment:</strong>
                   <ul class="threat-list" style="margin-top:6px">
                     ${reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                   </ul>
                 </div>`;
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
// ========== THREAT WARNING INJECTION ==========

// Main function that injects threat warning into the active tab
async function injectWarningIntoActiveTab(data) {
    const label = (data.label || data.threat_level || 'unknown').toLowerCase();
    const isDanger = label === 'danger' || label === 'malicious';
    const isWarning = label === 'warning' || label === 'phishing' || label === 'suspicious';

    if (!isDanger && !isWarning) return; // Only show for threats

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    try {
        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: injectThreatWarning,
            args: [{
                isDanger,
                isWarning,
                url: data.url || tab.url || '',
                reason: data.reason || data.message || '',
                threats: data.threats || [],
                label: label
            }]
        });
    } catch (err) {
        // Chrome's built-in warning page blocks content scripts
        // This is expected behavior - the warning is already shown by Chrome
        console.log('Warning: Could not inject custom warning (Chrome safety page may be blocking it)', err.message);
    }
}

// This function runs INSIDE the webpage (injected via executeScript)
function injectThreatWarning(threatData) {
    const { isDanger, url } = threatData;

    const modal = document.createElement('div');
    modal.id = 'threat-warning-modal';
    modal.style.cssText = `
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.6);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    `;

    const card = document.createElement('div');
    card.style.cssText = `
        background: #fff;
        border-radius: 16px;
        width: 360px;
        padding: 24px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        text-align: center;
    `;

    // HEADER
    const header = document.createElement('div');
    header.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <div style="display:flex;align-items:center;gap:8px;">
                <div style="width:28px;height:28px;background:#ff7a00;border-radius:6px; background:url(https://cdn-icons-png.flaticon.com/512/9645/9645004.png)no-repeat center center;background-size:cover"></div>
                <span style="font-weight:600;font-size:16px;color:black">ThreatAdvisor</span>
            </div>
            <span style="background:#2ecc71;color:#fff;padding:4px 10px;border-radius:20px;font-size:12px;">
                Active
            </span>
        </div>
        <hr style="border:none;border-top:1px solid #eee;margin-bottom:20px;">
    `;
    card.appendChild(header);

    // ICON
    const icon = document.createElement('div');
    icon.innerHTML = `
        <div style="
            width:80px;
            height:80px;
            background:#ff6a00;
            border-radius:50%;
            display:flex;
            align-items:center;
            justify-content:center;
            margin:0 auto 16px;
            color:white;
            font-size:40px;
            font-weight:bold;
        ">!</div>
    `;
    card.appendChild(icon);

    // TITLE
    const title = document.createElement('h2');
    title.textContent = 'Phishing Threat Detected';
    title.style.cssText = `
        color:#e53935;
        font-size:20px;
        margin-bottom:8px;
    `;
    card.appendChild(title);

    // URL
    const urlText = document.createElement('p');
    urlText.textContent = url;
    urlText.style.cssText = `
        font-size:13px;
        color:#555;
        margin-bottom:20px;
        word-break:break-all;
    `;
    card.appendChild(urlText);

    // BLOCK BUTTON
    const blockBtn = document.createElement('button');
    blockBtn.textContent = 'Block this site';
    blockBtn.style.cssText = `
        width:100%;
        padding:12px;
        background:linear-gradient(135deg,#ff6a00,#ff3d00);
        color:white;
        border:none;
        border-radius:8px;
        font-weight:600;
        cursor:pointer;
        margin-bottom:10px;
    `;
    blockBtn.onclick = () => {
        window.location.href = "about:blank";
    };

    // IGNORE BUTTON
    const ignoreBtn = document.createElement('button');
    ignoreBtn.textContent = 'Ignore';
    ignoreBtn.style.cssText = `
        width:100%;
        padding:12px;
        background:white;
        border:2px solid #ff6a00;
        color:#ff6a00;
        border-radius:8px;
        font-weight:600;
        cursor:pointer;
    `;
    ignoreBtn.onclick = () => modal.remove();

    card.appendChild(blockBtn);
    card.appendChild(ignoreBtn);

    // FOOTER
    const footer = document.createElement('p');
    footer.textContent = 'Scanned in 0.3s';
    footer.style.cssText = `
        margin-top:12px;
        font-size:12px;
        color:#888;
    `;
    card.appendChild(footer);

    modal.appendChild(card);
    document.body.appendChild(modal);
}

// ========== UTILITY FUNCTIONS ==========

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
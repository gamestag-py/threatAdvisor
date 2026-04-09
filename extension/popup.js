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
    const { isDanger, isWarning, url, reason, threats, label } = threatData;

    // Create warning modal wrapper
    const modal = document.createElement('div');
    modal.id = 'threat-warning-modal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    `;

    // Create warning card
    const card = document.createElement('div');
    card.style.cssText = `
        background: white;
        border-radius: 12px;
        padding: 32px;
        max-width: 500px;
        width: 90%;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        animation: slideIn 0.3s ease-out;
    `;

    // Add animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    `;
    document.head.appendChild(style);

    // Warning header
    const header = document.createElement('div');
    header.style.cssText = `
        text-align: center;
        margin-bottom: 20px;
    `;

    const emoji = isDanger ? '🚨' : '⚠️';
    const statusColor = isDanger ? '#d32f2f' : '#f57c00';
    const statusText = isDanger ? 'MALICIOUS SITE DETECTED' : 'WARNING: SUSPICIOUS SITE';

    header.innerHTML = `
        <div style="font-size: 48px; margin-bottom: 12px;">${emoji}</div>
        <h1 style="margin: 0; color: ${statusColor}; font-size: 20px; font-weight: 600;">
            ${statusText}
        </h1>
    `;
    card.appendChild(header);

    // Risk description
    const description = document.createElement('p');
    description.style.cssText = `
        color: #333;
        font-size: 14px;
        line-height: 1.6;
        margin: 16px 0;
        text-align: center;
    `;
    description.textContent = reason || 'This website has been flagged as potentially harmful.';
    card.appendChild(description);

    // Threats list (if available)
    if (threats && threats.length > 0) {
        const threatsList = document.createElement('div');
        threatsList.style.cssText = `
            background: #f5f5f5;
            border-left: 4px solid ${statusColor};
            padding: 12px;
            border-radius: 4px;
            margin: 16px 0;
            font-size: 13px;
            color: #555;
        `;
        threatsList.innerHTML = `<strong>Detected Threats:</strong><ul style="margin: 8px 0 0 20px; padding: 0;">
            ${threats.map(t => {
                const threatName = typeof t === 'string' ? t : t.name || 'Unknown threat';
                return `<li>${threatName}</li>`;
            }).join('')}
        </ul>`;
        card.appendChild(threatsList);
    }

    // URL display
    const urlDisplay = document.createElement('div');
    urlDisplay.style.cssText = `
        background: #f9f9f9;
        padding: 10px;
        border-radius: 4px;
        margin: 16px 0;
        font-size: 12px;
        color: #666;
        word-break: break-all;
        border: 1px solid #ddd;
    `;
    urlDisplay.innerHTML = `<strong>URL:</strong> ${url}`;
    card.appendChild(urlDisplay);

    // Button container
    const buttonContainer = document.createElement('div');
    buttonContainer.style.cssText = `
        display: flex;
        gap: 12px;
        margin-top: 24px;
    `;

    // Go back button
    const goBackBtn = document.createElement('button');
    goBackBtn.textContent = '← Go Back';
    goBackBtn.style.cssText = `
        flex: 1;
        padding: 12px 16px;
        border: 2px solid #ddd;
        background: white;
        color: #333;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
    `;
    goBackBtn.onmouseover = () => {
        goBackBtn.style.background = '#f5f5f5';
        goBackBtn.style.borderColor = '#999';
    };
    goBackBtn.onmouseout = () => {
        goBackBtn.style.background = 'white';
        goBackBtn.style.borderColor = '#ddd';
    };
    goBackBtn.onclick = () => {
        window.history.back();
    };
    buttonContainer.appendChild(goBackBtn);

    // Continue button (with warning for malicious sites)
    const continueBtn = document.createElement('button');
    continueBtn.textContent = isDanger ? 'Continue Anyway' : 'Continue';
    continueBtn.style.cssText = `
        flex: 1;
        padding: 12px 16px;
        border: none;
        background: ${statusColor};
        color: white;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
    `;
    continueBtn.onmouseover = () => {
        continueBtn.style.opacity = '0.9';
        continueBtn.style.transform = 'translateY(-1px)';
    };
    continueBtn.onmouseout = () => {
        continueBtn.style.opacity = '1';
        continueBtn.style.transform = 'translateY(0)';
    };
    continueBtn.onclick = () => {
        modal.remove();
    };
    buttonContainer.appendChild(continueBtn);

    card.appendChild(buttonContainer);
    modal.appendChild(card);
    document.body.insertBefore(modal, document.body.firstChild);
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
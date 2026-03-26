
let allDiscoveries = [];
let liveUpdateIntervalsStarted = false;

document.addEventListener('DOMContentLoaded', () => {
    const suggestionForm = document.getElementById('suggestionForm');

    if (suggestionForm) {
        suggestionForm.addEventListener('submit', handleSuggestionSubmit);
    }

    setupDiscoverySearch();
    setupClientDownloadDelegation();

    startLiveUpdates();
    loadScanningStatus();
    loadRecentDiscoveries();
});

async function handleSuggestionSubmit(e) {
    e.preventDefault();

    const messageDiv = document.getElementById('suggestionMessage');
    const submitButton = e.target.querySelector('button[type="submit"]');

    const suggestion = document.getElementById('suggestion')?.value || '';
    const priority = document.getElementById('priority')?.checked || false;

    if (!messageDiv || !submitButton) return;

    messageDiv.style.display = 'none';
    submitButton.disabled = true;
    submitButton.textContent = 'Submitting...';

    try {
        const response = await apiRequest('/api/discovery/suggest', {
            method: 'POST',
            body: JSON.stringify({
                suggestion,
                priority,
                source: 'user_suggestion',
                timestamp: new Date().toISOString()
            })
        });

        if (!response?.success) {
            throw new Error(response?.message || 'Failed to submit suggestion');
        }

        showMessage(
            messageDiv,
            'success',
            `Thank you. "${suggestion}" was added to the discovery queue.`
        );

        e.target.reset();
        setTimeout(loadRecentDiscoveries, 1000);

    } catch (error) {
        console.error('Suggestion submission error:', error);

        showMessage(
            messageDiv,
            'error',
            `Error: ${error.message}. Saved locally.`
        );

        queueLocalSuggestion(suggestion, priority);
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = '<i class="fa-solid fa-crosshairs"></i> Suggest Target';
    }
}

async function loadScanningStatus() {
    try {
        const status = await apiRequest('/api/discovery/status');

        if (!status) return;

        updateElementHTML('scanningTarget',
            status.current_target
                ? `Currently scanning: <span class="highlight">${escapeHtml(status.current_target)}</span>`
                : null
        );

        updateElementHTML('scannedCount',
            status.scanned_today != null
                ? `Total scanned today: <span class="highlight">${status.scanned_today.toLocaleString()}</span>`
                : null
        );

        updateElementHTML('foundVulns',
            status.vulnerabilities_found != null
                ? `Vulnerabilities found: <span class="highlight critical">${status.vulnerabilities_found}</span>`
                : null
        );

        if (status.stats) updateStats(status.stats);

    } catch {
        useDemoScanningStatus();
    }
}

async function loadRecentDiscoveries() {
    try {
        const response = await apiRequest('/api/discovery/recent?limit=10');

        if (response?.discoveries?.length) {
            allDiscoveries = response.discoveries;
        } else if (!allDiscoveries.length) {
            allDiscoveries = readDiscoveriesFromDom();
        }

        applyDiscoverySearch();

    } catch {
        if (!allDiscoveries.length) {
            allDiscoveries = readDiscoveriesFromDom();
        }
        applyDiscoverySearch();
    }
}


function displayDiscoveries(discoveries) {
    const container = document.getElementById('discoveriesList');
    if (!container) return;

    if (!discoveries.length) {
        container.innerHTML = `
            <div class="discovery-item">
                <div class="discovery-info">
                    <span class="discovery-target">No results found</span>
                </div>
            </div>`;
        return;
    }

    container.innerHTML = discoveries.map(d => {
        const vulns = d.vulnerabilities || [];
        const hasVulns = vulns.length > 0;

        return `
        <div class="discovery-item ${hasVulns ? 'vulnerability-found' : ''}">
            <div class="discovery-info">
                <span class="discovery-type">${escapeHtml(d.type || 'target')}</span>
                <span class="discovery-target">${escapeHtml(d.target || 'unknown')}</span>
                <span class="discovery-time">${formatTimeAgo(d.discovered_at)}</span>
            </div>

            <div class="discovery-status">
                ${vulns.map(v =>
                    `<span class="severity ${escapeHtml(v.severity || 'info')}">
                        ${escapeHtml(v.count || 0)} ${escapeHtml(v.severity || '')}
                    </span>`
                ).join('')}

                <span class="status ${escapeHtml(d.status || 'queued')}">
                    ${escapeHtml(getStatusText(d.status))}
                </span>

                <button class="btn-download-client"
                    data-type="${escapeHtml(d.type)}"
                    data-target="${escapeHtml(d.target)}"
                    data-status="${escapeHtml(d.status)}"
                    data-discovered-at="${escapeHtml(d.discovered_at || '')}">
                    Download
                </button>
            </div>
        </div>`;
    }).join('');
}

function updateStats(stats) {
    setText('domainCount', stats.domains_discovered);
    setText('repoCount', stats.repos_found);
    setText('activeScans', stats.active_scans);
    setText('contactedCount', stats.contacts_made);
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el && value != null) {
        el.textContent = value.toLocaleString ? value.toLocaleString() : value;
    }
}

function updateElementHTML(id, html) {
    const el = document.getElementById(id);
    if (el && html) el.innerHTML = html;
}

function startLiveUpdates() {
    if (liveUpdateIntervalsStarted) return;

    liveUpdateIntervalsStarted = true;

    setInterval(loadScanningStatus, 10000);
    setInterval(loadRecentDiscoveries, 30000);
}


function setupDiscoverySearch() {
    const input = document.getElementById('discoverySearch');
    if (!input) return;

    input.addEventListener('input', applyDiscoverySearch);
}

function applyDiscoverySearch() {
    const query = document.getElementById('discoverySearch')?.value.toLowerCase() || '';

    const filtered = allDiscoveries.filter(d =>
        (d.type || '').toLowerCase().includes(query) ||
        (d.target || '').toLowerCase().includes(query)
    );

    displayDiscoveries(filtered);
}


function formatTimeAgo(ts) {
    if (!ts) return 'just now';

    const diff = Math.floor((Date.now() - new Date(ts)) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

function getStatusText(status) {
    return {
        queued: 'Queued',
        running: 'Scanning',
        completed: 'Complete',
        failed: 'Failed'
    }[status] || status;
}

function showMessage(el, type, msg) {
    el.className = `message ${type} show`;
    el.textContent = msg;
}

function escapeHtml(str) {
    return String(str)
        .replace(/[&<>"']/g, m =>
            ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])
        );
}


function setupClientDownloadDelegation() {
    document.addEventListener('click', e => {
        const btn = e.target.closest('.btn-download-client');
        if (!btn) return;

        downloadToClient(btn.dataset);
    });
}

function downloadToClient(data) {
    const blob = new Blob(
        [JSON.stringify({ task: data }, null, 2)],
        { type: 'application/json' }
    );

    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `task-${(data.target || 'unknown').replace(/\W/g, '_')}.json`;

    document.body.appendChild(a);
    a.click();
    a.remove();
}


function queueLocalSuggestion(suggestion, priority) {
    const list = JSON.parse(localStorage.getItem('pendingSuggestions') || '[]');

    list.push({
        suggestion,
        priority,
        timestamp: new Date().toISOString()
    });

    localStorage.setItem('pendingSuggestions', JSON.stringify(list));
}

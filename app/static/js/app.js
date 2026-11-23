// =============================================================================
// Patch Manager AI: dashboard
// No inline handlers (the page runs under a strict CSP). All URLs are
// relative so the app works at / and behind a prefix such as /ai/.
// =============================================================================

const $ = (id) => document.getElementById(id);
const chatContainer = $('chatContainer');
const chatInput = $('chatInput');
const sendBtn = $('sendBtn');
const riskDashboard = $('riskDashboard');
const riskCards = $('riskCards');
const riskDetail = $('riskDetail');
const RISK_COLLAPSED_KEY = 'patchai.riskStripCollapsed';

let isProcessing = false;
const chatHistory = []; // last few turns, sent with free-text questions

// ─── HTTP helper ───────────────────────────────────────────────────────

async function api(path, { method = 'GET', body } = {}) {
    const headers = { 'Accept': 'application/json' };
    if (method !== 'GET') {
        headers['Content-Type'] = 'application/json';
        headers['X-Requested-With'] = 'patch-ai'; // required by the server (CSRF guard)
    }
    const res = await fetch(path, {
        method,
        headers,
        credentials: 'same-origin',
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    if (!res.ok) {
        const detail = data && data.detail ? data.detail : `HTTP ${res.status}`;
        throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
    return data;
}

function currentOptions() {
    return {
        target_hosts: $('targetGroup').value || null,
        security_only: $('optSecurityOnly').checked,
        dry_run: $('optDryRun').checked,
        no_reboot: $('optNoReboot').checked,
    };
}

// ─── Chat ──────────────────────────────────────────────────────────────

async function sendMessage(text) {
    const message = (text ?? chatInput.value).trim();
    if (!message || isProcessing) return;
    clearWelcome();
    appendMessage(message, 'user');
    chatInput.value = '';
    autoResizeInput();

    const opts = currentOptions();
    await runRequest(() => api('api/chat', {
        method: 'POST',
        body: {
            message,
            target_hosts: opts.target_hosts,
            options: { security_only: opts.security_only, dry_run: opts.dry_run, no_reboot: opts.no_reboot },
            history: chatHistory.slice(-10),
        },
    }), message);
}

async function quickAction(action) {
    if (isProcessing) return;
    clearWelcome();
    const labels = {
        'check-updates': 'Pending updates',
        'analyze-risk': 'Analyze risk',
        'plan-patches': 'Plan patches',
    };
    const opts = currentOptions();
    appendMessage(`${labels[action] || action}${opts.target_hosts ? ' on ' + opts.target_hosts : ''}`, 'user');
    await runRequest(() => api(`api/action/${action}`, { method: 'POST', body: opts }));
}

async function runRequest(call, userText) {
    const loadingEl = appendLoading();
    setProcessing(true);
    try {
        const data = await call();
        loadingEl.remove();
        appendMessage(data.response, 'ai');
        if (userText) {
            chatHistory.push({ role: 'user', content: userText });
            chatHistory.push({ role: 'assistant', content: (data.response || '').slice(0, 2000) });
        }
        if (data.risk_summary && data.risk_summary.length) showRiskDashboard(data.risk_summary);
        if (data.has_plan && data.plan_id) appendPlanCard(data.plan_id, data.plan_summary);
        const notes = [...(data.warnings || []), ...(data.errors || [])];
        if (notes.length) appendMessage('⚠️ ' + notes.join('\n⚠️ '), 'ai', 'message--warn');
    } catch (err) {
        loadingEl.remove();
        appendMessage(`❌ ${err.message}`, 'ai', 'message--warn');
    } finally {
        setProcessing(false);
    }
}

// ─── Plans (approval step) ─────────────────────────────────────────────

function appendPlanCard(planId, summary) {
    const card = document.createElement('div');
    card.className = 'plan-card';

    const isCapability = !!(summary && summary.kind === 'capability');
    const title = document.createElement('div');
    title.className = 'plan-title';
    title.textContent = isCapability
        ? `Plan ${planId} (${summary.capability}): waiting for approval`
        : `Patch plan ${planId}: waiting for approval`;
    card.appendChild(title);

    if (isCapability) {
        // Built with textContent only: names and values come from manifests and requests.
        const meta = document.createElement('div');
        meta.className = 'plan-meta';
        meta.textContent = `Template: ${summary.template} · Scope: ${summary.limit || 'hosts of the template'}` +
            ` · ${summary.total_hosts} hosts`;
        card.appendChild(meta);
        const list = document.createElement('ul');
        const vars = Object.entries(summary.vars || {});
        if (!vars.length) {
            const li = document.createElement('li');
            li.textContent = 'No parameters';
            list.appendChild(li);
        }
        vars.forEach(([k, v]) => {
            const li = document.createElement('li');
            li.textContent = `${k} = ${JSON.stringify(v)}`;
            list.appendChild(li);
        });
        card.appendChild(list);
        const note = document.createElement('div');
        note.className = 'plan-meta';
        note.textContent = 'Approving starts one Semaphore run of that template with these values.';
        card.appendChild(note);
    } else if (summary) {
        const flags = [];
        if (summary.security_only) flags.push('security only');
        if (summary.dry_run) flags.push('dry run');
        if (summary.no_reboot) flags.push('no reboot');
        const meta = document.createElement('div');
        meta.className = 'plan-meta';
        meta.textContent = `Scope: ${summary.limit || 'all hosts'} · ${summary.total_hosts} hosts` +
            (flags.length ? ` · ${flags.join(', ')}` : '');
        card.appendChild(meta);

        const list = document.createElement('ul');
        (summary.phases || []).forEach((p) => {
            const li = document.createElement('li');
            li.textContent = `${p.description || p.priority}: ${p.hosts.join(', ')}`;
            list.appendChild(li);
        });
        card.appendChild(list);
        const note = document.createElement('div');
        note.className = 'plan-meta';
        note.textContent = 'Approving starts one Semaphore run for all hosts listed. ' +
            'Hosts with patch_reboot_blocked in the inventory are never rebooted.';
        card.appendChild(note);
    }

    const actions = document.createElement('div');
    actions.className = 'plan-actions';
    const approve = document.createElement('button');
    approve.className = 'btn btn--danger';
    approve.type = 'button';
    approve.textContent = summary && summary.dry_run ? 'Approve dry run' : 'Approve and run';
    const reject = document.createElement('button');
    reject.className = 'btn';
    reject.type = 'button';
    reject.textContent = 'Reject';
    const status = document.createElement('div');
    status.className = 'plan-status';

    approve.addEventListener('click', async () => {
        const verb = isCapability ? summary.capability : (summary && summary.dry_run ? 'dry-run' : 'PATCH');
        if (!window.confirm(`Run plan ${planId} (${verb}) on ${summary ? (summary.limit || 'all hosts') : 'the selected hosts'}?`)) return;
        approve.disabled = reject.disabled = true;
        status.textContent = 'Starting…';
        try {
            const plan = await api(`api/plans/${encodeURIComponent(planId)}/approve`, { method: 'POST', body: {} });
            status.textContent = `Started Semaphore task #${plan.semaphore_task_id}`;
            if (plan.semaphore_task_id) pollTask(plan.semaphore_task_id, status);
        } catch (err) {
            status.textContent = `❌ ${err.message}`;
        }
    });
    reject.addEventListener('click', async () => {
        approve.disabled = reject.disabled = true;
        try {
            await api(`api/plans/${encodeURIComponent(planId)}/reject`, { method: 'POST', body: {} });
            status.textContent = 'Rejected.';
        } catch (err) {
            status.textContent = `❌ ${err.message}`;
        }
    });

    actions.append(approve, reject);
    card.append(actions, status);
    chatContainer.appendChild(card);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

async function pollTask(taskId, statusEl, attempt = 0) {
    try {
        const t = await api(`api/tasks/${taskId}`);
        statusEl.textContent = `Semaphore task #${taskId}: ${t.status}`;
        if (['success', 'error', 'stopped', 'rejected'].includes(t.status)) return;
    } catch (err) {
        statusEl.textContent = `Task #${taskId}: ${err.message}`;
    }
    if (attempt < 720) setTimeout(() => pollTask(taskId, statusEl, attempt + 1), 5000);
}

async function runCheck() {
    if (isProcessing) return;
    clearWelcome();
    const target = $('targetGroup').value || null;
    appendMessage(`Refresh host data${target ? ' on ' + target : ''}`, 'user');
    try {
        const r = await api('api/action/run-check', { method: 'POST', body: { target_hosts: target } });
        const el = appendMessage(`Started Check Updates (Semaphore task #${r.task_id}). Run an analysis once it finishes.`, 'ai');
        const status = document.createElement('div');
        status.className = 'plan-status';
        el.querySelector('.message-content').appendChild(status);
        pollTask(r.task_id, status);
    } catch (err) {
        appendMessage(`❌ ${err.message}`, 'ai', 'message--warn');
    }
}

async function emailReport() {
    if (isProcessing) return;
    clearWelcome();
    appendMessage('Email report now', 'user');
    const loadingEl = appendLoading();
    setProcessing(true);
    try {
        const r = await api('api/action/email-report', { method: 'POST', body: {} });
        loadingEl.remove();
        appendMessage(`Report sent to ${r.recipients} recipient${r.recipients === 1 ? '' : 's'}: ${r.subject}`, 'ai');
    } catch (err) {
        loadingEl.remove();
        appendMessage(`❌ ${err.message}`, 'ai', 'message--warn');
    } finally {
        setProcessing(false);
    }
}

// ─── Inventory → target selector ───────────────────────────────────────

async function loadInventory() {
    try {
        const inv = await api('api/inventory');
        const select = $('targetGroup');
        inv.groups.forEach((g) => {
            const opt = document.createElement('option');
            opt.value = g;
            opt.textContent = g;
            select.appendChild(opt);
        });
    } catch (_) { /* keep "All hosts" only */ }
}

// ─── DOM helpers ───────────────────────────────────────────────────────

function clearWelcome() {
    const welcome = document.querySelector('.chat-welcome');
    if (welcome) welcome.remove();
}

function appendMessage(content, role, extraClass) {
    const div = document.createElement('div');
    div.className = `message message--${role}` + (extraClass ? ` ${extraClass}` : '');
    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = role === 'user' ? '👤' : '🤖';
    const body = document.createElement('div');
    body.className = 'message-content';
    if (role === 'ai') body.innerHTML = renderMarkdown(content); // input is escaped first
    else body.textContent = content;
    if (role === 'user') div.append(body, avatar);
    else div.append(avatar, body);
    chatContainer.appendChild(div);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    return div;
}

function appendLoading() {
    const div = document.createElement('div');
    div.className = 'message message--ai';
    div.innerHTML = '<div class="message-avatar">🤖</div><div class="message-content">' +
        '<div class="message-loading"><span></span><span></span><span></span></div></div>';
    chatContainer.appendChild(div);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    return div;
}

function setProcessing(state) {
    isProcessing = state;
    sendBtn.disabled = state;
    document.querySelectorAll('.action-btn').forEach((b) => { b.disabled = state; });
}

// ─── Risk overview strip ───────────────────────────────────────────────
// One row of cards that scrolls sideways (arrows, swipe or trackpad). Its
// height does not depend on the number of hosts. Tapping a card shows its
// details below the row (tooltips don't exist on touch screens).

const RISK_ORDER = ['critical', 'high', 'medium', 'low'];

function showRiskDashboard(hosts) {
    const sorted = [...hosts].sort((a, b) => b.risk_score - a.risk_score);
    riskDashboard.classList.remove('hidden');
    riskCards.replaceChildren();
    hideRiskDetail();

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    sorted.forEach((host) => {
        const cls = riskClass(host);
        counts[cls] += 1;
        riskCards.appendChild(buildRiskCard(host, cls));
    });
    renderRiskCounts(sorted.length, counts);
    riskCards.scrollLeft = 0;
    updateRiskArrows();
}

function buildRiskCard(host, cls) {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = `risk-card risk-card--${cls}`;
    card.setAttribute('role', 'listitem');
    card.setAttribute('aria-pressed', 'false');
    const add = (parent, className, text, tag = 'div') => {
        const el = document.createElement(tag);
        el.className = className;
        el.textContent = text;
        parent.appendChild(el);
        return el;
    };
    add(card, 'host-name', host.hostname);
    const line = add(card, 'risk-line', '');
    add(line, 'risk-score', String(host.risk_score), 'span');
    add(line, `risk-label risk-label--${cls}`, cls, 'span');
    add(card, 'risk-meta', host.report_age_hours == null
        ? 'no report'
        : `${host.security_updates} sec / ${host.updates} total` + (host.kev && host.kev.length ? ' · KEV' : ''));
    card.addEventListener('click', () => toggleRiskDetail(card, host, cls));
    return card;
}

function renderRiskCounts(total, counts) {
    const box = $('riskCounts');
    box.replaceChildren();
    const add = (text, cls) => {
        const s = document.createElement('span');
        s.className = 'risk-count' + (cls ? ` risk-count--${cls}` : '');
        s.textContent = text;
        box.appendChild(s);
    };
    add(`${total} host${total === 1 ? '' : 's'}`);
    RISK_ORDER.forEach((cls) => { if (counts[cls]) add(`${counts[cls]} ${cls}`, cls); });
}

function toggleRiskDetail(card, host, cls) {
    const wasOpen = card.getAttribute('aria-pressed') === 'true';
    riskCards.querySelectorAll('.risk-card').forEach((c) => c.setAttribute('aria-pressed', 'false'));
    if (wasOpen) { hideRiskDetail(); return; }
    card.setAttribute('aria-pressed', 'true');

    riskDetail.replaceChildren();
    const name = document.createElement('strong');
    name.textContent = host.hostname;
    const parts = [
        host.os_name || host.os_group.replace('_servers', ''),
        `${cls.toUpperCase()} ${host.risk_score}`,
        host.report_age_hours == null
            ? 'no report'
            : `${host.security_updates} security / ${host.updates} total`,
    ];
    if (host.kev && host.kev.length) parts.push(`KEV: ${host.kev.join(', ')}`);
    if (host.reboot_required) parts.push('reboot pending');
    if (host.report_age_hours != null) parts.push(`report ${formatAge(host.report_age_hours)} old`);
    const factors = (host.risk_factors || []).join('; ');
    riskDetail.append(name, document.createTextNode(` · ${parts.join(' · ')}`));
    if (factors) {
        riskDetail.appendChild(document.createElement('br'));
        riskDetail.appendChild(document.createTextNode(`Factors: ${factors}`));
    }
    riskDetail.classList.remove('hidden');
}

function hideRiskDetail() {
    riskDetail.classList.add('hidden');
    riskDetail.replaceChildren();
}

function formatAge(hours) {
    if (hours < 1) return `${Math.round(hours * 60)} min`;
    if (hours < 48) return `${Math.round(hours)} h`;
    return `${Math.round(hours / 24)} days`;
}

function riskClass(host) {
    // The server sends the class; the thresholds below are only a fallback.
    if (host.risk_class) return host.risk_class.toLowerCase();
    const score = host.risk_score;
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

function scrollRisk(direction) {
    // About one screen of cards per click, keeping one card of overlap.
    const step = Math.max(riskCards.clientWidth - 160, 160);
    riskCards.scrollBy({ left: direction * step, behavior: 'smooth' });
}

function updateRiskArrows() {
    const max = riskCards.scrollWidth - riskCards.clientWidth;
    $('riskPrev').disabled = riskCards.scrollLeft <= 2;
    $('riskNext').disabled = riskCards.scrollLeft >= max - 2;
}

function setRiskCollapsed(collapsed) {
    riskDashboard.classList.toggle('risk-strip--collapsed', collapsed);
    $('riskToggle').setAttribute('aria-expanded', String(!collapsed));
    // A per-browser preference only; storage can be unavailable (private mode).
    try { localStorage.setItem(RISK_COLLAPSED_KEY, collapsed ? '1' : '0'); } catch (_) { /* ignore */ }
    if (!collapsed) updateRiskArrows();
}

function restoreRiskCollapsed() {
    let collapsed = false;
    try { collapsed = localStorage.getItem(RISK_COLLAPSED_KEY) === '1'; } catch (_) { /* ignore */ }
    riskDashboard.classList.toggle('risk-strip--collapsed', collapsed);
    $('riskToggle').setAttribute('aria-expanded', String(!collapsed));
}

// Minimal markdown renderer. Escapes HTML before adding any markup.
function renderMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    html = renderTables(html);
    html = html.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
    html = html.replace(/^\s*[-*] (.+)$/gm, '<li>$1</li>');
    html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>\n?)+/g, (m) => '<ul>' + m.replace(/\n/g, '') + '</ul>');
    html = html.replace(/\n\n/g, '</p><p>');
    html = '<p>' + html + '</p>';
    html = html.replace(/<p><\/p>/g, '')
        .replace(/<p>\s*(<h[1-3]>|<ul>|<pre>|<div class="md-table">)/g, '$1')
        .replace(/(<\/h[1-3]>|<\/ul>|<\/pre>|<\/table><\/div>)\s*<\/p>/g, '$1');
    return html;
}

// GitHub-style tables: a header row, a |---| separator, then body rows.
// Works on already-escaped text; each table becomes one line of HTML with
// blank lines around it so the paragraph pass leaves it alone.
function renderTables(text) {
    const isRow = (l) => /^\s*\|.*\|\s*$/.test(l);
    const isSep = (l) => /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/.test(l);
    const cells = (l) => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
    const lines = text.split('\n');
    const out = [];
    for (let i = 0; i < lines.length; i++) {
        if (isRow(lines[i]) && i + 1 < lines.length && isSep(lines[i + 1])) {
            const head = cells(lines[i]);
            const rows = [];
            let j = i + 2;
            while (j < lines.length && isRow(lines[j])) { rows.push(cells(lines[j])); j++; }
            const th = head.map((c) => `<th>${c}</th>`).join('');
            const body = rows.map((r) => '<tr>' + head.map((_, k) => `<td>${r[k] ?? ''}</td>`).join('') + '</tr>').join('');
            out.push('', `<div class="md-table"><table><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table></div>`, '');
            i = j - 1;
        } else {
            out.push(lines[i]);
        }
    }
    return out.join('\n');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function autoResizeInput() {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 160) + 'px';
}

// ─── Wiring ────────────────────────────────────────────────────────────

sendBtn.addEventListener('click', () => sendMessage());
chatInput.addEventListener('input', autoResizeInput);
chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});
document.querySelectorAll('.action-btn[data-action]').forEach((b) => {
    b.addEventListener('click', () => quickAction(b.dataset.action));
});
$('runCheckBtn').addEventListener('click', runCheck);
if ($('emailReportBtn')) $('emailReportBtn').addEventListener('click', emailReport);
$('riskPrev').addEventListener('click', () => scrollRisk(-1));
$('riskNext').addEventListener('click', () => scrollRisk(1));
$('riskToggle').addEventListener('click', () => {
    setRiskCollapsed(!riskDashboard.classList.contains('risk-strip--collapsed'));
});
riskCards.addEventListener('scroll', updateRiskArrows, { passive: true });
window.addEventListener('resize', updateRiskArrows);
restoreRiskCollapsed();
document.querySelectorAll('.example-btn').forEach((b) => {
    b.addEventListener('click', () => sendMessage(b.textContent));
});
loadInventory();

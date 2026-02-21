/* dashboard.js - Admin dashboard logic.
 * IMPORTANT: Read instructions/architecture before making changes.
 * No inline handlers; all via event delegation.
 * No escaping: use data-index + DOM APIs (textContent, value). */
var currentEditingId = null;

function msg(key) {
    var el = document.getElementById('dashboard-data');
    if (!el) return '';
    var val = el.getAttribute('data-msg-' + key);
    return val != null ? val : '';
}

document.addEventListener('DOMContentLoaded', function setupDashboardEvents() {
    document.addEventListener('click', function handleDashboardClick(e) {
        const target = e.target.closest('[data-action]');
        if (target) {
            const action = target.dataset.action;
            if (action === 'showConfigModal') { e.preventDefault(); showConfigModal(); return; }
            if (action === 'restartAppManager') { e.preventDefault(); restartAppManager(); return; }
            if (action === 'showAddModal') { e.preventDefault(); showAddModal(); return; }
            if (action === 'closeModal') { e.preventDefault(); closeModal(); return; }
            if (action === 'closeConfigModal') { e.preventDefault(); closeConfigModal(); return; }
            if (action === 'closeTestResultsModal') { e.preventDefault(); closeTestResultsModal(); return; }
            if (action === 'saveConfig') { e.preventDefault(); saveConfig(); return; }
            if (action === 'addAppSearchFolder') { e.preventDefault(); addAppSearchFolder(); return; }
            if (action === 'addEnvVar') { e.preventDefault(); addEnvVar(); return; }
            if (action === 'detectPort') { e.preventDefault(); detectPortFromFolder(); return; }
            if (action === 'detectServiceName') { e.preventDefault(); detectServiceName(); return; }
            if (action === 'showServiceNameHelp') { e.preventDefault(); showServiceNameHelp(); return false; }
            if (action === 'refreshDiscoveredApps') { e.stopPropagation(); refreshDiscoveredApps(); return; }
            if (action === 'refreshPortsConsole') { e.stopPropagation(); refreshPortsConsole(); return; }
            if (action === 'clearTerminal') { e.stopPropagation(); clearTerminal(); return; }
            if (action === 'refreshResourceStats') { e.stopPropagation(); refreshResourceStats(); return; }
            if (action === 'refreshTrafficStats') { e.stopPropagation(); refreshTrafficStats(); return; }
            if (action === 'refreshAdminLogins') { e.stopPropagation(); refreshAdminLogins(); return; }
            if (action === 'refreshAppManagerLogs') { e.stopPropagation(); refreshAppManagerLogs(); return; }
            if (action === 'toggleAppManagerLogPanel') { e.stopPropagation(); toggleAppManagerLogPanel(); return; }
            if (action === 'noop') { e.stopPropagation(); return; }
            if (action === 'toggleConsole' && target.dataset.console) {
                e.stopPropagation();
                toggleConsole(target.dataset.console);
                return;
            }
        }
        if (e.target.closest('.btn-remove-app-search-folder')) {
            e.preventDefault();
            var row = e.target.closest('.config-row');
            if (row) { row.remove(); }
            var container = document.getElementById('app-search-folders-container');
            if (container && container.children.length === 0) {
                var p = document.createElement('p');
                p.className = 'empty-placeholder';
                p.textContent = msg('no-folders');
                container.appendChild(p);
            }
            return;
        }
        if (e.target.closest('.btn-remove-env-var')) {
            e.preventDefault();
            var row = e.target.closest('.config-row');
            if (row) { row.remove(); }
            var container = document.getElementById('env-vars-container');
            if (container && container.children.length === 0) {
                var p = document.createElement('p');
                p.className = 'empty-placeholder';
                p.textContent = msg('no-env-vars');
                container.appendChild(p);
            }
            return;
        }
        if (e.target.id === 'config-modal') {
            closeConfigModal();
            return;
        }
        if (e.target.closest('.alert-close')) {
            e.preventDefault();
            const alert = e.target.closest('.alert-banner');
            if (alert) alert.remove();
            return;
        }
        const btn = e.target.closest('.app-dropdown-btn');
        if (btn) {
            e.preventDefault();
            var key = btn.dataset.appId || btn.dataset.appIndex;
            if (key) toggleDropdown(key);
            return;
        }
        const link = e.target.closest('.app-action-link');
        if (link) {
            e.preventDefault();
            var appId = link.dataset.appId || resolveAppId(link.dataset.appIndex);
            if (!appId) return false;
            var action = link.dataset.action;
            var idxOrId = link.dataset.appId || link.dataset.appIndex;
            if (action === 'edit') editApp(appId);
            else if (action === 'start') startApp(appId);
            else if (action === 'test') testApp(appId);
            else if (action === 'restart') restartApp(appId);
            else if (action === 'delete') deleteApp(appId);
            return false;
        }
    });
    document.addEventListener('change', function handleDashboardChange(e) {
        if (e.target.classList.contains('auto-start-checkbox')) {
            setAutoStart(e.target.dataset.appId, e.target.checked);
            return;
        }
        if (e.target.classList.contains('serve-app-checkbox')) {
            toggleServeApp(e.target.dataset.appIndex, e.target.checked);
        }
        if (e.target.id === 'include-local-checkbox') {
            handleIncludeLocalChange();
        }
        if (e.target.id === 'appmanager-log-filter-noise') {
            refreshAppManagerLogs();
        }
        if (e.target.id === 'appmanager-log-autorefresh') {
            toggleAppManagerLogAutorefresh(e.target.checked);
        }
    });
    initAppManagerLogPanel();
});

function getApps() {
    var el = document.getElementById('dashboard-data');
    if (!el || !el.dataset.apps) return [];
    try {
        return JSON.parse(el.dataset.apps);
    } catch (_) {
        return [];
    }
}

function resolveAppId(appIndex) {
    const apps = getApps();
    const idx = parseInt(appIndex, 10);
    if (isNaN(idx) || !apps[idx]) return null;
    return apps[idx].id;
}

function resolveAppIndex(appId) {
    const apps = getApps();
    for (var i = 0; i < apps.length; i++) {
        if (apps[i] && apps[i].id === appId) return i;
    }
    return -1;
}

var STATUS_LABELS = { started: 'Running', stopped: 'Stopped', starting: 'Starting', stopping: 'Stopping' };

function setAppStatus(appIndex, status) {
    var el = document.querySelector('.app-status[data-app-index="' + appIndex + '"]');
    if (!el) return;
    el.textContent = STATUS_LABELS[status] || status;
    el.className = 'app-status status-' + status;
}

function setAppStatusById(appId, status) {
    var el = document.querySelector('.app-status[data-app-id="' + appId + '"]');
    if (!el) return;
    el.textContent = STATUS_LABELS[status] || status;
    el.className = 'app-status status-' + status;
}

async function refreshAppStatusIndicators() {
    var indicators = document.querySelectorAll('.app-status[data-port]');
    if (indicators.length === 0) return;
    try {
        var response = await fetch('/blackgrid/admin/api/active-ports?_t=' + Date.now(), {
            credentials: 'include',
            cache: 'no-store'
        });
        var result = await response.json();
        var activePorts = new Set();
        if (result.success && result.ports) {
            result.ports.forEach(function (p) { activePorts.add(Number(p.port)); });
        }
        indicators.forEach(function (el) {
            var port = parseInt(el.dataset.port, 10);
            var status = activePorts.has(port) ? 'started' : 'stopped';
            if (!el.classList.contains('status-starting') && !el.classList.contains('status-stopping')) {
                el.textContent = STATUS_LABELS[status] || status;
                el.className = 'app-status status-' + status;
            }
        });
    } catch (e) {
        indicators.forEach(function (el) {
            if (!el.classList.contains('status-starting') && !el.classList.contains('status-stopping')) {
                el.textContent = STATUS_LABELS.stopped;
                el.className = 'app-status status-stopped';
            }
        });
    }
}

function showAddModal(port, serviceName, folderPath, name) {
    currentEditingId = null;
    clearModalError();
    document.getElementById('modal-title').textContent = 'Add Application';
    document.getElementById('app-form').reset();
    document.getElementById('app-id').value = '';
    var portEl = document.getElementById('app-port');
    var serviceEl = document.getElementById('app-service-name');
    var folderEl = document.getElementById('app-folder-path');
    var nameEl = document.getElementById('app-name');
    if (port != null && port !== '') portEl.value = port;
    if (serviceName) serviceEl.value = serviceName;
    if (folderPath) folderEl.value = folderPath;
    if (name) nameEl.value = name;
    portEl.removeAttribute('required');
    hideSlugUnsafeMessage();
    document.getElementById('app-modal').style.display = 'block';
}

function addAppFromPort(port, serviceName) {
    showAddModal(port, serviceName || '', '', '');
}

function addAppFromDiscovered(port, folderPath, name) {
    showAddModal(port, '', folderPath, name);
}

function editApp(appId) {
    currentEditingId = appId;
    clearModalError();
    document.getElementById('modal-title').textContent = 'Edit Application';
    
    // Preload step (resolved immediately; folder path is manual)
    Promise.resolve().then(() => {
        // Fetch app data
        fetch(`/blackgrid/admin/api/apps`)
            .then(r => r.json())
            .then(data => {
                const app = data.apps.find(a => a.id === appId);
                if (app) {
                    document.getElementById('app-id').value = app.id;
                    document.getElementById('app-name').value = app.name;
                    document.getElementById('app-slug').value = app.slug || '';
                    document.getElementById('app-port').value = app.port || '';
                    document.getElementById('app-service-name').value = app.service_name || '';
                    document.getElementById('app-folder-path').value = app.folder_path || '';
                    document.getElementById('app-port').removeAttribute('required');
                    hideSlugUnsafeMessage();
                    document.getElementById('app-modal').style.display = 'block';
                }
            });
    });
}

function closeModal() {
    document.getElementById('app-modal').style.display = 'none';
    currentEditingId = null;
    clearModalError();
    hideSlugUnsafeMessage();
}

function isSlugUrlSafe(value) {
    var v = (value || '').trim();
    if (v === '') return true;
    if (v !== v.toLowerCase()) return false;
    return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(v);
}

function showSlugUnsafeMessage() {
    var el = document.getElementById('app-slug-unsafe-msg');
    if (el) el.style.display = 'block';
    var input = document.getElementById('app-slug');
    if (input) input.setAttribute('aria-invalid', 'true');
}

function hideSlugUnsafeMessage() {
    var el = document.getElementById('app-slug-unsafe-msg');
    if (el) el.style.display = 'none';
    var input = document.getElementById('app-slug');
    if (input) input.removeAttribute('aria-invalid');
}

function updateSlugUnsafeMessage() {
    var value = (document.getElementById('app-slug') || {}).value || '';
    if (isSlugUrlSafe(value)) hideSlugUnsafeMessage(); else showSlugUnsafeMessage();
}

function showModalError(message) {
    const el = document.getElementById('app-modal-error');
    if (el) {
        el.textContent = message;
        el.style.display = 'block';
    }
}

function clearModalError() {
    const el = document.getElementById('app-modal-error');
    if (el) {
        el.textContent = '';
        el.style.display = 'none';
    }
}

// Config Modal Functions
async function showConfigModal() {
    const modal = document.getElementById('config-modal');
    modal.style.display = 'block';
    
    // Load admin config
    try {
        const adminResp = await fetch('/blackgrid/admin/api/config/admin');
        const adminResult = await adminResp.json();
        if (adminResult.success && adminResult.config) {
            renderAppSearchFolders(adminResult.config.app_search_folders || []);
        } else {
            renderAppSearchFolders([]);
        }
    } catch (error) {
        console.error('Error loading admin config:', error);
        renderAppSearchFolders([]);
    }

    // Load current timeout
    try {
        const response = await fetch('/blackgrid/admin/api/config/shutdown-timeout');
        const result = await response.json();
        if (result.success) {
            document.getElementById('shutdown-timeout').value = result.timeout_minutes;
        }
    } catch (error) {
        console.error('Error loading shutdown timeout:', error);
    }
    
    // Load environment variables
    try {
        const response = await fetch('/blackgrid/admin/api/config/env-vars');
        const result = await response.json();
        if (result.success) {
            renderEnvVars(result.env_vars || {});
        }
    } catch (error) {
        console.error('Error loading env vars:', error);
        renderEnvVars({});
    }
}

function closeConfigModal() {
    document.getElementById('config-modal').style.display = 'none';
}

function renderAppSearchFolders(folders) {
    var container = document.getElementById('app-search-folders-container');
    container.innerHTML = '';
    if (!folders || folders.length === 0) {
        var p = document.createElement('p');
        p.className = 'empty-placeholder';
        p.textContent = msg('no-folders');
        container.appendChild(p);
        return;
    }
    folders.forEach(function(folder) {
        var div = document.createElement('div');
        div.className = 'config-row';
        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'app-search-folder-path';
        input.placeholder = 'e.g. /opt or C:\\Projects';
        input.value = folder;
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-secondary btn-remove-app-search-folder';
        btn.textContent = 'Remove';
        btn.style.padding = '8px 12px';
        div.appendChild(input);
        div.appendChild(btn);
        container.appendChild(div);
    });
}

function addAppSearchFolder() {
    var container = document.getElementById('app-search-folders-container');
    var placeholder = container.querySelector('p.empty-placeholder');
    if (placeholder) placeholder.remove();
    var div = document.createElement('div');
    div.className = 'config-row';
    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'app-search-folder-path';
    input.placeholder = 'e.g. /opt or C:\\Projects';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary btn-remove-app-search-folder';
    btn.textContent = 'Remove';
    div.appendChild(input);
    div.appendChild(btn);
    container.appendChild(div);
}

function renderEnvVars(envVars) {
    const container = document.getElementById('env-vars-container');
    container.innerHTML = '';
    
    const entries = Object.entries(envVars);
    if (entries.length === 0) {
        var p = document.createElement('p');
        p.className = 'empty-placeholder';
        p.textContent = msg('no-env-vars');
        container.appendChild(p);
        return;
    }
    
    entries.forEach(function(entry) {
        var key = entry[0], value = entry[1];
        var div = document.createElement('div');
        div.className = 'config-row';
        var keyInput = document.createElement('input');
        keyInput.type = 'text';
        keyInput.className = 'env-var-key';
        keyInput.placeholder = 'Variable name';
        keyInput.value = key;
        var valInput = document.createElement('input');
        valInput.type = 'text';
        valInput.className = 'env-var-value';
        valInput.placeholder = 'Variable value';
        valInput.value = value;
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-secondary btn-remove-env-var';
        btn.textContent = 'Remove';
        div.appendChild(keyInput);
        div.appendChild(valInput);
        div.appendChild(btn);
        container.appendChild(div);
    });
}

function addEnvVar() {
    var container = document.getElementById('env-vars-container');
    var div = document.createElement('div');
    div.className = 'config-row';
    var keyInput = document.createElement('input');
    keyInput.type = 'text';
    keyInput.className = 'env-var-key';
    keyInput.placeholder = 'Variable name';
    var valInput = document.createElement('input');
    valInput.type = 'text';
    valInput.className = 'env-var-value';
    valInput.placeholder = 'Variable value';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary btn-remove-env-var';
    btn.textContent = 'Remove';
    div.appendChild(keyInput);
    div.appendChild(valInput);
    div.appendChild(btn);
    container.appendChild(div);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function saveConfig() {
    try {
        // Collect app search folders
        const folderInputs = document.querySelectorAll('.app-search-folder-path');
        const appSearchFolders = [];
        folderInputs.forEach(input => {
            const v = (input.value || '').trim();
            if (v) appSearchFolders.push(v);
        });
        
        // Save admin config
        const adminResp = await fetch('/blackgrid/admin/api/config/admin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                app_search_folders: appSearchFolders
            })
        });
        const adminResult = await adminResp.json();
        if (!adminResult.success) {
            alert('Error saving admin config: ' + (adminResult.error || 'Unknown error'));
            return;
        }

        // Save shutdown timeout
        const timeout = parseInt(document.getElementById('shutdown-timeout').value);
        if (isNaN(timeout) || timeout < 1 || timeout > 1440) {
            alert('Shutdown timeout must be between 1 and 1440 minutes');
            return;
        }
        
        const timeoutResponse = await fetch('/blackgrid/admin/api/config/shutdown-timeout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ timeout_minutes: timeout })
        });
        
        const timeoutResult = await timeoutResponse.json();
        if (!timeoutResult.success) {
            alert('Error saving shutdown timeout: ' + (timeoutResult.error || 'Unknown error'));
            return;
        }
        
        // Save environment variables
        const container = document.getElementById('env-vars-container');
        const envVars = {};
        var rows = container.querySelectorAll('.config-row');
        
        rows.forEach(row => {
            const keyInput = row.querySelector('.env-var-key');
            const valueInput = row.querySelector('.env-var-value');
            if (keyInput && keyInput.value.trim()) {
                envVars[keyInput.value.trim()] = valueInput ? valueInput.value : '';
            }
        });
        
        const envResponse = await fetch('/blackgrid/admin/api/config/env-vars', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ env_vars: envVars })
        });
        
        const envResult = await envResponse.json();
        if (!envResult.success) {
            alert('Error saving environment variables: ' + (envResult.error || 'Unknown error'));
            return;
        }
        
        alert('✓ Configuration saved successfully!');
        closeConfigModal();
    } catch (error) {
        alert('Error saving configuration: ' + error.message);
    }
}

function toggleDropdown(appKey) {
    const dropdown = document.getElementById(`dropdown-${appKey}`);
    if (!dropdown) return;
    const appRow = dropdown.closest('.app-row') || dropdown.closest('tr');
    const trigger = dropdown.previousElementSibling; // the ⋯ button
    document.querySelectorAll('.dropdown-menu').forEach(menu => {
        if (menu.id !== `dropdown-${appKey}`) {
            menu.style.display = 'none';
            menu.style.position = '';
            menu.style.top = '';
            menu.style.left = '';
            menu.style.right = '';
            menu.style.minWidth = '';
            var row = menu.closest('.app-row');
            if (row) row.classList.remove('dropdown-open');
        }
    });
    if (dropdown.style.display === 'block') {
        dropdown.style.display = 'none';
        dropdown.style.position = '';
        dropdown.style.top = '';
        dropdown.style.left = '';
        dropdown.style.right = '';
        dropdown.style.minWidth = '';
        if (appRow) appRow.classList.remove('dropdown-open');
    } else {
        dropdown.style.display = 'block';
        if (appRow) appRow.classList.add('dropdown-open');
        // Position fixed so menu is not clipped by overflow; compute placement to stay on screen
        if (trigger) {
            requestAnimationFrame(function () {
                var rect = trigger.getBoundingClientRect();
                var menuH = dropdown.offsetHeight;
                var menuW = dropdown.offsetWidth;
                var viewH = window.innerHeight;
                var viewW = window.innerWidth;
                var pad = 8;
                var above = rect.bottom + menuH + pad > viewH && rect.top > menuH + pad;
                dropdown.style.position = 'fixed';
                dropdown.style.minWidth = dropdown.offsetWidth + 'px';
                if (above) {
                    dropdown.style.top = Math.max(pad, rect.top - menuH - pad) + 'px';
                    dropdown.style.bottom = '';
                } else {
                    dropdown.style.top = Math.min(viewH - menuH - pad, rect.bottom + pad) + 'px';
                    dropdown.style.bottom = '';
                }
                var left = rect.right - menuW;
                if (left < pad) left = pad;
                if (left + menuW > viewW - pad) left = viewW - menuW - pad;
                dropdown.style.left = left + 'px';
                dropdown.style.right = 'auto';
            });
        }
    }
}

// Close dropdowns when clicking outside
document.addEventListener('click', (e) => {
    if (!e.target.closest('.dropdown')) {
        document.querySelectorAll('.dropdown-menu').forEach(menu => {
            menu.style.display = 'none';
            var row = menu.closest('.app-row');
            if (row) row.classList.remove('dropdown-open');
        });
    }
});

// Alert banner management
function showAlert(message, type) {
    if (type === undefined || type === null) type = 'warning';
    // Remove existing alerts
    const existingAlerts = document.querySelectorAll('.alert-banner');
    existingAlerts.forEach(alert => alert.remove());
    
    // Determine icon based on type
    let icon = '⚠️';
    if (type === 'success') {
        icon = '✓';
    } else if (type === 'error') {
        icon = '⚠️';
    }
    
    var alert = document.createElement('div');
    alert.className = 'alert-banner ' + type;
    var iconSpan = document.createElement('span');
    iconSpan.className = 'alert-icon';
    iconSpan.textContent = icon;
    var msgSpan = document.createElement('span');
    msgSpan.className = 'alert-message';
    msgSpan.textContent = message;
    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'alert-close';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.textContent = String.fromCharCode(215);
    alert.appendChild(iconSpan);
    alert.appendChild(msgSpan);
    alert.appendChild(closeBtn);
    
    // Insert at top of apps-list
    const appsList = document.querySelector('.apps-list');
    appsList.insertBefore(alert, appsList.firstChild);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, 10000);
}

// Ports Console
async function refreshPortsConsole() {
    var content = document.getElementById('ports-console-content');
    content.textContent = '';
    var loadingP = document.createElement('p');
    loadingP.className = 'console-loading';
    loadingP.textContent = msg('loading-ports');
    content.appendChild(loadingP);
    
    try {
        var response = await fetch('/blackgrid/admin/api/active-ports');
        const result = await response.json();
        
        if (result.success && result.ports && result.ports.length > 0) {
            window.__lastPortsData = result.ports;
            let html = '<table><thead><tr><th>Port</th><th>Service Name</th><th>PID</th><th>Action</th></tr></thead><tbody>';
            result.ports.forEach((item, idx) => {
                html += `<tr>
                    <td class="port-number">${item.port}</td>
                    <td class="${item.service_name ? 'service-name' : 'no-service'}">${escapeHtml(item.service_name || '(no service)')}</td>
                    <td class="pid-info">${item.pid || 'N/A'}</td>
                    <td><button class="btn-add-port" data-index="${idx}" title="Add as configured application">+</button></td>
                </tr>`;
            });
            html += '</tbody></table>';
            content.innerHTML = html;
            content.querySelectorAll('.btn-add-port').forEach(btn => {
                btn.addEventListener('click', function() {
                    const idx = parseInt(this.dataset.index, 10);
                    const item = window.__lastPortsData && window.__lastPortsData[idx];
                    if (item) addAppFromPort(item.port, item.service_name || '');
                });
            });
        } else {
            content.textContent = '';
            var emptyP = document.createElement('p');
            emptyP.className = 'console-empty';
            emptyP.textContent = msg('no-ports');
            content.appendChild(emptyP);
        }
    } catch (error) {
        content.textContent = '';
        var errP = document.createElement('p');
        errP.className = 'console-error';
        errP.textContent = msg('error-prefix') + ': ' + (error && error.message ? error.message : 'Unknown error');
        content.appendChild(errP);
    }
}

// Discovered Apps (from configured search folders)
async function refreshDiscoveredApps() {
    var content = document.getElementById('discovered-apps-content');
    content.textContent = '';
    var loadingP = document.createElement('p');
    loadingP.className = 'console-loading';
    loadingP.textContent = msg('loading-discovered');
    content.appendChild(loadingP);

    try {
        var response = await fetch('/blackgrid/admin/api/config/discovered-apps?_t=' + Date.now(), {
            credentials: 'include',
            cache: 'no-store'
        });
        const result = await response.json();

        if (result.success && result.apps && result.apps.length > 0) {
            window.__lastDiscoveredApps = result.apps;
            var skipTableReplace = window.__autoStartInProgress === true;
            if (!skipTableReplace) {
            var autoCol = msg('auto-column') || 'Auto';
            var slugCol = msg('slug-column') || 'Slug';
            var html = '<table><thead><tr><th>' + escapeHtml(autoCol) + '</th><th>AppName</th><th>' + escapeHtml(slugCol) + '</th><th>Port</th><th>Folder</th><th>Action</th></tr></thead><tbody>';
            var apps = getApps();
            result.apps.forEach(function (item, idx) {
                var isRegistered = item.already_registered;
                var appId = item.app_id || '';
                var displayName = item.name;
                if (isRegistered && appId) {
                    var configured = apps.find(function (a) { return a && a.id === appId; });
                    if (configured && configured.name) displayName = configured.name;
                }
                var actionCell;
                var autoCell;
                if (isRegistered && appId) {
                    var checked = item.auto_start ? ' checked' : '';
                    autoCell = '<td class="auto-start-cell"><input type="checkbox" class="auto-start-checkbox" data-app-id="' + escapeHtml(appId) + '"' + checked + ' title="Auto-start when stopped"></td>';
                    var menuEdit = msg('menu-edit') || 'Edit';
                    var menuStart = msg('menu-start') || 'Start';
                    var menuTest = msg('menu-test') || 'Test';
                    var menuRestart = msg('menu-restart') || 'Restart';
                    var menuLogs = msg('menu-see-logs') || 'See Logs';
                    var menuDelete = msg('menu-delete') || 'Delete';
                    var logsUrl = '/blackgrid/admin/apps/' + appId + '/logs';
                    actionCell = '<td class="discovered-action-cell"><span class="app-status" data-app-id="' + escapeHtml(appId) + '" data-port="' + item.port + '">—</span><div class="dropdown"><button class="btn-icon app-dropdown-btn" data-app-id="' + escapeHtml(appId) + '">⋯</button><div id="dropdown-' + escapeHtml(appId) + '" class="dropdown-menu">' +
                        '<a href="#" class="app-action-link" data-action="edit" data-app-id="' + escapeHtml(appId) + '">' + menuEdit + '</a>' +
                        '<a href="#" class="app-action-link" data-action="start" data-app-id="' + escapeHtml(appId) + '">' + menuStart + '</a>' +
                        '<a href="#" class="app-action-link" data-action="test" data-app-id="' + escapeHtml(appId) + '">' + menuTest + '</a>' +
                        '<a href="#" class="app-action-link" data-action="restart" data-app-id="' + escapeHtml(appId) + '">' + menuRestart + '</a>' +
                        '<a href="' + logsUrl + '" target="_blank">' + menuLogs + '</a>' +
                        '<a href="#" class="app-action-link danger" data-action="delete" data-app-id="' + escapeHtml(appId) + '">' + menuDelete + '</a>' +
                        '</div></div></td>';
                } else {
                    autoCell = '<td></td>';
                    actionCell = '<td><button class="btn-icon btn-add-discovered" data-index="' + idx + '" title="Add as configured application">+</button></td>';
                }
                var appUrl = 'http://' + (window.location.hostname || 'localhost') + ':' + item.port;
                var slugDisplay = (item.slug != null && item.slug !== '') ? escapeHtml(item.slug) : '—';
                html += '<tr>' + autoCell + '<td class="port-number"><a href="' + escapeHtml(appUrl) + '" target="_blank" rel="noopener">' + escapeHtml(displayName) + '</a></td><td class="app-slug-cell">' + slugDisplay + '</td><td>' + item.port + '</td><td style="font-size: 0.85em; color: #808080;">' + escapeHtml(item.folder_path) + '</td>' + actionCell + '</tr>';
            });
            html += '</tbody></table>';
            content.innerHTML = html;
            content.querySelectorAll('.btn-add-discovered').forEach(function (btn) {
                btn.addEventListener('click', function() {
                    var idx = parseInt(this.dataset.index, 10);
                    var item = window.__lastDiscoveredApps && window.__lastDiscoveredApps[idx];
                    if (item) addAppFromDiscovered(item.port, item.folder_path, item.name);
                });
            });
            }
            refreshAppStatusIndicators();
        } else {
            content.textContent = '';
            var emptyP = document.createElement('p');
            emptyP.className = 'console-empty';
            var hint = msg('no-discovered');
            var searchFolders = result.search_folders || [];
            var missing = searchFolders.filter(function(s) { return !s.exists; });
            if (missing.length > 0) {
                hint += ' Path(s) not found: ' + missing.map(function(s) { return s.path; }).join(', ') + '. Check Config > App Search Folders.';
            }
            emptyP.textContent = hint;
            content.appendChild(emptyP);
        }
    } catch (error) {
        content.textContent = '';
        var errP = document.createElement('p');
        errP.className = 'console-error';
        errP.textContent = msg('error-prefix') + ': ' + (error && error.message ? error.message : 'Unknown error');
        content.appendChild(errP);
    }
}

// Toggle console collapse/expand
function toggleConsole(type) {
    let header, content;
    
    if (type === 'discovered') {
        header = document.querySelector('#discovered-apps-console .console-header');
        content = document.getElementById('discovered-apps-content');
        const wasCollapsed = header && header.classList.contains('collapsed');
        if (wasCollapsed) {
            setTimeout(() => {
                if (header && !header.classList.contains('collapsed')) {
                    refreshDiscoveredApps();
                }
            }, 100);
        }
    } else if (type === 'ports') {
        header = document.querySelector('#ports-console .console-header');
        content = document.getElementById('ports-console-content');
    } else if (type === 'terminal') {
        header = document.querySelector('.terminal-console .console-header');
        content = document.getElementById('terminal-content');
    } else if (type === 'resources') {
        header = document.querySelector('.resource-manager .console-header');
        content = document.getElementById('resources-content');
        // Initialize resource manager on first expand (with small delay to avoid blocking)
        const wasCollapsed = header && header.classList.contains('collapsed');
        if (wasCollapsed) {
            // Small delay to avoid blocking UI, and only load if not already loaded
            setTimeout(() => {
                // Only load if section is now expanded and charts don't exist yet
                if (header && !header.classList.contains('collapsed') && !memoryChart) {
                    refreshResourceStats();
                }
            }, 100);
        }
    } else if (type === 'traffic') {
        // Find the traffic section header (the one that contains "Traffic Analytics")
        const allManagers = document.querySelectorAll('.resource-manager');
        header = null;
        for (let mgr of allManagers) {
            const h = mgr.querySelector('.console-header');
            if (h && h.textContent.includes('Traffic Analytics')) {
                header = h;
                break;
            }
        }
        content = document.getElementById('traffic-content');
        // Initialize traffic manager on first expand
        if (header && header.classList.contains('collapsed')) {
            setTimeout(() => {
                if (!header.classList.contains('collapsed') && !dailyVisitsChart) {
                    refreshTrafficStats();
                }
            }, 100);
        }
    } else if (type === 'admin-logins') {
        // Find the admin logins section header (the one that contains "Admin Login History")
        const allManagers = document.querySelectorAll('.resource-manager');
        header = null;
        for (let mgr of allManagers) {
            const h = mgr.querySelector('.console-header');
            if (h && h.textContent.includes('Admin Login History')) {
                header = h;
                break;
            }
        }
        content = document.getElementById('admin-logins-content');
        // Initialize admin logins on first expand
        if (header && header.classList.contains('collapsed')) {
            setTimeout(() => {
                if (!header.classList.contains('collapsed')) {
                    refreshAdminLogins();
                }
            }, 100);
        }
    }
    
    if (header && content) {
        const isCollapsed = header.classList.contains('collapsed');
        
        if (isCollapsed) {
            header.classList.remove('collapsed');
            content.classList.remove('collapsed');
        } else {
            header.classList.add('collapsed');
            content.classList.add('collapsed');
        }
    }
}

// Load consoles on page load
document.addEventListener('DOMContentLoaded', function() {
    refreshDiscoveredApps();
    refreshPortsConsole();
    refreshAppStatusIndicators();
    initializeTerminal();

    // Periodically refresh app status (Running/Stopped) so the page stays in sync when
    // apps are started by the auto-start monitor or from another tab.
    var statusRefreshInterval = setInterval(function() {
        if (document.visibilityState === 'visible') {
            refreshAppStatusIndicators();
        }
    }, 12000);
});

// Terminal functionality
let terminalHistory = [];
let terminalHistoryIndex = -1;
let currentCommand = '';
let currentWorkingDirectory = '~';
let autocompleteMatches = [];
let autocompleteIndex = -1;
let lastAutocompleteQuery = '';

function updateTerminalPrompt() {
    const promptDisplay = document.getElementById('terminal-prompt-display');
    if (promptDisplay) {
        const displayDir = currentWorkingDirectory === '~' ? '~' : currentWorkingDirectory;
        promptDisplay.textContent = displayDir + '$';
    }
}

function initializeTerminal() {
    const terminalInput = document.getElementById('terminal-input');
    const terminalOutput = document.getElementById('terminal-output');
    
    if (!terminalInput || !terminalOutput) return;
    
    // Update prompt display
    updateTerminalPrompt();
    
    // Welcome message
    addTerminalLine('output', 'Welcome to AppManager Server Terminal');
    addTerminalLine('output', 'Type commands to execute on the server. Use "help" for available commands.');
    addTerminalLine('output', 'Press TAB for file/folder autocomplete.');
    addTerminalLine('output', '');
    
    // Focus input
    terminalInput.focus();
    
    // Handle Enter key
    terminalInput.addEventListener('keydown', async (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const command = terminalInput.value.trim();
            if (command) {
                executeCommand(command);
                terminalInput.value = '';
                terminalHistoryIndex = -1;
                autocompleteMatches = [];
                autocompleteIndex = -1;
            }
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (terminalHistory.length > 0) {
                if (terminalHistoryIndex === -1) {
                    currentCommand = terminalInput.value;
                    terminalHistoryIndex = terminalHistory.length;
                }
                terminalHistoryIndex = Math.max(0, terminalHistoryIndex - 1);
                terminalInput.value = terminalHistory[terminalHistoryIndex];
                autocompleteMatches = [];
                autocompleteIndex = -1;
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (terminalHistoryIndex >= 0) {
                terminalHistoryIndex = Math.min(terminalHistory.length - 1, terminalHistoryIndex + 1);
                if (terminalHistoryIndex === terminalHistory.length - 1) {
                    terminalInput.value = currentCommand;
                    terminalHistoryIndex = -1;
                } else {
                    terminalInput.value = terminalHistory[terminalHistoryIndex];
                }
                autocompleteMatches = [];
                autocompleteIndex = -1;
            }
        } else if (e.key === 'Tab') {
            e.preventDefault();
            await handleTabCompletion(terminalInput);
        }
    });
    
    // Keep focus on input when clicking terminal
    terminalOutput.addEventListener('click', () => {
        terminalInput.focus();
    });
}

async function handleTabCompletion(input) {
    const value = input.value;
    const cursorPos = input.selectionStart;
    
    // Extract the word at cursor position (could be a path)
    const textBeforeCursor = value.substring(0, cursorPos);
    const textAfterCursor = value.substring(cursorPos);
    
    // Find the start of the current word/path
    // Look for spaces or start of line
    let wordStart = textBeforeCursor.length;
    for (let i = textBeforeCursor.length - 1; i >= 0; i--) {
        if (textBeforeCursor[i] === ' ' || textBeforeCursor[i] === '\t') {
            wordStart = i + 1;
            break;
        }
        if (i === 0) {
            wordStart = 0;
        }
    }
    
    const partialPath = textBeforeCursor.substring(wordStart);
    
    // If no partial path, don't autocomplete
    if (!partialPath) {
        return;
    }
    
    // Get autocomplete suggestions
    try {
        const response = await fetch('/blackgrid/admin/api/terminal/autocomplete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                path: partialPath,
                cwd: currentWorkingDirectory
            })
        });
        
        const result = await response.json();
        
        if (result.matches && result.matches.length > 0) {
            // Check if this is the same query (for cycling through matches)
            if (partialPath === lastAutocompleteQuery && autocompleteMatches.length > 0) {
                // Cycle to next match
                autocompleteIndex = (autocompleteIndex + 1) % autocompleteMatches.length;
            } else {
                // New query, reset
                autocompleteMatches = result.matches;
                autocompleteIndex = 0;
                lastAutocompleteQuery = partialPath;
            }
            
            const match = autocompleteMatches[autocompleteIndex];
            const dirPart = partialPath.includes('/') ? partialPath.substring(0, partialPath.lastIndexOf('/') + 1) : '';
            const completedPath = dirPart + match.name;
            
            // If it's a directory, add trailing slash
            const finalPath = match.is_directory ? completedPath + '/' : completedPath;
            
            // Replace the partial path with completed path
            const newValue = textBeforeCursor.substring(0, wordStart) + finalPath + textAfterCursor;
            input.value = newValue;
            
            // Set cursor position after completed path
            const newCursorPos = wordStart + finalPath.length;
            input.setSelectionRange(newCursorPos, newCursorPos);
            
            // If multiple matches, show hint
            if (autocompleteMatches.length > 1) {
                // Show matches in terminal (temporary, will be cleared on next command)
                const matchList = autocompleteMatches.map((m, i) => {
                    const marker = i === autocompleteIndex ? '>' : ' ';
                    const type = m.is_directory ? '/' : '';
                    return `${marker} ${m.name}${type}`;
                }).join('  ');
                
                // Add hint line (will be cleared when user types)
                const hintLine = document.createElement('div');
                hintLine.className = 'terminal-line output';
                hintLine.style.color = '#808080';
                hintLine.style.fontSize = '0.85em';
                hintLine.textContent = `Matches (${autocompleteIndex + 1}/${autocompleteMatches.length}): ${matchList}`;
                hintLine.id = 'autocomplete-hint';
                
                // Remove previous hint if exists
                const prevHint = document.getElementById('autocomplete-hint');
                if (prevHint) {
                    prevHint.remove();
                }
                
                const terminalOutput = document.getElementById('terminal-output');
                terminalOutput.appendChild(hintLine);
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
            }
        }
    } catch (error) {
        // Silently fail on autocomplete errors
        console.error('Autocomplete error:', error);
    }
}

function addTerminalLine(type, text) {
    const terminalOutput = document.getElementById('terminal-output');
    if (!terminalOutput) return;
    
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = text;
    terminalOutput.appendChild(line);
    
    // Auto-scroll to bottom
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function clearTerminal() {
    const terminalOutput = document.getElementById('terminal-output');
    if (terminalOutput) {
        terminalOutput.innerHTML = '';
        addTerminalLine('output', 'Terminal cleared.');
        addTerminalLine('output', '');
    }
}

async function executeCommand(command) {
    const terminalOutput = document.getElementById('terminal-output');
    const terminalInput = document.getElementById('terminal-input');
    
    if (!terminalOutput || !terminalInput) return;
    
    // Remove autocomplete hint if exists
    const hint = document.getElementById('autocomplete-hint');
    if (hint) {
        hint.remove();
    }
    
    // Reset autocomplete state
    autocompleteMatches = [];
    autocompleteIndex = -1;
    lastAutocompleteQuery = '';
    
    // Add command to history
    if (command && (terminalHistory.length === 0 || terminalHistory[terminalHistory.length - 1] !== command)) {
        terminalHistory.push(command);
        if (terminalHistory.length > 100) {
            terminalHistory.shift(); // Keep last 100 commands
        }
    }
    
    // Display command with current directory
    const promptDir = currentWorkingDirectory === '~' ? '~' : currentWorkingDirectory;
    addTerminalLine('command', `${promptDir}$ ${command}`);
    
    // Handle special commands
    if (command === 'clear' || command === 'cls') {
        clearTerminal();
        return;
    }
    
    // Note: cd command handling is now done server-side and returned in response
    
    if (command === 'help') {
        addTerminalLine('output', 'Available commands:');
        addTerminalLine('output', '  ls, cd, pwd, cat, head, tail, grep, find');
        addTerminalLine('output', '  ps, df, du, free, uptime, whoami, uname');
        addTerminalLine('output', '  systemctl, journalctl, netstat, ss');
        addTerminalLine('output', '  git, python3, pip, npm, docker');
        addTerminalLine('output', '  nginx, certbot, ufw, iptables');
        addTerminalLine('output', '');
        addTerminalLine('output', 'Shell Scripts:');
        addTerminalLine('output', '  bash script.sh - Run a shell script');
        addTerminalLine('output', '  sh script.sh - Run a shell script');
        addTerminalLine('output', '  ./script.sh - Run an executable script');
        addTerminalLine('output', '  Scripts must be in: ~, /BlackGrid/appmanager, or /tmp');
        addTerminalLine('output', '');
        addTerminalLine('output', 'Terminal Commands:');
        addTerminalLine('output', '  clear - Clear terminal');
        addTerminalLine('output', '  help - Show this help message');
        addTerminalLine('output', '');
        return;
    }
    
    // Show loading indicator
    const loadingLine = document.createElement('div');
    loadingLine.className = 'terminal-line loading';
    loadingLine.textContent = 'Executing...';
    terminalOutput.appendChild(loadingLine);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
    
    // Disable input during execution
    terminalInput.disabled = true;
    
    try {
        const response = await fetch('/blackgrid/admin/api/terminal/execute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                command: command,
                cwd: currentWorkingDirectory
            })
        });
        
        // Remove loading indicator
        loadingLine.remove();
        
        const result = await response.json();
        
        if (result.success) {
            // Update working directory if returned
            if (result.cwd) {
                currentWorkingDirectory = result.cwd;
                updateTerminalPrompt();
            }
            
            // Display output
            if (result.output) {
                const lines = result.output.split('\n');
                lines.forEach(line => {
                    addTerminalLine('output', line);
                });
            } else {
                // For cd command, don't show "(no output)" - it's normal
                if (!command.startsWith('cd ')) {
                    addTerminalLine('output', '(no output)');
                }
            }
            
            // Show exit code if non-zero
            if (result.exit_code !== 0) {
                addTerminalLine('error', `[Exit code: ${result.exit_code}]`);
            }
        } else {
            // Even on error, update cwd if provided (to maintain state)
            if (result.cwd) {
                currentWorkingDirectory = result.cwd;
                updateTerminalPrompt();
            }
            addTerminalLine('error', `Error: ${result.error || 'Unknown error'}`);
            if (result.hint) {
                addTerminalLine('output', result.hint);
            }
        }
    } catch (error) {
        loadingLine.remove();
        addTerminalLine('error', `Network error: ${error.message}`);
    } finally {
        terminalInput.disabled = false;
        terminalInput.focus();
        addTerminalLine('output', ''); // Empty line after command
    }
}

document.getElementById('app-slug').addEventListener('input', updateSlugUnsafeMessage);
document.getElementById('app-slug').addEventListener('change', updateSlugUnsafeMessage);

document.getElementById('app-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    clearModalError();
    var slugVal = (document.getElementById('app-slug') || {}).value || '';
    if ((slugVal = slugVal.trim()) && !isSlugUrlSafe(slugVal)) {
        showSlugUnsafeMessage();
        document.getElementById('app-slug').focus();
        return;
    }
    var formData = new FormData(e.target);
    var appId = document.getElementById('app-id').value;
    var portInput = document.getElementById('app-port');
    var portVal = (portInput && portInput.value !== undefined) ? String(portInput.value).trim() : (formData.get('port') || '').toString().trim();
    var portNum = portVal ? parseInt(portVal, 10) : null;
    if (!portVal) formData.delete('port');
    try {
        var response;
        if (appId) {
            var putBody = {
                name: formData.get('name'),
                service_name: (formData.get('service_name') || '').trim() || null,
                folder_path: (formData.get('folder_path') || '').trim() || null,
                slug: (formData.get('slug') || '').trim()
            };
            if (portVal !== '') putBody.port = isNaN(portNum) ? portVal : portNum;
            response = await fetch('/blackgrid/admin/api/apps/' + appId, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(putBody)
            });
        } else {
            response = await fetch('/blackgrid/admin/api/apps', {
                method: 'POST',
                body: formData
            });
        }
        
        let result;
        try {
            const text = await response.text();
            result = text ? JSON.parse(text) : {};
        } catch (e) {
            const statusHint = !response.ok ? ` (HTTP ${response.status})` : '';
            showModalError('Server returned an invalid response' + statusHint + '. The server may have encountered an error — check the terminal where AppManager is running for details.');
            return;
        }
        
        if (result.success) {
            closeModal();
            refreshPortsConsole();
            refreshDiscoveredApps();
        } else {
            const errorMsg = result.error || 'Unknown error';
            showModalError(errorMsg);
            
            // If it's a port listening error, highlight the port field
            if (result.is_listening === false) {
                document.getElementById('app-port').style.borderColor = '#dc3545';
                document.getElementById('app-port').focus();
            }
        }
    } catch (error) {
        showModalError('Error: ' + error.message);
    }
});

function closeTestResultsModal() {
    document.getElementById('test-results-modal').style.display = 'none';
}

async function testApp(appId) {
    try {
        // Show loading state
        const modal = document.getElementById('test-results-modal');
        const content = document.getElementById('test-results-content');
        content.innerHTML = '<p style="text-align: center; padding: 40px; color: #b0b0b0;">Testing app connectivity...</p>';
        modal.style.display = 'block';
        
        const response = await fetch(`/blackgrid/admin/api/apps/${appId}/test`, {
            method: 'POST'
        });
        const result = await response.json();
        
        // Build HTML content for test results
        let html = '<div class="test-results">';
        
        // Socket listening test
        html += '<div class="test-section">';
        html += '<h3>Socket Test</h3>';
        html += '<div class="test-result ' + (result.is_listening ? 'success' : 'error') + '">';
        html += result.is_listening 
            ? '<span class="test-icon">✓</span><span>Port ' + result.port + ' is listening</span>'
            : '<span class="test-icon">✗</span><span>Port ' + result.port + ' is NOT listening</span>';
        html += '</div>';
        html += '</div>';
        
        // HTTP test (local / server address)
        html += '<div class="test-section">';
        html += '<h3>HTTP Test (Port ' + result.port + ')</h3>';
        const httpIsSuccessful = result.http.accessible && result.http.successful;
        html += '<div class="test-result ' + (httpIsSuccessful ? 'success' : 'error') + '">';
        if (result.http.accessible) {
            const status = typeof result.http.status === 'number' ? 'HTTP ' + result.http.status : result.http.status;
            if (result.http.successful) {
                html += '<span class="test-icon">✓</span><span>Accessible - ' + status + '</span>';
            } else {
                html += '<span class="test-icon">✗</span><span>Error - ' + status + '</span>';
                if (typeof result.http.status === 'number' && result.http.status === 404) {
                    html += '<div class="test-warning">⚠ Resource not found (404) - App may not be responding correctly</div>';
                } else if (typeof result.http.status === 'number' && result.http.status >= 500) {
                    html += '<div class="test-warning">⚠ Server error (' + result.http.status + ') - App is returning an error</div>';
                }
            }
        } else {
            html += '<span class="test-icon">✗</span><span>NOT accessible - ' + result.http.status + '</span>';
        }
        html += '</div>';
        html += '<div class="test-url"><strong>URL:</strong> <code>' + result.http.url + '</code></div>';
        html += '</div>';

        // Public HTTP test (domain:port users click)
        if (result.public_http) {
            html += '<div class="test-section">';
            html += '<h3>Public HTTP Test (' + (result.public_http.host || 'domain') + ':' + result.port + ')</h3>';
            const publicHttpSuccessful = result.public_http.accessible && result.public_http.successful;
            html += '<div class="test-result ' + (publicHttpSuccessful ? 'success' : 'error') + '">';
            if (result.public_http.accessible) {
                const status = typeof result.public_http.status === 'number' ? 'HTTP ' + result.public_http.status : result.public_http.status;
                if (result.public_http.successful) {
                    html += '<span class="test-icon">✓</span><span>Accessible - ' + status + '</span>';
                } else {
                    html += '<span class="test-icon">✗</span><span>Error - ' + status + '</span>';
                    if (typeof result.public_http.status === 'number' && result.public_http.status === 404) {
                        html += '<div class="test-warning">⚠ Resource not found (404) - App may be running but route returned 404</div>';
                    } else if (typeof result.public_http.status === 'number' && result.public_http.status >= 500) {
                        html += '<div class="test-warning">⚠ Server error (' + result.public_http.status + ') - App is returning an error</div>';
                    }
                }
            } else {
                html += '<span class="test-icon">✗</span><span>NOT accessible - ' + result.public_http.status + '</span>';
            }
            html += '</div>';
            html += '<div class="test-url"><strong>URL:</strong> <code>' + result.public_http.url + '</code></div>';
            html += '</div>';
        }
        
        // HTTPS test
        html += '<div class="test-section">';
        html += '<h3>HTTPS Test (Port ' + result.https.port + ')</h3>';
        const httpsIsSuccessful = result.https.accessible && result.https.successful;
        html += '<div class="test-result ' + (httpsIsSuccessful ? 'success' : 'error') + '">';
        if (result.https.accessible) {
            const status = typeof result.https.status === 'number' ? 'HTTP ' + result.https.status : result.https.status;
            if (result.https.successful) {
                html += '<span class="test-icon">✓</span><span>Accessible - ' + status + '</span>';
            } else {
                html += '<span class="test-icon">✗</span><span>Error - ' + status + '</span>';
                if (result.https.status === 'SSL_ERROR') {
                    html += '<div class="test-warning">⚠ SSL certificate issue detected (certificate not trusted)</div>';
                } else if (typeof result.https.status === 'number' && result.https.status === 404) {
                    html += '<div class="test-warning">⚠ Resource not found (404) - App may not be responding correctly</div>';
                } else if (typeof result.https.status === 'number' && result.https.status >= 500) {
                    html += '<div class="test-warning">⚠ Server error (' + result.https.status + ') - App is returning an error</div>';
                }
            }
        } else {
            html += '<span class="test-icon">✗</span><span>NOT accessible - ' + result.https.status + '</span>';
        }
        html += '</div>';
        html += '<div class="test-url"><strong>URL:</strong> <code>' + result.https.url + '</code></div>';
        
        // SSL Certificate Status
        if (result.https.certificate_status) {
            const certStatus = result.https.certificate_status;
            html += '<div class="test-cert-info" style="margin-top: 10px; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 5px;">';
            html += '<strong>SSL Certificate Status:</strong><br>';
            html += '• Nginx Configured: ' + (certStatus.nginx_configured ? '✓ Yes' : '✗ No') + '<br>';
            html += '• Certificate Exists: ' + (certStatus.certificate_exists ? '✓ Yes' : '✗ No') + '<br>';
            html += '• Certificate Trusted: ' + (certStatus.certificate_trusted ? '✓ Yes (Let\'s Encrypt)' : '✗ No') + '<br>';
            if (certStatus.certificate_path) {
                html += '• Certificate Path: <code style="font-size: 0.9em;">' + certStatus.certificate_path + '</code><br>';
            }
            if (certStatus.certificate_info) {
                const certInfo = certStatus.certificate_info;
                if (certInfo.issuer) {
                    html += '• Issuer: ' + (certInfo.issuer.get('organizationName') || certInfo.issuer.get('CN') || 'Unknown') + '<br>';
                }
                if (certInfo.expires) {
                    html += '• Expires: ' + certInfo.expires + '<br>';
                }
                if (certInfo.error) {
                    html += '• Error: <span style="color: #f48771;">' + certInfo.error + '</span><br>';
                }
            }
            if (certStatus.error) {
                html += '• Error: <span style="color: #f48771;">' + certStatus.error + '</span><br>';
            }
            html += '</div>';
        }
        html += '</div>';
        
        // Masked-path proxy tests removed (new routing model is domain:port)
        
        html += '</div>';
        
        content.innerHTML = html;
    } catch (error) {
        const content = document.getElementById('test-results-content');
        content.innerHTML = '<div class="test-error"><p>Error testing app: ' + error.message + '</p></div>';
    }
}


// NOTE: Do not close this modal on outside click.
// It should only close via the "X" button (see `closeTestResultsModal()`).

function getPortForApp(appId) {
    var el = document.querySelector('.app-status[data-app-id="' + appId + '"][data-port]');
    return el ? parseInt(el.dataset.port, 10) : null;
}

function pollUntilPortActive(appId, port, maxWaitMs) {
    var interval = 1500;
    var elapsed = 0;
    return new Promise(function (resolve) {
        function check() {
            if (elapsed >= maxWaitMs) {
                resolve(false);
                return;
            }
            fetch('/blackgrid/admin/api/active-ports', { credentials: 'include' })
                .then(function (r) { return r.json(); })
                .then(function (result) {
                    var activePorts = new Set();
                    if (result.success && result.ports) {
                        result.ports.forEach(function (p) { activePorts.add(Number(p.port)); });
                    }
                    if (activePorts.has(port)) {
                        resolve(true);
                        return;
                    }
                    elapsed += interval;
                    setTimeout(check, interval);
                })
                .catch(function () {
                    elapsed += interval;
                    setTimeout(check, interval);
                });
        }
        setTimeout(check, interval);
    });
}

async function startApp(appId) {
    setAppStatusById(appId, 'starting');
    try {
        const response = await fetch(`/blackgrid/admin/api/apps/${appId}/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include'
        });
        const result = await response.json();
        if (result.success) {
            showAlert(result.message || 'App started.', 'success');
            refreshPortsConsole();
            var port = getPortForApp(appId);
            if (port) {
                await pollUntilPortActive(appId, port, 20000);
            }
            await refreshDiscoveredApps();
            setAppStatusById(appId, 'started');
            refreshAppStatusIndicators();
            setTimeout(refreshAppManagerLogs, 1500);
        } else {
            showAlert(result.error || 'Failed to start app.', 'error');
            setAppStatusById(appId, 'stopped');
            refreshAppStatusIndicators();
        }
    } catch (error) {
        showAlert('Error starting app: ' + error.message, 'error');
        setAppStatusById(appId, 'stopped');
        refreshAppStatusIndicators();
    }
}

async function restartApp(appId) {
    if (!confirm('Are you sure you want to restart this app?')) {
        return;
    }
    setAppStatusById(appId, 'starting');
    try {
        const response = await fetch(`/blackgrid/admin/api/apps/${appId}/restart`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error('Expected JSON but received ' + (contentType || 'unknown'));
        }

        const result = await response.json();

        if (result.success) {
            showAlert(result.message || 'App restarted.', 'success');
            refreshPortsConsole();
            var port = getPortForApp(appId);
            if (port) {
                await pollUntilPortActive(appId, port, 20000);
            }
            await refreshDiscoveredApps();
            setAppStatusById(appId, 'started');
            refreshAppStatusIndicators();
            setTimeout(refreshAppManagerLogs, 1500);
        } else {
            showAlert(result.error || 'Restart failed.', 'error');
            setAppStatusById(appId, 'stopped');
            refreshAppStatusIndicators();
        }
    } catch (error) {
        showAlert('Error restarting app: ' + error.message, 'error');
        setAppStatusById(appId, 'stopped');
        refreshAppStatusIndicators();
    }
}

async function restartAppManager() {
    if (!confirm('Are you sure you want to restart App Manager? This will temporarily disconnect you from the dashboard.')) {
        return;
    }
    
    try {
        const response = await fetch(`/blackgrid/admin/api/restart-appmanager`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        // Check if response is JSON before parsing
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`Expected JSON but received ${contentType}. Response: ${text.substring(0, 100)}`);
        }
        
        const result = await response.json();
        
        if (result.success) {
            alert('✓ ' + (result.message || 'App Manager restarted successfully. You will be disconnected momentarily.'));
            // Redirect to welcome page after a short delay
            setTimeout(() => {
                window.location.href = '/blackgrid/';
            }, 2000);
        } else {
            alert('✗ Error: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        // If we get a network error, the service might have restarted before response was sent
        // In this case, assume it worked and redirect anyway
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            alert('✓ Restart initiated. The service is restarting. You will be redirected...');
            setTimeout(() => {
                window.location.href = '/blackgrid/';
            }, 2000);
        } else {
            alert('Error restarting App Manager: ' + error.message);
        }
    }
}

async function setAutoStart(appId, enabled) {
    window.__autoStartInProgress = true;
    var checkbox = document.querySelector('.auto-start-checkbox[data-app-id="' + appId + '"]');
    try {
        var response = await fetch('/blackgrid/admin/api/apps/' + appId + '/set-auto-start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ auto_start: enabled })
        });
        var result = await response.json();
        if (result.success) {
            showAlert(enabled ? 'App will auto-start when stopped.' : 'Auto-start disabled.', 'success');
            var currentCheckbox = document.querySelector('.auto-start-checkbox[data-app-id="' + appId + '"]');
            if (currentCheckbox) currentCheckbox.checked = !!result.app.auto_start;
        } else {
            if (checkbox) checkbox.checked = !enabled;
            showAlert(result.error || 'Failed to update auto-start', 'error');
        }
    } catch (e) {
        if (checkbox) checkbox.checked = !enabled;
        showAlert('Error updating auto-start: ' + (e && e.message ? e.message : String(e)), 'error');
    } finally {
        setTimeout(function() { window.__autoStartInProgress = false; }, 500);
    }
}

async function toggleServeApp(appIndex, checked) {
    const appId = resolveAppId(appIndex);
    if (!appId) return;
    const checkbox = document.querySelector(`input.serve-app-checkbox[data-app-index="${appIndex}"]`);
    
    try {
        const response = await fetch(`/blackgrid/admin/api/apps/${appId}/toggle-serve`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const result = await response.json();
        
        if (result.success) {
            // Ensure checkbox state matches API response
            if (checkbox) {
                checkbox.checked = result.app.serve_app;
            }
            // Show a brief feedback message
            const status = result.app.serve_app ? 'enabled' : 'disabled';
            showAlert(`App serving ${status}`, 'success');
        } else {
            // Revert checkbox on error
            if (checkbox) {
                checkbox.checked = !checked;
            }
            alert('Error: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        // Revert checkbox on error
        if (checkbox) {
            checkbox.checked = !checked;
        }
        alert('Error toggling serve app: ' + error.message);
    }
}

async function deleteApp(appId) {
    if (!confirm('Are you sure you want to delete this app? This cannot be undone.')) {
        return;
    }
    
    try {
        const response = await fetch(`/blackgrid/admin/api/apps/${appId}`, {
            method: 'DELETE'
        });
        const result = await response.json();
        
        if (result.success) {
            refreshDiscoveredApps();
        } else {
            alert('Error: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Error deleting app: ' + error.message);
    }
}

function showServiceNameHelp() {
    alert('Service Name Help:\n\n' +
          'The service name is the systemd service name for your app on Linux servers.\n\n' +
          'To find it:\n' +
          '1. Click the "🔍 Detect" button next to the Port field to auto-detect\n' +
          '2. Or on your server, run: sudo systemctl list-units --type=service\n' +
          '3. Look for your app (e.g., calculator.service, quizia.service)\n' +
          '4. Or check: ls /etc/systemd/system/*.service\n\n' +
          'Examples:\n' +
          '- calculator.service (for Calculator app)\n' +
          '- quizia.service (for Quizia app)\n' +
          '- deltabooks.service (for DeltaBooks app)\n\n' +
          'Note: Leave blank if:\n' +
          '- Running locally (not on Linux server)\n' +
          '- Not using systemd\n' +
          '- Don\'t need restart functionality\n\n' +
          'See SERVICE_NAME_GUIDE.md for more details.');
}

async function detectPortFromFolder() {
    var folderPath = (document.getElementById('app-folder-path').value || '').trim();
    if (!folderPath) {
        alert('Please enter the app folder path first');
        return;
    }
    var btn = document.querySelector('[data-action="detectPort"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Detecting...'; }
    try {
        var r = await fetch('/blackgrid/admin/api/config/detect-port?folder_path=' + encodeURIComponent(folderPath));
        var result = await r.json();
        if (result.success) {
            document.getElementById('app-port').value = result.port;
            if (btn) btn.textContent = 'Detect Port';
        } else {
            alert(result.error || 'Could not detect port');
        }
    } catch (err) {
        alert('Error: ' + (err && err.message ? err.message : 'Unknown'));
    }
    if (btn) { btn.disabled = false; btn.textContent = 'Detect Port'; }
}

async function detectServiceName() {
    var port = document.getElementById('app-port').value;
    if (!port) {
        alert('Please enter a port number first (or use Detect Port)');
        return;
    }
    
    const detectBtn = event.target;
    const originalText = detectBtn.textContent;
    detectBtn.disabled = true;
    detectBtn.textContent = 'Detecting...';
    
    try {
        const response = await fetch(`/blackgrid/admin/api/detect-service/${port}`);
        const result = await response.json();
        
        if (result.success && result.service_name) {
            document.getElementById('app-service-name').value = result.service_name;
            alert(`✓ Detected service: ${result.service_name}`);
        } else {
            alert('Could not detect service name for this port.\n\n' +
                  'This might mean:\n' +
                  '- No service is running on this port\n' +
                  '- Not running on Linux with systemd\n' +
                  '- Service detection is not available\n\n' +
                  'You can still manually enter the service name.');
        }
    } catch (error) {
        alert('Error detecting service: ' + error.message);
    } finally {
        detectBtn.disabled = false;
        detectBtn.textContent = originalText;
    }
}

// Resource Manager
let memoryChart = null;
let diskChart = null;
let networkChart = null;
let resourceStatsLoading = false;
let lastResourceStatsCall = 0;
const RESOURCE_STATS_THROTTLE_MS = 2000; // Minimum 2 seconds between calls



// Helper function to generate colors using vibrant scheme (avoid white/light colors)
function generateTrafficColor(index) {
    // Use muted color palette (matching screenshot colors)
    const mutedColors = [
        '#c57c3c', // Orange/Brown
        '#ab62c0', // Purple
        '#72a555', // Green
        '#ca5670', // Red/Pink
        '#638ccc', // Blue
        '#8b6f47', // Brown
        '#9d7fb8', // Light Purple
        '#5d8a3f', // Dark Green
        '#b84a5f', // Dark Pink
        '#4a6ba3'  // Dark Blue
    ];
    return mutedColors[index % mutedColors.length];
}

async function refreshResourceStats() {
    // Throttle: prevent calls more frequently than every 2 seconds
    const now = Date.now();
    if (now - lastResourceStatsCall < RESOURCE_STATS_THROTTLE_MS) {
        console.log('Resource stats refresh throttled');
        return;
    }
    
    // Prevent duplicate simultaneous requests
    if (resourceStatsLoading) {
        console.log('Resource stats already loading, skipping');
        return;
    }
    
    resourceStatsLoading = true;
    lastResourceStatsCall = now;
    
    try {
        const response = await fetch('/blackgrid/admin/api/resources');
        
        // Check if response is OK before parsing JSON
        if (!response.ok) {
            // Try to get error text for debugging
            const errorText = await response.text();
            console.error(`Failed to load resource stats: HTTP ${response.status}`, errorText.substring(0, 200));
            
            // Show user-friendly error message
            const resourceArea = document.getElementById('resource-content-area');
            if (resourceArea) {
                resourceArea.innerHTML = `<div style="color: #dc3545; text-align: center; padding: 20px;">
                    <p>Error loading resource stats: HTTP ${response.status}</p>
                    <p style="font-size: 0.9em; color: #808080;">Please try refreshing or check the console for details.</p>
                </div>`;
            }
            return;
        }
        
        // Check content type to ensure we're getting JSON
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const errorText = await response.text();
            console.error('Expected JSON but got:', contentType, errorText.substring(0, 200));
            
            // Show user-friendly error message
            const resourceArea = document.getElementById('resource-content-area');
            if (resourceArea) {
                resourceArea.innerHTML = `<div style="color: #dc3545; text-align: center; padding: 20px;">
                    <p>Error: Server returned invalid response format</p>
                    <p style="font-size: 0.9em; color: #808080;">Please try refreshing or check the console for details.</p>
                </div>`;
            }
            return;
        }
        
        const result = await response.json();
        
        if (result.success) {
            updateMemoryChart(result.memory, result.apps || [], result.appmanager || null, result.breakdown || null);
            updateDiskChart(result.disk, result.apps || [], result.appmanager || null, result.breakdown || null);
            updateNetworkChart(result.network);
            
            // Resize charts after update to ensure they fit the container
            setTimeout(() => {
                if (memoryChart) memoryChart.resize();
                if (diskChart) diskChart.resize();
                if (networkChart) networkChart.resize();
            }, 100);
        } else {
            console.error('Failed to load resource stats:', result.error);
            
            // Show user-friendly error message
            const resourceArea = document.getElementById('resource-content-area');
            if (resourceArea) {
                resourceArea.innerHTML = `<div style="color: #dc3545; text-align: center; padding: 20px;">
                    <p>Error loading resource stats: ${result.error || 'Unknown error'}</p>
                    <p style="font-size: 0.9em; color: #808080;">Please try refreshing or check the console for details.</p>
                </div>`;
            }
        }
    } catch (error) {
        console.error('Error loading resource stats:', error);
        
        // Show user-friendly error message
        const resourceArea = document.getElementById('resource-content-area');
        if (resourceArea) {
            resourceArea.innerHTML = `<div style="color: #dc3545; text-align: center; padding: 20px;">
                <p>Error loading resource stats: ${error.message || 'Network error'}</p>
                <p style="font-size: 0.9em; color: #808080;">Please try refreshing or check the console for details.</p>
            </div>`;
        }
    } finally {
        resourceStatsLoading = false;
    }
}

function updateMemoryChart(memory, apps, appmanager, breakdown) {
    const ctx = document.getElementById('memory-chart');
    if (!ctx) return;
    
    const usedPercent = memory.percent;
    const freePercent = 100 - usedPercent;
    
    // Update center text
    const centerText = document.getElementById('memory-center-text');
    if (centerText) {
        centerText.innerHTML = `
            <div style="font-size: 2.5em; font-weight: bold; color: #d4d4d4; line-height: 1.2;">${usedPercent.toFixed(2)}%</div>
            <div style="font-size: 0.9em; color: #808080; margin-top: 5px;">(${parseFloat(memory.used_gb).toFixed(2)} GB / ${parseFloat(memory.total_gb).toFixed(2)} GB)</div>
        `;
    }
    
    // Build breakdown data for the used portion
    const labels = [];
    const data = [];
    const colors = [];
    let colorIndex = 0;
    
    // Add mapped apps
    apps.forEach(app => {
        if (app.memory_percent > 0.1) { // Only show if > 0.1%
            labels.push(app.app_name || `App ${app.port}`);
            data.push(app.memory_percent);
            colors.push(generateTrafficColor(colorIndex));
            colorIndex++;
        }
    });
    
    // Add AppManager
    if (appmanager && appmanager.memory_percent > 0.1) {
        labels.push('AppManager');
        data.push(appmanager.memory_percent);
        colors.push(generateTrafficColor(colorIndex));
        colorIndex++;
    }
    
    // Add System
    if (breakdown && breakdown.system && breakdown.system.memory_percent > 0.1) {
        labels.push('System');
        data.push(breakdown.system.memory_percent);
        colors.push(generateTrafficColor(colorIndex));
        colorIndex++;
    }
    
    // Add Other
    if (breakdown && breakdown.other && breakdown.other.memory_percent > 0.1) {
        labels.push('Other');
        data.push(breakdown.other.memory_percent);
        colors.push(generateTrafficColor(colorIndex));
        colorIndex++;
    }
    
    // Calculate remaining used (if breakdown doesn't add up to 100%)
    const breakdownTotal = data.reduce((sum, val) => sum + val, 0);
    if (breakdownTotal < usedPercent && usedPercent - breakdownTotal > 0.1) {
        labels.push('Unallocated');
        data.push(usedPercent - breakdownTotal);
        colors.push(generateTrafficColor(colorIndex));
        colorIndex++;
    }
    
    // Add free space
    labels.push('Free');
    data.push(freePercent);
    colors.push('#252526'); // Dark background color
    
    // Stats grid removed - no longer displaying stats below charts
    
    if (memoryChart) {
        memoryChart.destroy();
    }
    
    memoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'right',
                    labels: {
                        color: '#ffffff',
                        padding: 10,
                        font: {
                            size: 11,
                            color: '#ffffff'
                        },
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length && data.datasets.length) {
                                return data.labels.map((label, i) => {
                                    const value = data.datasets[0].data[i];
                                    return {
                                        text: `${label} (${value.toFixed(2)}%)`,
                                        fillStyle: data.datasets[0].backgroundColor[i],
                                        strokeStyle: data.datasets[0].borderColor,
                                        lineWidth: data.datasets[0].borderWidth,
                                        hidden: false,
                                        index: i,
                                        fontColor: '#ffffff',
                                        color: '#ffffff'
                                    };
                                });
                            }
                            return [];
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = memory.total_gb;
                            const gb = (value / 100) * total;
                            return `${label}: ${value.toFixed(2)}% (${gb.toFixed(2)} GB)`;
                        }
                    }
                }
            },
            animation: {
                onComplete: function() {
                    updateMemoryCenterTextPosition(memoryChart);
                }
            },
            onResize: function(chart) {
                updateMemoryCenterTextPosition(chart);
            }
        }
    });
    
    // Position center text on the donut, not the entire chart area (with delay to ensure chartArea is ready)
    setTimeout(() => updateMemoryCenterTextPosition(memoryChart), 100);
}

function updateMemoryCenterTextPosition(chart) {
    const centerText = document.getElementById('memory-center-text');
    if (!centerText || !chart) return;
    
    const chartArea = chart.chartArea;
    if (!chartArea) {
        // If chartArea not available yet, try again after a short delay
        setTimeout(() => updateMemoryCenterTextPosition(chart), 100);
        return;
    }
    
    const canvas = chart.canvas;
    const container = canvas.parentElement;
    
    // Calculate the center of the donut chart (chartArea), not the entire canvas
    const donutCenterX = chartArea.left + (chartArea.right - chartArea.left) / 2;
    const donutCenterY = chartArea.top + (chartArea.bottom - chartArea.top) / 2;
    
    // Convert to percentage relative to canvas
    const leftPercent = (donutCenterX / canvas.width) * 100;
    const topPercent = (donutCenterY / canvas.height) * 100;
    
    centerText.style.left = `${leftPercent}%`;
    centerText.style.top = `${topPercent}%`;
    centerText.style.transform = 'translate(-50%, -50%)';
}

function updateDiskChart(disk, apps, appmanager, breakdown) {
    const ctx = document.getElementById('disk-chart');
    if (!ctx) return;
    
    const usedPercent = disk.percent;
    const freePercent = 100 - usedPercent;
    
    // Update center text
    const centerText = document.getElementById('disk-center-text');
    if (centerText) {
        centerText.innerHTML = `
            <div style="font-size: 2.5em; font-weight: bold; color: #d4d4d4; line-height: 1.2;">${usedPercent.toFixed(2)}%</div>
            <div style="font-size: 0.9em; color: #808080; margin-top: 5px;">(${parseFloat(disk.used_gb).toFixed(2)} GB / ${parseFloat(disk.total_gb).toFixed(2)} GB)</div>
        `;
    }
    
    // Build breakdown data for the used portion
    const labels = [];
    const data = [];
    const colors = [];
    let colorIndex = 0;
    
    // Add mapped apps (based on disk usage)
    apps.forEach(app => {
        if (app.disk_percent > 0.01) { // Only show if > 0.01%
            labels.push(app.app_name || `App ${app.port}`);
            data.push(app.disk_percent);
            colors.push(generateTrafficColor(colorIndex));
            colorIndex++;
        }
    });
    
    // Add AppManager
    if (appmanager && appmanager.disk_percent > 0.01) {
        labels.push('AppManager');
        data.push(appmanager.disk_percent);
        colors.push(generateTrafficColor(colorIndex));
        colorIndex++;
    }
    
    // Add Other (everything else)
    if (breakdown && breakdown.other && breakdown.other.disk_percent > 0.01) {
        labels.push('Other');
        data.push(breakdown.other.disk_percent);
        colors.push(generateTrafficColor(colorIndex));
        colorIndex++;
    }
    
    // Calculate remaining used (if breakdown doesn't add up to 100%)
    const breakdownTotal = data.reduce((sum, val) => sum + val, 0);
    if (breakdownTotal < usedPercent && usedPercent - breakdownTotal > 0.01) {
        labels.push('Unallocated');
        data.push(usedPercent - breakdownTotal);
        colors.push(generateTrafficColor(colorIndex));
        colorIndex++;
    }
    
    // Add free space
    labels.push('Free');
    data.push(freePercent);
    colors.push('#252526'); // Dark background color
    
    // Stats grid removed - no longer displaying stats below charts
    
    if (diskChart) {
        diskChart.destroy();
    }
    
    diskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'right',
                    labels: {
                        color: '#ffffff',
                        padding: 10,
                        font: {
                            size: 11,
                            color: '#ffffff'
                        },
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length && data.datasets.length) {
                                return data.labels.map((label, i) => {
                                    const value = data.datasets[0].data[i];
                                    return {
                                        text: `${label} (${value.toFixed(2)}%)`,
                                        fillStyle: data.datasets[0].backgroundColor[i],
                                        strokeStyle: data.datasets[0].borderColor,
                                        lineWidth: data.datasets[0].borderWidth,
                                        hidden: false,
                                        index: i,
                                        fontColor: '#ffffff',
                                        color: '#ffffff'
                                    };
                                });
                            }
                            return [];
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = disk.total_gb;
                            const gb = (value / 100) * total;
                            return `${label}: ${value.toFixed(2)}% (${gb.toFixed(2)} GB)`;
                        }
                    }
                }
            },
            animation: {
                onComplete: function() {
                    updateDiskCenterTextPosition(diskChart);
                }
            },
            onResize: function(chart) {
                updateDiskCenterTextPosition(chart);
            }
        }
    });
    
    // Position center text on the donut, not the entire chart area (with delay to ensure chartArea is ready)
    setTimeout(() => updateDiskCenterTextPosition(diskChart), 100);
}

function updateDiskCenterTextPosition(chart) {
    const centerText = document.getElementById('disk-center-text');
    if (!centerText || !chart) return;
    
    const chartArea = chart.chartArea;
    if (!chartArea) {
        // If chartArea not available yet, try again after a short delay
        setTimeout(() => updateDiskCenterTextPosition(chart), 100);
        return;
    }
    
    const canvas = chart.canvas;
    const container = canvas.parentElement;
    
    // Calculate the center of the donut chart (chartArea), not the entire canvas
    const donutCenterX = chartArea.left + (chartArea.right - chartArea.left) / 2;
    const donutCenterY = chartArea.top + (chartArea.bottom - chartArea.top) / 2;
    
    // Convert to percentage relative to canvas
    const leftPercent = (donutCenterX / canvas.width) * 100;
    const topPercent = (donutCenterY / canvas.height) * 100;
    
    centerText.style.left = `${leftPercent}%`;
    centerText.style.top = `${topPercent}%`;
    centerText.style.transform = 'translate(-50%, -50%)';
}

function updateNetworkChart(network) {
    const ctx = document.getElementById('network-chart');
    if (!ctx) return;
    
    const sentGB = network.bytes_sent_gb;
    const recvGB = network.bytes_recv_gb;
    const totalGB = sentGB + recvGB;
    
    document.getElementById('network-value').textContent = `Sent: ${parseFloat(sentGB).toFixed(2)} GB | Received: ${parseFloat(recvGB).toFixed(2)} GB`;
    
    // Stats grid removed - no longer displaying stats below charts
    
    if (networkChart) {
        networkChart.destroy();
    }
    
    networkChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Sent', 'Received'],
            datasets: [{
                label: 'Network Traffic (GB)',
                data: [sentGB, recvGB],
                backgroundColor: ['#638ccc', '#ab62c0'],
                borderColor: ['#638ccc', '#ab62c0'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(30, 30, 30, 0.95)',
                    titleColor: '#ffffff',
                    bodyColor: '#ffffff',
                    borderColor: 'rgba(255, 255, 255, 0.2)',
                    borderWidth: 1,
                    padding: 12,
                    titleFont: {
                        size: 14,
                        weight: 'bold'
                    },
                    bodyFont: {
                        size: 13
                    },
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed.y || 0;
                            return `${label}: ${value.toFixed(2)} GB`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#d4d4d4',
                        callback: function(value) {
                            return value.toFixed(2) + ' GB';
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#d4d4d4'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    });
}

// Traffic Manager
let dailyVisitsChart = null;
let hourlyDistributionChart = null;
let countriesChart = null;
let referrersChart = null;
let appsBreakdownChart = null;
let trafficStatsLoading = false;
let lastTrafficStatsCall = 0;
const TRAFFIC_STATS_THROTTLE_MS = 5000; // Minimum 5 seconds between calls

async function refreshTrafficStats() {
    // Throttle: prevent calls more frequently than every 5 seconds
    const now = Date.now();
    if (now - lastTrafficStatsCall < TRAFFIC_STATS_THROTTLE_MS) {
        console.log('Traffic stats refresh throttled');
        return;
    }
    
    // Prevent duplicate simultaneous requests
    if (trafficStatsLoading) {
        console.log('Traffic stats already loading, skipping');
        return;
    }
    
    trafficStatsLoading = true;
    lastTrafficStatsCall = now;
    
    try {
        // Get include_local value from checkbox
        const includeLocalCheckbox = document.getElementById('include-local-checkbox');
        const includeLocal = includeLocalCheckbox ? includeLocalCheckbox.checked : true;
        
        const response = await fetch(`/blackgrid/admin/api/traffic?days=30&include_local=${includeLocal}`);
        const result = await response.json();
        
        if (result.success && result.stats) {
            updateTrafficCharts(result.stats);
        } else {
            console.error('Failed to load traffic stats:', result.error);
        }
    } catch (error) {
        console.error('Error loading traffic stats:', error);
    } finally {
        trafficStatsLoading = false;
    }
}

function handleIncludeLocalChange() {
    // Refresh traffic stats when checkbox changes
    refreshTrafficStats();
}

function updateTrafficCharts(stats) {
    // Update overall statistics
    document.getElementById('traffic-overall-value').textContent = 
        `${stats.total_visits.toLocaleString()} visits | ${stats.total_unique_visitors.toLocaleString()} unique visitors`;
    
    const overallStatsHtml = `
        <div class="resource-stat-item">
            <span class="resource-stat-label">Total Visits:</span>
            <span class="resource-stat-value">${stats.total_visits.toLocaleString()}</span>
        </div>
        <div class="resource-stat-item">
            <span class="resource-stat-label">Unique Visitors:</span>
            <span class="resource-stat-value">${stats.total_unique_visitors.toLocaleString()}</span>
        </div>
        <div class="resource-stat-item">
            <span class="resource-stat-label">Period:</span>
            <span class="resource-stat-value">${stats.period_days} days</span>
        </div>
        <div class="resource-stat-item">
            <span class="resource-stat-label">Avg Daily Visits:</span>
            <span class="resource-stat-value">${Math.round(stats.total_visits / stats.period_days).toLocaleString()}</span>
        </div>
    `;
    document.getElementById('traffic-overall-stats').innerHTML = overallStatsHtml;
    
    // Daily Visits Chart
    updateDailyVisitsChart(stats.daily_visits || []);
    
    // Hourly Distribution Chart
    updateHourlyDistributionChart(stats.hourly_distribution || []);
    
    // Countries Chart
    updateCountriesChart(stats.top_countries || {});
    
    // Referrers Chart
    updateReferrersChart(stats.top_referrers || {});
    
    // Apps Breakdown Chart (with stacked referrers)
    updateAppsBreakdownChart(stats.apps || {});
}

function updateDailyVisitsChart(dailyData) {
    const ctx = document.getElementById('daily-visits-chart');
    if (!ctx) return;
    
    const labels = dailyData.map(d => {
        const date = new Date(d.date);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });
    const visits = dailyData.map(d => d.visits);
    const totalVisits = visits.reduce((sum, v) => sum + v, 0);
    
    document.getElementById('daily-visits-value').textContent = `Total: ${totalVisits.toLocaleString()} visits`;
    
    if (dailyVisitsChart) {
        dailyVisitsChart.destroy();
    }
    
    dailyVisitsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Daily Visits',
                data: visits,
                borderColor: '#638ccc',
                backgroundColor: 'rgba(99, 140, 204, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Visits: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#d4d4d4',
                        stepSize: 1
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#d4d4d4',
                        maxRotation: 45,
                        minRotation: 45
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    });
}

function updateHourlyDistributionChart(hourlyData) {
    const ctx = document.getElementById('hourly-distribution-chart');
    if (!ctx) return;
    
    const labels = hourlyData.map(d => `${d.hour}:00`);
    const visits = hourlyData.map(d => d.visits);
    const totalVisits = visits.reduce((sum, v) => sum + v, 0);
    
    document.getElementById('hourly-distribution-value').textContent = 
        totalVisits > 0 ? `Total: ${totalVisits.toLocaleString()} visits today` : 'No visits today';
    
    if (hourlyDistributionChart) {
        hourlyDistributionChart.destroy();
    }
    
    hourlyDistributionChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Visits',
                data: visits,
                backgroundColor: '#ab62c0',
                borderColor: '#ab62c0',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Visits: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#d4d4d4',
                        stepSize: 1
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#d4d4d4'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    });
}

function updateCountriesChart(countriesData) {
    const ctx = document.getElementById('countries-chart');
    if (!ctx) return;
    
    const countries = Object.entries(countriesData).slice(0, 10); // Top 10
    const labels = countries.map(([country]) => country);
    const visits = countries.map(([, count]) => count);
    const totalVisits = visits.reduce((sum, v) => sum + v, 0);
    
    document.getElementById('countries-value').textContent = 
        `${countries.length} countries tracked`;
    
    if (countriesChart) {
        countriesChart.destroy();
    }
    
    if (labels.length === 0) {
        return;
    }
    
    // Use muted color palette (matching screenshot colors)
    const mutedColors = [
        '#c57c3c', // Orange/Brown
        '#ab62c0', // Purple
        '#72a555', // Green
        '#ca5670', // Red/Pink
        '#638ccc', // Blue
        '#8b6f47', // Brown
        '#9d7fb8', // Light Purple
        '#5d8a3f', // Dark Green
        '#b84a5f', // Dark Pink
        '#4a6ba3'  // Dark Blue
    ];
    
    const colors = [];
    for (let i = 0; i < labels.length; i++) {
        colors.push(mutedColors[i % mutedColors.length]);
    }
    
    countriesChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: visits,
                backgroundColor: colors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'right',
                    labels: {
                        color: '#ffffff',
                        padding: 15,
                        font: {
                            size: 12,
                            color: '#ffffff'
                        },
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length && data.datasets.length) {
                                return data.labels.map((label, i) => {
                                    const value = data.datasets[0].data[i];
                                    const percent = totalVisits > 0 ? ((value / totalVisits) * 100).toFixed(1) : 0;
                                    return {
                                        text: `${label} (${percent}%)`,
                                        fillStyle: data.datasets[0].backgroundColor[i],
                                        strokeStyle: data.datasets[0].borderColor,
                                        lineWidth: data.datasets[0].borderWidth,
                                        hidden: false,
                                        index: i,
                                        fontColor: '#ffffff',
                                        color: '#ffffff'
                                    };
                                });
                            }
                            return [];
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const percent = totalVisits > 0 ? ((value / totalVisits) * 100).toFixed(1) : 0;
                            return `${label}: ${value} visits (${percent}%)`;
                        }
                    }
                }
            }
        }
    });
}

function updateReferrersChart(referrersData) {
    const ctx = document.getElementById('referrers-chart');
    if (!ctx) return;
    
    // Get all referrers sorted by count
    const allReferrers = Object.entries(referrersData).sort((a, b) => b[1] - a[1]);
    const totalReferrerVisits = allReferrers.reduce((sum, [, count]) => sum + count, 0);
    
    if (allReferrers.length === 0 || totalReferrerVisits === 0) {
        document.getElementById('referrers-value').textContent = 'No referrer data';
        return;
    }
    
    // Take top 10 individually
    const top10 = allReferrers.slice(0, 10);
    const others = allReferrers.slice(10);
    
    // Build labels and data
    const labels = top10.map(([referrer]) => referrer || 'Direct');
    const visits = top10.map(([, count]) => count);
    
    // Add "Other" category if there are more than 10 referrers
    if (others.length > 0) {
        const otherVisits = others.reduce((sum, [, count]) => sum + count, 0);
        labels.push('Other');
        visits.push(otherVisits);
    }
    
    const totalVisits = visits.reduce((sum, v) => sum + v, 0);
    
    document.getElementById('referrers-value').textContent = 
        `${allReferrers.length} referrers tracked`;
    
    if (referrersChart) {
        referrersChart.destroy();
    }
    
    // Use muted color palette (matching screenshot colors)
    const mutedColors = [
        '#c57c3c', // Orange/Brown
        '#ab62c0', // Purple
        '#72a555', // Green
        '#ca5670', // Red/Pink
        '#638ccc', // Blue
        '#8b6f47', // Brown
        '#9d7fb8', // Light Purple
        '#5d8a3f', // Dark Green
        '#b84a5f', // Dark Pink
        '#4a6ba3'  // Dark Blue
    ];
    
    const colors = [];
    for (let i = 0; i < labels.length; i++) {
        colors.push(mutedColors[i % mutedColors.length]);
    }
    
    referrersChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: visits,
                backgroundColor: colors,
                borderColor: '#1e1e1e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'right',
                    labels: {
                        color: '#e0e0e0',
                        padding: 15,
                        font: {
                            size: 12,
                            color: '#e0e0e0'
                        },
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length && data.datasets.length) {
                                return data.labels.map((label, i) => {
                                    const value = data.datasets[0].data[i];
                                    const percent = totalVisits > 0 ? ((value / totalVisits) * 100).toFixed(1) : 0;
                                    return {
                                        text: `${label} (${percent}%)`,
                                        fillStyle: data.datasets[0].backgroundColor[i],
                                        strokeStyle: data.datasets[0].borderColor,
                                        lineWidth: data.datasets[0].borderWidth,
                                        hidden: false,
                                        index: i,
                                        fontColor: '#e0e0e0'
                                    };
                                });
                            }
                            return [];
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(30, 30, 30, 0.95)',
                    titleColor: '#e0e0e0',
                    bodyColor: '#e0e0e0',
                    borderColor: 'rgba(255, 255, 255, 0.2)',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            const label = context.label || 'Direct';
                            const value = context.parsed || 0;
                            const percent = totalVisits > 0 ? ((value / totalVisits) * 100).toFixed(1) : 0;
                            return `${label}: ${value} visits (${percent}%)`;
                        }
                    }
                }
            }
        }
    });
}

function updateAppsBreakdownChart(appsData) {
    const ctx = document.getElementById('apps-breakdown-chart');
    if (!ctx) return;
    
    const apps = Object.entries(appsData);
    const appLabels = apps.map(([name]) => name);
    const totalVisits = apps.reduce((sum, [, data]) => sum + (data.visits || 0), 0);
    
    // Collect all unique referrers across all apps
    const allReferrers = new Set();
    apps.forEach(([appName, appData]) => {
        if (appData.referrers) {
            Object.keys(appData.referrers).forEach(ref => allReferrers.add(ref));
        }
    });
    
    const referrerList = Array.from(allReferrers).sort();
    
    document.getElementById('apps-breakdown-value').textContent = 
        `${apps.length} apps tracked | ${totalVisits.toLocaleString()} total visits${referrerList.length > 0 ? ` | ${referrerList.length} referrers` : ''}`;
    
    // Update stats grid
    let statsHtml = '';
    apps.forEach(([name, data]) => {
        if (data.visits > 0) {
            statsHtml += `
                <div class="resource-stat-item">
                    <span class="resource-stat-label">${name}:</span>
                    <span class="resource-stat-value">${data.visits.toLocaleString()} visits (${data.unique_visitors} unique)</span>
                </div>
            `;
        }
    });
    document.getElementById('apps-breakdown-stats').innerHTML = statsHtml || 
        '<div class="resource-stat-item"><span class="resource-stat-label">No traffic data yet</span></div>';
    
    if (appsBreakdownChart) {
        appsBreakdownChart.destroy();
    }
    
    if (appLabels.length === 0 || totalVisits === 0) {
        return;
    }
    
    // Build datasets for each referrer (each referrer will be a stack segment)
    // If no referrers, fall back to single dataset showing total visits
    let datasets;
    if (referrerList.length === 0) {
        // No referrer data, show simple bar chart
        const visits = apps.map(([, data]) => data.visits || 0);
        const mutedColors = [
            '#c57c3c', // Orange/Brown
            '#ab62c0', // Purple
            '#72a555', // Green
            '#ca5670', // Red/Pink
            '#638ccc', // Blue
            '#8b6f47', // Brown
            '#9d7fb8', // Light Purple
            '#5d8a3f', // Dark Green
            '#b84a5f', // Dark Pink
            '#4a6ba3'  // Dark Blue
        ];
        const colors = [];
        for (let i = 0; i < appLabels.length; i++) {
            colors.push(mutedColors[i % mutedColors.length]);
        }
        datasets = [{
            label: 'Visits',
            data: visits,
            backgroundColor: colors,
            borderColor: colors,
            borderWidth: 1
        }];
    } else {
        // Create stacked datasets for each referrer
        const mutedColors = [
            '#c57c3c', // Orange/Brown
            '#ab62c0', // Purple
            '#72a555', // Green
            '#ca5670', // Red/Pink
            '#638ccc', // Blue
            '#8b6f47', // Brown
            '#9d7fb8', // Light Purple
            '#5d8a3f', // Dark Green
            '#b84a5f', // Dark Pink
            '#4a6ba3'  // Dark Blue
        ];
        datasets = referrerList.map((referrer, index) => {
            const color = mutedColors[index % mutedColors.length];
            
            // For each app, get the count for this referrer
            const data = apps.map(([appName, appData]) => {
                return appData.referrers ? (appData.referrers[referrer] || 0) : 0;
            });
            
            return {
                label: referrer || 'Direct',
                data: data,
                backgroundColor: color,
                borderColor: color,
                borderWidth: 1
            };
        });
    }
    
    appsBreakdownChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: appLabels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: referrerList.length > 0,
                    position: 'top',
                    labels: {
                        color: '#e0e0e0',
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(30, 30, 30, 0.95)',
                    titleColor: '#e0e0e0',
                    bodyColor: '#e0e0e0',
                    borderColor: 'rgba(255, 255, 255, 0.2)',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            if (referrerList.length === 0) {
                                // Simple tooltip for non-stacked chart
                                const label = context.label || '';
                                const value = context.parsed.y || 0;
                                const appData = appsData[label];
                                const percent = totalVisits > 0 ? ((value / totalVisits) * 100).toFixed(1) : 0;
                                return `${label}: ${value} visits (${percent}%) | ${appData.unique_visitors} unique visitors`;
                            } else {
                                // Stacked chart tooltip
                                const label = context.dataset.label || '';
                                const value = context.parsed.y || 0;
                                const appName = context.label || '';
                                const appData = appsData[appName];
                                const appTotal = appData.visits || 0;
                                const percent = appTotal > 0 ? ((value / appTotal) * 100).toFixed(1) : 0;
                                return `${label}: ${value} visits (${percent}% of ${appName})`;
                            }
                        },
                        footer: function(tooltipItems) {
                            if (referrerList.length > 0 && tooltipItems.length > 0) {
                                const appName = tooltipItems[0].label;
                                const appData = appsData[appName];
                                const total = tooltipItems.reduce((sum, item) => sum + (item.parsed.y || 0), 0);
                                return `Total: ${total} visits | ${appData.unique_visitors} unique visitors`;
                            }
                            return '';
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    stacked: referrerList.length > 0,
                    ticks: {
                        color: '#d4d4d4',
                        stepSize: 1
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    stacked: referrerList.length > 0,
                    ticks: {
                        color: '#d4d4d4',
                        maxRotation: 45,
                        minRotation: 45
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    });
}

// Admin Login Tracking
async function refreshAdminLogins() {
    try {
        const response = await fetch('/blackgrid/admin/api/admin-logins');
        const result = await response.json();
        
        if (result.success && result.logins) {
            updateAdminLoginsTable(result.logins);
        } else {
            console.error('Failed to load admin login stats:', result.error);
            document.getElementById('admin-logins-table-body').innerHTML = 
                '<tr><td colspan="4" style="padding: 20px; text-align: center; color: #ff6b6b;">Error loading login history</td></tr>';
        }
    } catch (error) {
        console.error('Error loading admin login stats:', error);
        document.getElementById('admin-logins-table-body').innerHTML = 
            '<tr><td colspan="4" style="padding: 20px; text-align: center; color: #ff6b6b;">Error loading login history</td></tr>';
    }
}

function updateAdminLoginsTable(logins) {
    const tbody = document.getElementById('admin-logins-table-body');
    
    if (!logins || logins.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="padding: 20px; text-align: center; color: #808080;">No login history</td></tr>';
        return;
    }
    
    let html = '';
    logins.forEach(login => {
        const lastLogin = login.last_login ? new Date(login.last_login).toLocaleString() : 'Never';
        const location = login.city && login.city !== 'Unknown' && login.city !== 'Local' 
            ? `${login.city}, ${login.country}` 
            : login.country || 'Unknown';
        
        // Highlight current session
        const rowClass = login.is_current ? 'style="background: rgba(102, 126, 234, 0.2); border-left: 3px solid #667eea;"' : '';
        
        html += `
            <tr ${rowClass}>
                <td style="padding: 10px; border-bottom: 1px solid #2d2d2d; color: #d4d4d4;">
                    ${login.ip}
                    ${login.is_current ? '<span style="color: #667eea; margin-left: 8px; font-size: 0.85em;">(Current Session)</span>' : ''}
                </td>
                <td style="padding: 10px; border-bottom: 1px solid #2d2d2d; color: #d4d4d4;">${location}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2d2d2d; text-align: right; color: #d4d4d4;">${login.login_count}</td>
                <td style="padding: 10px; border-bottom: 1px solid #2d2d2d; color: #d4d4d4;">${lastLogin}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// AppManager Log Panel (fixed at bottom)
var _appmanagerLogRaw = '';
var _appmanagerLogHeight = 280;

function stripAnsi(line) {
    return (line || '').replace(/\x1b\[[0-9;]*m/g, '');
}

function isNoisyLogLine(line) {
    if (!line || !line.trim()) return true;
    var t = stripAnsi(line);
    if (/"(GET|POST|OPTIONS|HEAD|PUT|PATCH|DELETE)\s+\S+\s+HTTP\/[\d.]+"\s+(200|304)\s/.test(t)) return true;
    if (t.indexOf('INFO:werkzeug') >= 0 && (t.indexOf('" 200') >= 0 || t.indexOf('" 304') >= 0)) return true;
    if (/werkzeug:(INFO|WARNING):\s*\*?\s*Debugger\s+(is active|PIN)/i.test(t)) return true;
    if (/GET\s+\/static\//.test(t) && (/" 200\s/.test(t) || /" 304\s/.test(t))) return true;
    if (/GET\s+\/blackgrid\/media\//.test(t) && (/" 200\s/.test(t) || /" 304\s/.test(t))) return true;
    if (/GET\s+\/favicon\.ico/.test(t)) return true;
    return false;
}

function filterLogLines(raw, hideNoise) {
    if (!raw) return '';
    var lines = raw.split('\n');
    if (!hideNoise) return raw;
    return lines.filter(function(l) { return !isNoisyLogLine(l); }).join('\n');
}

function renderAppManagerLogs() {
    var pre = document.getElementById('appmanager-log-content-pre');
    var cb = document.getElementById('appmanager-log-filter-noise');
    if (!pre) return;
    var hideNoise = cb ? cb.checked : true;
    pre.textContent = filterLogLines(_appmanagerLogRaw, hideNoise) || '(No logs)';
    pre.onclick = null;
    pre.style.cursor = '';
    pre.style.textDecoration = '';
    var container = pre.closest('.appmanager-log-content');
    if (container) container.scrollTop = container.scrollHeight;
}

async function refreshAppManagerLogs() {
    var pre = document.getElementById('appmanager-log-content-pre');
    if (!pre) return;
    var hadContent = pre.textContent && pre.textContent.trim().length > 0;
    if (!hadContent) pre.textContent = 'Loading...';
    try {
        var resp = await fetch('/blackgrid/admin/api/logs/appmanager?lines=300', { credentials: 'include' });
        if (resp.status === 401) {
            pre.textContent = 'Session expired. Click here to log in again.';
            if (_appmanagerLogRefreshInterval) {
                clearInterval(_appmanagerLogRefreshInterval);
                _appmanagerLogRefreshInterval = null;
            }
            pre.onclick = function() { window.location.href = '/blackgrid/admin/login?next=' + encodeURIComponent(window.location.pathname || '/blackgrid/admin/dashboard'); };
            pre.style.cursor = 'pointer';
            pre.style.textDecoration = 'underline';
            return;
        }
        pre.onclick = null;
        pre.style.cursor = '';
        pre.style.textDecoration = '';
        var data = await resp.json().catch(function() { return { success: false, error: 'Invalid response' }; });
        if (data && data.success) {
            _appmanagerLogRaw = (typeof data.logs === 'string') ? data.logs : '';
            renderAppManagerLogs();
        } else {
            pre.textContent = 'Error: ' + (data && data.error ? data.error : 'Unknown error');
        }
    } catch (e) {
        pre.textContent = 'Error: ' + (e && e.message ? e.message : String(e));
    }
}

var _appmanagerLogRefreshInterval = null;

function toggleAppManagerLogAutorefresh(enable) {
    if (_appmanagerLogRefreshInterval) {
        clearInterval(_appmanagerLogRefreshInterval);
        _appmanagerLogRefreshInterval = null;
    }
    if (enable) {
        _appmanagerLogRefreshInterval = setInterval(refreshAppManagerLogs, 1000);
    }
}

function toggleAppManagerLogPanel() {
    var panel = document.getElementById('appmanager-log-panel');
    if (!panel) return;
    panel.classList.toggle('collapsed');
    if (!panel.classList.contains('collapsed')) {
        refreshAppManagerLogs();
    } else {
        if (_appmanagerLogRefreshInterval) {
            clearInterval(_appmanagerLogRefreshInterval);
            _appmanagerLogRefreshInterval = null;
        }
        var autorefreshCb = document.getElementById('appmanager-log-autorefresh');
        if (autorefreshCb) autorefreshCb.checked = false;
    }
}

function initAppManagerLogPanel() {
    var panel = document.getElementById('appmanager-log-panel');
    var resizeHandle = document.getElementById('appmanager-log-resize');
    if (!panel || !resizeHandle) return;

    var startY, startH;
    resizeHandle.addEventListener('mousedown', function(e) {
        e.preventDefault();
        startY = e.clientY;
        startH = panel.offsetHeight;
        function onMove(ev) {
            var dy = ev.clientY - startY;
            var newH = Math.max(120, Math.min(window.innerHeight - 100, startH - dy));
            _appmanagerLogHeight = newH;
            panel.style.setProperty('--appmanager-log-height', newH + 'px');
        }
        function onUp() {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    });

    panel.style.setProperty('--appmanager-log-height', _appmanagerLogHeight + 'px');
}

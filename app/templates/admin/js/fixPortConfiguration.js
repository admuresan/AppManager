{# IMPORTANT: Read `instructions/architecture` before making changes. #}

async function fixAppConfig(appId) {
    // Close dropdown
    const dropdown = document.getElementById(`dropdown-${appId}`);
    if (dropdown) {
        dropdown.style.display = 'none';
        dropdown.closest('.app-row')?.classList.remove('dropdown-open');
    }

    try {
        const modal = document.getElementById('test-results-modal');
        const content = document.getElementById('test-results-content');
        content.innerHTML = `
          <div class="test-results">
            <div class="test-section">
              <h3>Fix Port Configuration</h3>
              <div id="fpc-status" class="test-result success" style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);">
                <span class="test-icon">…</span><span>Starting…</span>
              </div>
              <div class="test-url"><strong>Host:</strong> <code id="fpc-host">(resolving…)</code></div>
              <div class="test-url"><strong>Port:</strong> <code id="fpc-port">(pending)</code></div>
              <div class="test-url"><strong>HTTPS Port:</strong> <code id="fpc-https-port">(pending)</code></div>
            </div>

            <div class="test-section">
              <h3>What changed</h3>
              <div id="fpc-actions" class="test-cert-info" style="margin-top: 10px;">
                <div class="muted">Waiting for results…</div>
              </div>
            </div>

            <div class="test-section">
              <h3>Tests</h3>
              <div id="fpc-tests" class="test-cert-info" style="margin-top: 10px;">
                <div class="muted">Waiting for tests…</div>
              </div>
            </div>
          </div>
        `;
        modal.style.display = 'block';

        const statusEl = document.getElementById('fpc-status');
        const hostEl = document.getElementById('fpc-host');
        const portEl = document.getElementById('fpc-port');
        const httpsPortEl = document.getElementById('fpc-https-port');
        const actionsEl = document.getElementById('fpc-actions');
        const testsEl = document.getElementById('fpc-tests');

        const actions = [];
        const tests = {};

        function setStatus(icon, text, kind) {
            statusEl.classList.remove('success', 'error');
            if (kind) statusEl.classList.add(kind);
            statusEl.querySelector('.test-icon').textContent = icon;
            statusEl.querySelector('span:last-child').textContent = text;
        }

        function renderActions() {
            if (!actions.length) {
                actionsEl.innerHTML = '<div class="muted">No actions recorded yet…</div>';
                return;
            }
            actionsEl.innerHTML = actions.map(a => {
                const ok = a.success ? '✓' : '✗';
                const method = (a.method || '').toUpperCase();
                const target = a.target ? ` (${a.target})` : '';
                return `• ${ok} ${method}${target}: ${a.message || a.action || ''}`;
            }).join('<br>');
        }

        function renderTests() {
            const keys = Object.keys(tests);
            if (!keys.length) {
                testsEl.innerHTML = '<div class="muted">No tests recorded yet…</div>';
                return;
            }
            const lines = [];
            keys.forEach(k => {
                const t = tests[k];
                if (t.name && t.name.startsWith('socket')) {
                    lines.push(`• ${t.listening ? '✓' : '✗'} ${t.name}: port <code>${t.port}</code> listening = ${String(t.listening)}`);
                    return;
                }
                const ok = t.successful ? '✓' : (t.accessible ? '⚠' : '✗');
                const status = (t.status !== undefined && t.status !== null) ? t.status : '(unknown)';
                lines.push(`• ${ok} ${t.name}: <code>${t.url}</code> → ${status}`);
                if (t.certificate_info && t.certificate_info.error) {
                    lines.push(`&nbsp;&nbsp;↳ cert error: <span style="color:#f48771;">${t.certificate_info.error}</span>`);
                }
            });
            testsEl.innerHTML = lines.join('<br>');
        }

        // Start streaming via SSE (no confirmation popup).
        setStatus('…', 'Working…', null);
        const es = new EventSource(`/blackgrid/admin/api/apps/${appId}/fix-config/stream`);

        es.addEventListener('meta', (e) => {
            const data = JSON.parse(e.data);
            hostEl.textContent = data.host || 'blackgrid.ddns.net';
            portEl.textContent = data.port ?? '(unknown)';
            httpsPortEl.textContent = data.https_port ?? '(unknown)';
        });

        es.addEventListener('step', (e) => {
            const data = JSON.parse(e.data);
            if (data && data.message) setStatus('…', data.message, null);
        });

        es.addEventListener('applied', (e) => {
            const data = JSON.parse(e.data);
            const r = data.result || {};
            // Add explicit per-method actions.
            if (r.ufw) actions.push({ method: 'ufw', target: data.target, success: r.ufw.success, action: r.ufw.action, message: r.ufw.message });
            if (r.oci) actions.push({ method: 'oci', target: data.target, success: r.oci.success, action: r.oci.action, message: r.oci.message });
            renderActions();
        });

        es.addEventListener('test', (e) => {
            const data = JSON.parse(e.data);
            if (!data || !data.name) return;
            tests[data.name] = data;
            renderTests();
        });

        es.addEventListener('done', (e) => {
            const result = JSON.parse(e.data);
            es.close();
            if (result && result.details) {
                hostEl.textContent = result.details.host || hostEl.textContent || 'blackgrid.ddns.net';
                portEl.textContent = result.details.port ?? portEl.textContent;
                httpsPortEl.textContent = result.details.https_port ?? httpsPortEl.textContent;
            }
            if (result && result.success) setStatus('✓', 'Applied configuration', 'success');
            else setStatus('✗', 'Failed: ' + ((result && result.error) ? result.error : 'Unknown error'), 'error');
        });

        es.addEventListener('error', (_e) => {
            try { es.close(); } catch (e2) {}
            setStatus('✗', 'Streaming error. Try again or check logs.', 'error');
        });
    } catch (error) {
        const content = document.getElementById('test-results-content');
        content.innerHTML = '<div class="test-error"><p>Error applying configuration: ' + error.message + '</p></div>';
    }
}


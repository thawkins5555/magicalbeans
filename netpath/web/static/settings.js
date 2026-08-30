/* The global Settings page. Changes are staged and applied together, because
   applying on every keystroke would restart the resolver constantly. */
(() => {
  function load() {
    const s = App.state.settings;
    const server = App.state.serverState || {};
    App.el('set-dns-enabled').checked = !!s.dns_enabled;
    App.el('set-dns-workers').value = s.dns_workers;
    App.el('set-dns-timeout').value = s.dns_timeout_s;
    App.el('set-dns-cache').value = s.dns_cache_days;
    App.el('set-dns-server').value = s.dns_server || '';
    App.el('set-dns-nslookup').checked = s.dns_use_nslookup !== false;
    App.el('set-asn-enabled').checked = s.asn_enabled !== false;
    App.el('set-asn-cache').value = s.asn_cache_days;
    App.el('set-asn-server').value = s.asn_server || '';
    App.el('set-refresh-netpath').value = s.netpath_refresh_s;
    App.el('set-refresh-nodes').value = s.nodes_refresh_s;
    App.el('set-refresh-alerts').value = s.alerts_refresh_s;
    App.el('set-refresh-netflow').value = s.netflow_refresh_s;
    App.el('set-refresh-snmp').value = s.snmp_refresh_s;
    App.el('set-refresh-syslog').value = s.syslog_refresh_s;
    App.el('set-refresh-ipam').value = s.ipam_refresh_s;
    App.el('set-refresh-debug').value = s.debug_refresh_s;
    App.el('set-trace-cap').value = s.max_trace_db_mb;
    App.el('set-flow-cap').value = s.max_flow_db_mb;
    App.el('set-snmp-cap').value = s.max_snmp_db_mb;
    App.el('set-syslog-cap').value = s.max_syslog_db_mb;
    App.el('set-ipam-cap').value = s.max_ipam_db_mb;
    App.el('set-nodes-cap').value = s.max_nodes_db_mb;
    App.el('set-alerts-cap').value = s.max_alerts_db_mb;
    App.el('set-idle-minutes').value = s.session_idle_minutes;
    App.el('set-session-hours').value = s.session_max_hours;

    const storage = server.storage || {};
    App.el('set-app-path').value = storage.app_path || '';
    App.el('set-trace-path').value = storage.trace_path || '';
    App.el('set-flow-path').value = storage.flow_path || '';
    App.el('set-snmp-path').value = storage.snmp_path || '';
    App.el('set-syslog-path').value = storage.syslog_path || '';
    App.el('set-ipam-path').value = storage.ipam_path || '';
    App.el('set-nodes-path').value = storage.nodes_path || '';
    App.el('set-alerts-path').value = storage.alerts_path || '';
    showUsage(storage);
    showUpdateInfo(server);
    status('Showing saved settings', 'var(--faint)');
  }

  /* --------------------------------------------------------------- update */

  function showUpdateInfo(server) {
    App.el('update-version').textContent = server.version ? `v${server.version}` : '';
    const commit = (server.update || {}).installed_commit;
    App.el('update-commit').textContent = commit ? commit.slice(0, 10) : 'unknown';
  }

  function updateStatus(message, colour) {
    const el = App.el('update-status');
    el.textContent = message;
    el.style.color = colour || 'var(--faint)';
  }

  async function checkForUpdate() {
    const button = App.el('update-now');
    button.disabled = true;
    updateStatus('Checking github.com for the latest commit…', 'var(--muted)');
    let payload;
    try {
      payload = await App.post('/api/update', {});
    } catch (error) {
      updateStatus(error.message, 'var(--fail)');
      button.disabled = false;
      return;
    }
    if (!payload.ok) {
      updateStatus(payload.error || 'Update failed', 'var(--fail)');
      button.disabled = false;
      return;
    }
    if (payload.up_to_date) {
      updateStatus(`Already up to date — ${payload.commit} “${payload.message}”.`,
                   'var(--ok)');
      button.disabled = false;
      return;
    }
    updateStatus(`Installed ${payload.commit} “${payload.message}” — restarting…`,
                 'var(--ok)');
    showRestartModal(payload);
    waitForRestart();
  }

  /* Blocks the whole screen while the restart is in flight: there is nothing
     useful to do with the rest of the UI mid-restart anyway (every request
     will 401 the instant the old session dies), and a plain status line
     off in Settings is easy to miss if you've wandered to another tab. */
  function showRestartModal(payload) {
    App.state.modalLocked = true;
    App.modal('Updating SappiWhere', `
      <p>Installed <b>${escape(payload.commit)}</b> — “${escape(payload.message)}”.</p>
      <p>Restarting the service to load it. This signs everyone out, this
      session included — you'll land back on the sign-in page automatically
      once it's back.</p>
      <p class="hint" id="restart-modal-status">Waiting for the service to
      come back…</p>`, []);
  }

  function restartModalStatus(message) {
    const el = document.getElementById('restart-modal-status');
    if (el) el.textContent = message;
  }

  /* The service is a single process; restarting it drops every connection for
     a moment and, since sessions are in-memory, ends every session including
     this one. Poll the public session endpoint with a plain fetch — not
     App.get, which would redirect to /login on the first 401 rather than
     waiting for the server to actually come back — until it answers, then
     send the browser to sign back in. */
  async function waitForRestart() {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      try {
        await fetch('/api/session', { cache: 'no-store' });
        updateStatus('Back up — signing back in…', 'var(--ok)');
        restartModalStatus('Back up — signing back in…');
        App.state.modalLocked = false;
        setTimeout(() => { window.location.href = '/login'; }, 500);
        return;
      } catch (error) {
        // still down — keep polling
      }
      restartModalStatus('Waiting for the service to come back… '
        + `(${Math.max(0, Math.round((deadline - Date.now()) / 1000))}s left)`);
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    updateStatus('Still not reachable after a minute — check the service directly.',
                 'var(--fail)');
    restartModalStatus('Still not reachable after a minute — check the '
      + 'service directly. You can close this and try again.');
    App.state.modalLocked = false;
    App.el('update-now').disabled = false;
  }

  /* What each database is using now, against the cap set beside it. The cap
     is only meaningful next to the number it is capping. */
  function showUsage(storage) {
    const rows = [
      ['use-trace', storage.trace_bytes, Number(App.el('set-trace-cap').value)],
      ['use-flow', storage.flow_bytes, Number(App.el('set-flow-cap').value)],
      ['use-snmp', storage.snmp_bytes, Number(App.el('set-snmp-cap').value)],
      ['use-syslog', storage.syslog_bytes, Number(App.el('set-syslog-cap').value)],
      ['use-ipam', storage.ipam_bytes, Number(App.el('set-ipam-cap').value)],
      ['use-nodes', storage.nodes_bytes, Number(App.el('set-nodes-cap').value)],
      ['use-alerts', storage.alerts_bytes, Number(App.el('set-alerts-cap').value)],
    ];
    for (const [id, bytes, capMb] of rows) {
      const el = App.el(id);
      if (!el) continue;
      const cap = (capMb || 0) * 1024 * 1024;
      const share = cap ? Math.min(bytes / cap, 1) : 0;
      const pct = cap ? Math.round(share * 100) : 0;
      el.className = 'usage' + (share >= 0.9 ? ' full' : share >= 0.75 ? ' warn' : '');
      el.innerHTML =
        `<span class="bar"><i style="width:${share * 100}%"></i></span>` +
        `${App.bytes(bytes || 0)} used${cap ? ` · ${pct}%` : ''}`;
    }
    const total = (storage.trace_bytes || 0) + (storage.flow_bytes || 0)
      + (storage.snmp_bytes || 0) + (storage.syslog_bytes || 0)
      + (storage.app_bytes || 0) + (storage.ipam_bytes || 0)
      + (storage.nodes_bytes || 0) + (storage.alerts_bytes || 0);
    App.el('set-sizes').textContent =
      `${App.bytes(total)} on disk in total. Sizes include each file's `
      + 'write-ahead log, which is why they can grow between prunes and shrink after one.';
  }

  function status(message, colour) {
    const el = App.el('set-status');
    el.textContent = message;
    el.style.color = colour || 'var(--faint)';
  }

  async function apply() {
    const values = {
      dns_enabled: App.el('set-dns-enabled').checked,
      dns_workers: Number(App.el('set-dns-workers').value),
      dns_timeout_s: Number(App.el('set-dns-timeout').value),
      dns_cache_days: Number(App.el('set-dns-cache').value),
      dns_server: App.el('set-dns-server').value.trim(),
      dns_use_nslookup: App.el('set-dns-nslookup').checked,
      asn_enabled: App.el('set-asn-enabled').checked,
      asn_cache_days: Number(App.el('set-asn-cache').value),
      asn_server: App.el('set-asn-server').value.trim(),
      netpath_refresh_s: Number(App.el('set-refresh-netpath').value),
      nodes_refresh_s: Number(App.el('set-refresh-nodes').value),
      alerts_refresh_s: Number(App.el('set-refresh-alerts').value),
      netflow_refresh_s: Number(App.el('set-refresh-netflow').value),
      snmp_refresh_s: Number(App.el('set-refresh-snmp').value),
      syslog_refresh_s: Number(App.el('set-refresh-syslog').value),
      ipam_refresh_s: Number(App.el('set-refresh-ipam').value),
      debug_refresh_s: Number(App.el('set-refresh-debug').value),
      max_trace_db_mb: Number(App.el('set-trace-cap').value),
      max_flow_db_mb: Number(App.el('set-flow-cap').value),
      max_snmp_db_mb: Number(App.el('set-snmp-cap').value),
      max_syslog_db_mb: Number(App.el('set-syslog-cap').value),
      max_ipam_db_mb: Number(App.el('set-ipam-cap').value),
      max_nodes_db_mb: Number(App.el('set-nodes-cap').value),
      max_alerts_db_mb: Number(App.el('set-alerts-cap').value),
      session_idle_minutes: Number(App.el('set-idle-minutes').value),
      session_max_hours: Number(App.el('set-session-hours').value),
    };
    await App.post('/api/settings', { scope: 'global', values });
    await App.loadState();
    status(`Applied · reverse DNS ${values.dns_enabled ? 'on' : 'off'} · ` +
           `NetPath ${values.netpath_refresh_s}s · ` +
           `Nodes ${values.nodes_refresh_s}s · ` +
           `Alerts ${values.alerts_refresh_s}s · ` +
           `NetFlow ${values.netflow_refresh_s}s · ` +
           `SNMP ${values.snmp_refresh_s}s · ` +
           `Syslog ${values.syslog_refresh_s}s · ` +
           `Debug ${values.debug_refresh_s}s · ` +
           `idle timeout ${values.session_idle_minutes}min`, 'var(--ok)');
  }

  async function maintenance(action) {
    status('Working…', 'var(--muted)');
    const payload = await App.post('/api/maintenance', { action });
    await App.loadState();
    status(payload.message || '', 'var(--muted)');
    showUsage((App.state.serverState || {}).storage || {});
  }

  /* ------------------------------------------------------------- users */

  const escape = (t) => String(t ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function when(ts) {
    return ts ? new Date(ts * 1000).toLocaleString() : 'never';
  }

  async function loadUsers() {
    const payload = await App.get('/api/users');
    const table = App.el('users-table');
    const me = (App.state.session || {}).username;
    table.innerHTML = '<thead><tr><th>User</th><th>Created</th>' +
      '<th>Last sign-in</th><th>State</th><th></th></tr></thead>';
    const body = document.createElement('tbody');

    for (const user of payload.users) {
      const tr = document.createElement('tr');
      const isMe = user.username === me;
      tr.innerHTML =
        `<td>${escape(user.username)}${isMe ? ' <span class="hint">(you)</span>' : ''}</td>` +
        `<td>${when(user.created)}</td>` +
        `<td>${when(user.last_login)}</td>` +
        `<td>${user.must_change ? 'must change password' : 'active'}</td>` +
        '<td></td>';
      if (!isMe) {
        const remove = document.createElement('button');
        remove.textContent = 'Remove';
        remove.onclick = () => confirmRemove(user.username);
        tr.lastElementChild.appendChild(remove);
      }
      body.appendChild(tr);
    }
    table.appendChild(body);

    const sessions = payload.sessions || [];
    App.el('sessions-line').textContent = sessions.length
      ? `${sessions.length} active session(s): ` + sessions
        .map((s) => `${s.username} from ${s.client} (idle ${Math.round(s.idle_s)}s)`)
        .join(', ')
      : 'No active sessions.';
  }

  function confirmRemove(username) {
    App.modal('Remove user',
      `<p>Remove <b>${escape(username)}</b>? Any session they have open ends ` +
      'immediately.</p>', [
        { label: 'Cancel', onClick: App.closeModal },
        { label: 'Remove', primary: true, onClick: async () => {
          try {
            await App.del('/api/users', { username });
            App.closeModal();
            await loadUsers();
            usersStatus(`Removed ${username}`, 'var(--muted)');
          } catch (error) {
            App.closeModal();
            usersStatus(error.message, 'var(--fail)');
          }
        } },
      ]);
  }

  function usersStatus(message, colour) {
    const el = App.el('users-status');
    el.textContent = message;
    el.style.color = colour || 'var(--faint)';
  }

  async function addUser() {
    const username = App.el('new-username').value.trim();
    const password = App.el('new-password').value;
    try {
      await App.post('/api/users', { username, password });
      App.el('new-username').value = '';
      App.el('new-password').value = '';
      await loadUsers();
      usersStatus(`Added ${username}. They must change this password when ` +
                  'they first sign in.', 'var(--ok)');
    } catch (error) {
      usersStatus(error.message, 'var(--fail)');
    }
  }

  function pwStatus(message, colour) {
    const el = App.el('pw-status');
    el.textContent = message;
    el.style.color = colour || 'var(--faint)';
  }

  async function changePassword() {
    const current = App.el('pw-current').value;
    const next = App.el('pw-new').value;
    const repeat = App.el('pw-repeat').value;

    if (next !== repeat) return pwStatus('The two new passwords differ', 'var(--fail)');
    try {
      await App.post('/api/password', {
        current_password: current, new_password: next,
      });
      pwStatus('Changed. Signing you back in…', 'var(--ok)');
      // The change ends every session for this account, this one included.
      setTimeout(() => { window.location.href = '/login'; }, 1200);
    } catch (error) {
      pwStatus(error.message, 'var(--fail)');
    }
  }

  function forcePasswordChange() {
    App.selectTab('settings');
    App.modal('Change your password', `
      <p>This account is still using the password it was created with. Choose a
      new one before going any further.</p>
      <p class="hint">At least 12 characters. A short phrase is easier to
      remember and harder to guess than a mangled word.</p>`, [
      { label: 'Take me there', primary: true, onClick: () => {
        App.closeModal();
        App.el('pw-current').focus();
      } },
    ]);
  }

  function init() {
    App.el('pw-save').onclick = changePassword;
    App.el('add-user').onclick = addUser;
    App.el('new-password').onkeydown = (e) => { if (e.key === 'Enter') addUser(); };
    loadUsers().catch(() => {});
    for (const id of ['set-trace-cap', 'set-flow-cap', 'set-snmp-cap', 'set-syslog-cap',
                     'set-ipam-cap', 'set-nodes-cap', 'set-alerts-cap']) {
      App.el(id).oninput = () =>
        showUsage((App.state.serverState || {}).storage || {});
    }
    App.el('set-apply').onclick = apply;
    App.el('set-revert').onclick = load;
    App.el('update-now').onclick = checkForUpdate;
    for (const button of document.querySelectorAll('[data-maint]')) {
      button.onclick = () => maintenance(button.dataset.maint);
    }
    App.el('reset-layout').onclick = () => {
      App.resetLayout();
      status('Panel sizes reset', 'var(--muted)');
    };
    load();
  }

  App.pages.settings = {
    init,
    activate: () => { load(); loadUsers().catch(() => {}); },
    refresh: () => {},
    forcePasswordChange,
  };
})();

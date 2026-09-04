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
    App.el('set-refresh-dashboard').value = s.dashboard_refresh_s ?? 5;
    App.el('set-refresh-wireless').value = s.wireless_refresh_s ?? 2;
    App.el('set-refresh-configrx').value = s.configrx_refresh_s ?? 2;
    // Every time the interface shows is this browser's, and this is where
    // it says which zone that is.
    App.el('set-timezone').textContent =
      `Times everywhere in this interface are shown in this browser's zone: ${App.timeZoneLabel()}.`;
    App.el('set-trace-cap').value = s.max_trace_db_mb;
    App.el('set-flow-cap').value = s.max_flow_db_mb;
    App.el('set-snmp-cap').value = s.max_snmp_db_mb;
    App.el('set-syslog-cap').value = s.max_syslog_db_mb;
    App.el('set-ipam-cap').value = s.max_ipam_db_mb;
    App.el('set-nodes-cap').value = s.max_nodes_db_mb;
    App.el('set-alerts-cap').value = s.max_alerts_db_mb;
    App.el('set-idle-minutes').value = s.session_idle_minutes;
    App.el('set-session-hours').value = s.session_max_hours;

    // The four text/number fields below are ADMIN_ONLY_SETTINGS and so are
    // absent from `s` entirely for anyone without Settings read (see
    // SETTINGS_ONLY_KEYS in api.py) — App.el(...).value = undefined would
    // otherwise show "undefined" in the box rather than leaving it blank.
    App.el('set-ldap-enabled').checked = !!s.ldap_enabled;
    App.el('set-ldap-url').value = s.ldap_url || '';
    App.el('set-ldap-template').value = s.ldap_bind_dn_template || '';
    App.el('set-ldap-cleartext').checked = !!s.ldap_allow_cleartext;
    App.el('set-ldap-timeout').value = s.ldap_timeout_s ?? 10;

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
    status('Showing saved settings', 'var(--muted)');
  }

  /* --------------------------------------------------------------- update */

  function showUpdateInfo(server) {
    App.el('update-version').textContent = server.version ? `v${server.version}` : '';
    const commit = (server.update || {}).installed_commit;
    App.el('update-commit').textContent = commit ? commit.slice(0, 10) : 'unknown';
    App.el('set-updates-enabled').checked = !!(server.update || {}).enabled;
  }

  /* Saved on the spot rather than joining the Apply button's payload.
     updates_enabled is administrator-only, and post_settings refuses the
     whole request when a key like that is present without the grant — so
     folding it into `apply()` would have made Apply fail outright for
     anyone holding Settings write without Admin, for a setting they were
     not even trying to change. */
  async function setUpdatesEnabled() {
    const box = App.el('set-updates-enabled');
    const wanted = box.checked;
    try {
      await App.post('/api/settings',
                     { scope: 'global', values: { updates_enabled: wanted } });
      await App.loadState();
      updateStatus(wanted
        ? 'Updates from GitHub are allowed — this host will install the tip '
          + 'of main when the button below is pressed.'
        : 'Updates from GitHub are switched off; the button below will refuse.',
        wanted ? 'var(--warn)' : 'var(--ok)');
    } catch (error) {
      // Put the box back where it was: the setting did not change, and a
      // tick that stays ticked would say it did.
      box.checked = !wanted;
      updateStatus(error.message, 'var(--fail)');
    }
  }

  function updateStatus(message, colour) {
    const el = App.el('update-status');
    el.textContent = message;
    el.style.color = colour || 'var(--muted)';
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
      // No cap field backs this one — it's deliberately uncapped (see the
      // DATA FILES hint) — so it always renders with an empty bar and just
      // the byte count, the same way the loop below already renders any
      // row whose cap comes back 0.
      ['use-app', storage.app_bytes, 0],
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
        `<span class="meter"><i style="width:${share * 100}%"></i></span>` +
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
    el.style.color = colour || 'var(--muted)';
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
      dashboard_refresh_s: Number(App.el('set-refresh-dashboard').value),
      wireless_refresh_s: Number(App.el('set-refresh-wireless').value),
      configrx_refresh_s: Number(App.el('set-refresh-configrx').value),
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
    // The list used to name seven of the eleven refresh rates (IPAM had a
    // field and was left out; three had no field at all).
    status(`Applied · reverse DNS ${values.dns_enabled ? 'on' : 'off'} · ` +
           `eleven refresh rates · idle timeout ${values.session_idle_minutes} min`, 'var(--ok)');
  }

  /* What each maintenance action actually destroys. Several of these are
     not "prune old rows" despite the name — they delete the entire table,
     so the wording has to say so plainly before anyone clicks through. */
  const MAINTENANCE_WARNINGS = {
    redns: ['Re-run reverse DNS',
      'Discard every cached hostname and look them all up again?',
      'Names will be blank until each lookup completes.'],
    prune_traces: ['Delete old traces',
      'Delete stored traceroutes older than the trace retention period?',
      'Recent traces are kept. This cannot be undone.'],
    prune_flows: ['Delete stored flows',
      'Delete <b>every</b> stored NetFlow record?',
      'This is not a prune of old rows — it empties the flow database entirely, '
      + 'including today\'s. This cannot be undone.'],
    prune_snmp: ['Delete stored traps',
      'Delete <b>every</b> stored SNMP trap?',
      'This empties the trap database entirely, not just old rows. This cannot be undone.'],
    prune_syslog: ['Delete stored syslog',
      'Delete <b>every</b> stored syslog message?',
      'This empties the syslog database entirely, not just old rows. This cannot be undone.'],
    prune_nodes: ['Delete stored samples',
      'Delete <b>every</b> stored Nodes metric sample and device event?',
      'All history behind the device charts and timelines goes with it. The devices '
      + 'themselves stay. This cannot be undone.'],
    prune_alerts: ['Delete resolved alerts',
      'Delete every alert that has been resolved?',
      'Open and acknowledged alerts are kept. This cannot be undone.'],
    prune_configrx: ['Delete stored config backups',
      'Delete <b>every</b> stored device configuration backup?',
      'Every version of every device\'s config goes. This cannot be undone.'],
  };

  function confirmMaintenance(action) {
    const [title, question, note] = MAINTENANCE_WARNINGS[action]
      || ['Run maintenance', `Run "${escape(action)}"?`, 'This cannot be undone.'];
    App.confirmDestructive(title, `<p>${question}</p><p class="hint">${note}</p>`,
      'Continue', () => maintenance(action));
  }

  async function maintenance(action) {
    status('Working…', 'var(--muted)');
    const payload = await App.post('/api/maintenance', { action });
    await App.loadState();
    status(payload.message || '', 'var(--muted)');
    showUsage((App.state.serverState || {}).storage || {});
  }

  /* --------------------------------------------------------------- ldap */

  function ldapStatus(message, colour) {
    const el = App.el('ldap-status');
    el.textContent = message;
    el.style.color = colour || 'var(--muted)';
  }

  function ldapTestStatus(message, colour) {
    const el = App.el('ldap-test-status');
    el.textContent = message;
    el.style.color = colour || 'var(--muted)';
  }

  /* Its own save, the same way set-updates-enabled is its own save rather
     than joining the Apply button's payload: every key here is in
     ADMIN_ONLY_SETTINGS, and post_settings refuses the WHOLE request when
     an admin-only key is present without the admin grant — folding these
     into apply() would make Apply fail outright for a settings:write
     account changing an unrelated refresh rate, for keys it never touched. */
  async function applyLdapSettings() {
    const values = {
      ldap_enabled: App.el('set-ldap-enabled').checked,
      ldap_url: App.el('set-ldap-url').value.trim(),
      ldap_bind_dn_template: App.el('set-ldap-template').value.trim(),
      ldap_allow_cleartext: App.el('set-ldap-cleartext').checked,
      ldap_timeout_s: Number(App.el('set-ldap-timeout').value) || 10,
    };
    try {
      await App.post('/api/settings', { scope: 'global', values });
      await App.loadState();
      ldapStatus(`Saved — LDAP sign-in is ${values.ldap_enabled ? 'on' : 'off'}.`,
                 'var(--ok)');
    } catch (error) {
      ldapStatus(error.message, 'var(--fail)');
    }
  }

  /* A dry-run bind against whatever is in the fields right now (so it can
     be tried before Save is even pressed), or the saved settings for any
     field left blank. Creates no session and stores nothing. */
  async function testLdap() {
    const username = App.el('ldap-test-username').value.trim();
    const password = App.el('ldap-test-password').value;
    if (!username || !password) {
      ldapTestStatus('Enter a test username and password first', 'var(--fail)');
      return;
    }
    ldapTestStatus('Testing…', 'var(--muted)');
    try {
      const result = await App.post('/api/settings/ldap-test', {
        username, password,
        url: App.el('set-ldap-url').value.trim(),
        bind_dn_template: App.el('set-ldap-template').value.trim(),
        allow_cleartext: App.el('set-ldap-cleartext').checked,
      });
      ldapTestStatus(result.message, result.ok ? 'var(--ok)' : 'var(--fail)');
    } catch (error) {
      ldapTestStatus(error.message, 'var(--fail)');
    } finally {
      App.el('ldap-test-password').value = '';
    }
  }

  /* ------------------------------------------------------------- tokens */

  function tokensStatus(message, colour) {
    const el = App.el('tokens-status');
    el.textContent = message;
    el.style.color = colour || 'var(--muted)';
  }

  function tokensVisible() {
    return App.canWrite('admin');
  }

  async function loadTokens() {
    const table = App.el('tokens-table');
    if (!table) return;
    if (!tokensVisible()) {
      table.innerHTML = '<caption class="sr-only">API tokens</caption>' +
        '<tbody><tr><td class="hint">API tokens need administrator access. ' +
        'Ask an administrator if you need one issued.</td></tr></tbody>';
      return;
    }
    const payload = await App.get('/api/tokens');
    table.innerHTML = '<caption class="sr-only">API tokens</caption><thead><tr>' +
      '<th scope="col">Account</th><th scope="col">Label</th>' +
      '<th scope="col">Created</th><th scope="col">Expires</th>' +
      '<th scope="col">Last used</th><th scope="col"></th></tr></thead>';
    const body = document.createElement('tbody');
    for (const token of (payload.tokens || [])) {
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${escape(token.username)}</td>` +
        `<td>${escape(token.label)}</td>` +
        `<td>${when(token.created)}</td>` +
        `<td>${token.expires ? when(token.expires) : 'never'}</td>` +
        `<td>${token.last_used ? when(token.last_used) : 'never'}</td>` +
        '<td></td>';
      const revoke = document.createElement('button');
      revoke.textContent = 'Revoke';
      revoke.onclick = () => confirmRevokeToken(token);
      tr.lastElementChild.appendChild(revoke);
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  function confirmRevokeToken(token) {
    App.confirmDestructive('Revoke token',
      `<p>Revoke the token <b>${escape(token.label)}</b> for ` +
      `<b>${escape(token.username)}</b>? Anything using it is refused on its ` +
      'very next request. This cannot be undone.</p>',
      'Revoke',
      () => App.del('/api/tokens', { id: token.id }),
      async (confirmed) => {
        if (!confirmed) return;
        await loadTokens();
        tokensStatus(`Revoked ${token.label}`, 'var(--muted)');
      });
  }

  /* The plaintext token is in THIS response only — the server never keeps
     it and never sends it again, so it is shown once, with a copy button
     and an explicit warning, and dropped the moment the dialog closes. */
  function showNewToken(payload) {
    App.modal('Token created', `
      <p class="hint warn-text">This is the only time this token is shown. Copy it now — it
        cannot be displayed again, and there is no way to recover it if lost. If it is lost,
        revoke it and issue a new one.</p>
      <p><code style="word-break:break-all" id="new-token-value">${escape(payload.token)}</code></p>
      <p class="hint">For account <b>${escape(payload.username)}</b>, labelled
        “${escape(payload.label)}”. Send it as
        <code>Authorization: Bearer ${escape(payload.token)}</code>.</p>`, [
      { label: 'Copy token', onClick: () => {
        navigator.clipboard.writeText(payload.token).catch(() => {});
      } },
      { label: 'Done', primary: true, onClick: App.closeModal },
    ]);
  }

  async function addToken() {
    const username = App.el('new-token-username').value.trim();
    const label = App.el('new-token-label').value.trim();
    const expiresRaw = App.el('new-token-expires').value.trim();
    const body = { username, label };
    if (expiresRaw) body.expires_days = Number(expiresRaw);
    try {
      const payload = await App.post('/api/tokens', body);
      App.el('new-token-username').value = '';
      App.el('new-token-label').value = '';
      App.el('new-token-expires').value = '';
      await loadTokens();
      tokensStatus(`Created ${label} for ${username}`, 'var(--ok)');
      showNewToken(payload);
    } catch (error) {
      tokensStatus(error.message, 'var(--fail)');
    }
  }

  /* ------------------------------------------------------------- users */

  // One implementation, in app.js. This was twelve copies of the same
  // three lines, which is how one of them came to be missing a
  // character while the others were not.
  const escape = App.escapeHtml;

  const when = App.when;

  let modules = [];

  /* One row per module, three radios each (none/read/write) — write
     implies read, so picking write doesn't need a separate read tick. */
  function permissionGridHtml(idPrefix, grants) {
    const rows = modules.map((m) => {
      const level = grants[m] || 'none';
      const radio = (value, label) =>
        `<label class="check"><input type="radio" name="${idPrefix}-${m}" value="${value}"
          ${level === value ? 'checked' : ''}> ${label}</label>`;
      return `<tr><td>${escape(m)}</td>` +
        `<td>${radio('none', 'None')}</td>` +
        `<td>${radio('read', 'Read')}</td>` +
        `<td>${radio('write', 'Write')}</td></tr>`;
    }).join('');
    return `<table><caption class="sr-only">Module permissions</caption><thead><tr><th scope="col">Module</th><th scope="col"></th><th scope="col"></th><th scope="col"></th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  function readPermissionGrid(box, idPrefix) {
    const grants = {};
    for (const m of modules) {
      const checked = box.querySelector(`input[name="${idPrefix}-${m}"]:checked`);
      const value = checked ? checked.value : 'none';
      if (value !== 'none') grants[m] = value;
    }
    return grants;
  }

  function editPermissions(user) {
    const box = App.modal(`Permissions for ${user.username}`,
      permissionGridHtml('ep', user.permissions || {}), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async () => {
        try {
          await App.post('/api/users/permissions',
            { username: user.username, grants: readPermissionGrid(box, 'ep') });
          App.closeModal();
          await loadUsers();
          usersStatus(`Updated permissions for ${user.username}`, 'var(--ok)');
        } catch (error) {
          usersStatus(error.message, 'var(--fail)');
        }
      } },
    ]);
  }

  /* The accounts grid is behind settings:write on the server, so a
     read-only account asking for it got a 403 every time Settings was
     opened — and an empty table with no explanation. Ask only when the
     grant is there, and say why when it is not. */
  function usersVisible() {
    return App.canWrite('settings');
  }

  async function loadUsers() {
    if (!usersVisible()) {
      const table = App.el('users-table');
      if (table) {
        table.innerHTML = '<caption class="sr-only">User accounts</caption>' +
          '<tbody><tr><td class="hint">Managing accounts needs Settings ' +
          'write access. Ask an administrator if you need it.</td></tr></tbody>';
      }
      const grid = App.el('new-user-grid');
      if (grid) grid.innerHTML = '';
      return;
    }
    const payload = await App.get('/api/users');
    modules = payload.modules || [];
    App.el('new-user-grid').innerHTML = permissionGridHtml('nu', {});
    const table = App.el('users-table');
    const me = (App.state.session || {}).username;
    table.innerHTML = '<caption class="sr-only">User accounts</caption><thead><tr>' +
      '<th scope="col">User</th><th scope="col">Created</th>' +
      '<th scope="col">Last sign-in</th><th scope="col">State</th><th scope="col"></th></tr></thead>';
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
      const edit = document.createElement('button');
      edit.textContent = 'Permissions';
      edit.onclick = () => editPermissions(user);
      tr.lastElementChild.appendChild(edit);
      if (!isMe) {
        const remove = document.createElement('button');
        remove.textContent = 'Remove';
        remove.onclick = () => confirmRemove(user.username);
        tr.lastElementChild.appendChild(remove);
      }
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.wireRowKeyboard(body);

    const sessions = payload.sessions || [];
    App.el('sessions-line').textContent = sessions.length
      ? `${sessions.length} active session(s): ` + sessions
        .map((s) => `${s.username} from ${s.client} (idle ${Math.round(s.idle_s)}s)`)
        .join(', ')
      : 'No active sessions.';
  }

  function confirmRemove(username) {
    // A refusal — the last administrator, an account that has gone since
    // the page was drawn — used to close the dialog and leave the reason on
    // the page behind it. It now stays where it was asked.
    App.confirmDestructive('Remove user',
      `<p>Remove <b>${escape(username)}</b>? Any session they have open ends ` +
      'immediately.</p>',
      'Remove',
      () => App.del('/api/users', { username }),
      async (confirmed) => {
        if (!confirmed) return;
        await loadUsers();
        usersStatus(`Removed ${username}`, 'var(--muted)');
      });
  }

  function usersStatus(message, colour) {
    const el = App.el('users-status');
    el.textContent = message;
    el.style.color = colour || 'var(--muted)';
  }

  /* 'local' or 'ldap' — whichever radio in the auth-source pair is checked. */
  function newAuthSource() {
    return App.el('new-auth-ldap').checked ? 'ldap' : 'local';
  }

  /* An LDAP account has no local password at all, so the initial-password
     field means nothing for one — disabled (not merely ignored) so it
     cannot look like it did something. */
  function updateNewAuthFields() {
    const ldap = newAuthSource() === 'ldap';
    App.el('new-password').disabled = ldap;
    App.el('new-password').placeholder = ldap
      ? 'not used — verified by the directory' : 'initial password';
    if (ldap) App.el('new-password').value = '';
  }

  async function addUser() {
    const username = App.el('new-username').value.trim();
    const authSource = newAuthSource();
    const password = App.el('new-password').value;
    const grid = App.el('new-user-grid');
    const grants = readPermissionGrid(grid, 'nu');
    try {
      await App.post('/api/users',
        { username, password, auth_source: authSource, grants });
      App.el('new-username').value = '';
      App.el('new-password').value = '';
      App.el('new-auth-local').checked = true;
      updateNewAuthFields();
      await loadUsers();
      usersStatus(authSource === 'ldap'
        ? `Added ${username}, signing in via the directory.`
        : `Added ${username}. They must change this password when they ` +
          'first sign in.', 'var(--ok)');
    } catch (error) {
      usersStatus(error.message, 'var(--fail)');
    }
  }

  function forcePasswordChange() {
    App.accountModal(true);
  }

  function init() {
    App.el('add-user').onclick = addUser;
    App.el('new-password').onkeydown = (e) => { if (e.key === 'Enter') addUser(); };
    App.el('new-auth-local').onchange = updateNewAuthFields;
    App.el('new-auth-ldap').onchange = updateNewAuthFields;
    updateNewAuthFields();
    loadUsers().catch(() => {});
    loadTokens().catch(() => {});
    App.el('add-token').onclick = addToken;
    App.el('ldap-apply').onclick = applyLdapSettings;
    App.el('ldap-test').onclick = testLdap;
    for (const id of ['set-trace-cap', 'set-flow-cap', 'set-snmp-cap', 'set-syslog-cap',
                     'set-ipam-cap', 'set-nodes-cap', 'set-alerts-cap']) {
      App.el(id).oninput = () =>
        showUsage((App.state.serverState || {}).storage || {});
    }
    App.el('set-apply').onclick = apply;
    // Client state: applied on change, stored per browser, never sent.
    const theme = App.el('set-theme');
    theme.value = App.currentTheme();
    theme.onchange = () => {
      App.setTheme(theme.value);
      App.announce(`Theme: ${theme.options[theme.selectedIndex].text}`);
    };
    App.el('set-revert').onclick = load;
    App.el('update-now').onclick = checkForUpdate;
    App.el('set-updates-enabled').onchange = setUpdatesEnabled;
    for (const button of document.querySelectorAll('[data-maint]')) {
      button.onclick = () => confirmMaintenance(button.dataset.maint);
    }
    App.el('reset-layout').onclick = () => {
      App.resetLayout();
      status('Panel sizes reset', 'var(--muted)');
    };
    load();
  }

  App.pages.settings = {
    init,
    activate: () => { load(); loadUsers().catch(() => {}); loadTokens().catch(() => {}); },
    refresh: () => {},
    forcePasswordChange,
  };
})();

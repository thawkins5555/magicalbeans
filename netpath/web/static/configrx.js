/* The ConfigRX page: a searchable device list (sourced from Nodes' own
   devices — ConfigRX has no device table of its own), each row's stored
   backups, and a read-only viewer for one backup's config text. There is
   no editable field or save-back action anywhere on this page — that is
   a hard design boundary, not an oversight: this module only ever pulls
   a config, never pushes one. */
(() => {
  const view = {
    devices: [],
    selectedDeviceId: null,
    backups: [],
    selectedBackupId: null,
    backupContent: '',
  };

  const escape = (s) => String(s ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function ago(ts) {
    if (!ts) return 'never';
    const age = Date.now() / 1000 - ts;
    if (age < 5) return 'just now';
    if (age < 90) return `${Math.round(age)}s ago`;
    if (age < 5400) return `${Math.round(age / 60)}m ago`;
    if (age < 172800) return `${(age / 3600).toFixed(1)}h ago`;
    return `${(age / 86400).toFixed(1)}d ago`;
  }

  function bytesText(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  const STATUS_COLOR = { changed: 'var(--ok)', unchanged: 'var(--accent)',
    error: 'var(--fail)' };

  function statusDot(status) {
    // last_backup_status can carry a trailing host-key note, e.g.
    // "changed (host key not previously known)" — only the leading word
    // decides the color.
    const key = (status || '').split(' ')[0];
    const color = STATUS_COLOR[key] || 'var(--faint)';
    return `<span class="dot" style="background:${color};display:inline-block;` +
      `width:8px;height:8px;border-radius:50%;margin-right:6px"></span>`;
  }

  /* ------------------------------------------------------------ status */

  function drawStatus() {
    const server = App.state.serverState || {};
    const worker = server.configrx || { counters: {} };
    App.el('cx-status').textContent = worker.status || 'Worker stopped';
    App.el('cx-dot').style.background = worker.running ? 'var(--ok)' : 'var(--faint)';
    App.el('cx-toggle').textContent = worker.running ? 'Stop worker' : 'Start worker';
    const c = worker.counters || {};
    const parts = [`${c.backups || 0} backup(s) run`, `${c.changed || 0} changed`,
      `${c.unchanged || 0} unchanged`, `${c.errors || 0} errors`];
    App.el('cx-counters').textContent = parts.join(' · ');
  }

  /* ------------------------------------------------------------- devices */

  const COLUMNS = [
    { key: 'backup_enabled', label: '', width: 28 },
    { key: 'name', label: 'Device', width: 220 },
    { key: 'vendor', label: 'Vendor', width: 110 },
    { key: 'last_backup_status', label: 'Last backup', width: 110 },
    { key: 'last_backup_ts', label: 'When', width: 100, numeric: true,
      value: (r) => r.last_backup_ts || 0 },
  ];

  function drawDevices() {
    const table = App.grid(App.el('cx-devices'), { name: 'configrx-devices', columns: COLUMNS });
    const body = document.createElement('tbody');
    for (const row of view.devices) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (view.selectedDeviceId === row.id ? ' selected' : '');
      const status = row.last_backup_error
        ? `<span title="${escape(row.last_backup_error)}">error</span>`
        : escape(row.last_backup_status || (row.backup_enabled ? 'pending' : '—'));
      tr.innerHTML =
        `<td>${row.backup_enabled ? statusDot(row.last_backup_status) : ''}</td>` +
        `<td>${escape(row.name)}<div class="hint">${escape(row.ip)}</div></td>` +
        `<td>${escape(row.vendor || '—')}</td>` +
        `<td>${status}</td>` +
        `<td>${ago(row.last_backup_ts)}</td>`;
      tr.onclick = () => selectDevice(row.id);
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('cx-device-count').textContent = `${view.devices.length} device(s)`;
  }

  async function selectDevice(deviceId) {
    view.selectedDeviceId = deviceId;
    view.selectedBackupId = null;
    view.backupContent = '';
    drawDevices();
    drawViewer();
    const result = await App.get(`/api/configrx/devices/${deviceId}/backups`, {});
    view.backups = result.backups;
    drawBackups();
  }

  /* ------------------------------------------------------------- backups */

  function drawBackups() {
    const list = App.el('cx-backup-list');
    list.innerHTML = '';
    const device = view.devices.find((d) => d.id === view.selectedDeviceId);
    App.el('cx-backup-header').textContent = device
      ? `BACKUPS — ${device.name}` : 'BACKUPS';
    App.el('cx-backup-now').hidden = !device || !device.backup_enabled;
    App.el('cx-device-settings').hidden = !device;
    if (!view.backups.length) {
      list.innerHTML = '<div class="hint" style="padding:8px">No backups stored yet.</div>';
      return;
    }
    for (const backup of view.backups) {
      const row = document.createElement('div');
      row.className = 'clickable-row' + (view.selectedBackupId === backup.id ? ' selected' : '');
      row.style.cssText = 'padding:6px 8px;cursor:pointer;border-bottom:1px solid var(--hairline)';
      if (view.selectedBackupId === backup.id) row.style.background = 'var(--panel)';
      row.innerHTML = `<div>${new Date(backup.ts * 1000).toLocaleString()}</div>` +
        `<div class="hint">${bytesText(backup.size_bytes)} · ${backup.sha256.slice(0, 12)}</div>`;
      row.onclick = () => selectBackup(backup.id);
      list.appendChild(row);
    }
  }

  async function selectBackup(backupId) {
    view.selectedBackupId = backupId;
    drawBackups();
    const result = await App.get(`/api/configrx/backups/${backupId}`, {});
    view.backupContent = result.content || '';
    drawViewer();
  }

  function drawViewer() {
    App.el('cx-viewer').textContent = view.backupContent
      || (view.selectedDeviceId
        ? 'Select a backup on the left to view its stored config.'
        : 'Select a device to see its stored backups.');
  }

  /* --------------------------------------------------------- device config */

  function deviceSettingsModal() {
    const device = view.devices.find((d) => d.id === view.selectedDeviceId);
    if (!device) return;
    App.modal(`ConfigRX settings: ${device.name}`, `
      <fieldset><legend>BACKUP</legend>
        <label class="check"><input type="checkbox" id="cx-enabled"
          ${device.backup_enabled ? 'checked' : ''}> Back up this device</label>
        <label>Vendor override <input id="cx-vendor" value="${escape(device.vendor_override)}"
          placeholder="${escape(device.vendor || 'auto-detected from Nodes')}"></label>
        <p class="hint">Leave blank to use the vendor Nodes already detected over SNMP.
          Set this only when that is wrong or unset. Recognized values: cisco, fortinet,
          juniper, mikrotik, hp, aruba.</p>
      </fieldset>
      <fieldset><legend>SSH CREDENTIAL</legend>
        <label>Port <input id="cx-port" type="number" min="1" max="65535"
          value="${device.ssh_port}"></label>
        <label>Username <input id="cx-username" value="${escape(device.ssh_username)}"></label>
        <label>Password <input id="cx-password" type="password"
          placeholder="${device.has_credential ? 'stored — leave blank to keep' : ''}"></label>
        <p class="hint">Stored encrypted; never shown again once saved. ConfigRX only ever
          runs one fixed, read-only "show config" command for this device's vendor — there
          is no way to run any other command from here.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        await App.post(`/api/configrx/devices/${device.id}/config`, {
          backup_enabled: m.querySelector('#cx-enabled').checked,
          ssh_port: Number(m.querySelector('#cx-port').value),
          ssh_username: m.querySelector('#cx-username').value.trim(),
          vendor_override: m.querySelector('#cx-vendor').value.trim(),
        });
        const password = m.querySelector('#cx-password').value;
        const username = m.querySelector('#cx-username').value.trim();
        if (password && username) {
          await App.post(`/api/configrx/devices/${device.id}/credential`, {
            ssh_username: username, ssh_password: password,
          });
        }
        App.closeModal();
        await App.refreshNow('configrx');
      } },
    ]);
  }

  /* ---------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.configrxSettings || {};
    App.modal('ConfigRX settings', `
      <fieldset><legend>SCHEDULE</legend>
        <label class="check"><input type="checkbox" id="cxs-enabled"
          ${s.enabled ? 'checked' : ''}> Run the backup worker</label>
        <label>Backup interval (hours) <input id="cxs-interval" type="number" min="1"
          value="${s.backup_interval_hours}"></label>
      </fieldset>
      <fieldset><legend>RETENTION</legend>
        <label>Keep backups for (days) <input id="cxs-days" type="number" min="0"
          value="${s.retention_days}"></label>
        <label>Keep at most (per device) <input id="cxs-count" type="number" min="0"
          value="${s.retention_count_per_device}"></label>
        <p class="hint">An unchanged config never creates a new stored backup, so a
          device that never changes stays at one row regardless of these caps.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        await App.post('/api/settings', { scope: 'configrx', values: {
          enabled: m.querySelector('#cxs-enabled').checked,
          backup_interval_hours: Number(m.querySelector('#cxs-interval').value),
          retention_days: Number(m.querySelector('#cxs-days').value),
          retention_count_per_device: Number(m.querySelector('#cxs-count').value),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('configrx');
      } },
    ]);
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'configrx') return;
    drawStatus();
    const params = { q: App.el('cx-q').value.trim() };
    if (App.el('cx-enabled-only').checked) params.enabled_only = 1;
    const result = await App.get('/api/configrx/devices', params);
    view.devices = result.devices;
    drawDevices();
    drawBackups();
  }

  function init() {
    App.el('cx-apply').onclick = () => App.refreshNow('configrx');
    App.el('cx-q').onkeydown = (event) => {
      if (event.key === 'Enter') App.refreshNow('configrx');
    };
    App.el('cx-enabled-only').onchange = () => App.refreshNow('configrx');
    App.el('cx-settings').onclick = settingsDialog;
    App.el('cx-device-settings').onclick = deviceSettingsModal;
    App.el('cx-backup-now').onclick = async () => {
      if (!view.selectedDeviceId) return;
      await App.post(`/api/configrx/devices/${view.selectedDeviceId}/backup`, {});
      App.el('cx-backup-now').textContent = 'Queued…';
      setTimeout(() => { App.el('cx-backup-now').textContent = 'Back up now'; }, 3000);
    };
    App.el('cx-toggle').onclick = async () => {
      const running = (App.state.serverState.configrx || {}).running;
      await App.post('/api/configrx/worker', { action: running ? 'stop' : 'start' });
      await App.loadState();
      App.refreshNow('configrx');
    };
  }

  App.pages.configrx = { init, refresh, fastTick: drawStatus };
})();

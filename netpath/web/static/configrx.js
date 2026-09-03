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
    devicesChecked: new Set(),
    deviceSort: { key: 'name', descending: false },
    backups: [],
    backupsChecked: new Set(),
    backupSort: { key: 'ts', descending: true },
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
  /* Backup outcomes mapped onto the tones App.statusMark draws. "changed"
     is information rather than health — a device whose config differs from
     the last copy is working exactly as intended — so it takes the info
     tone and its own shape, instead of the green that means "up" on every
     other page in the product. */
  const STATUS_TONE = { changed: 'info', unchanged: 'ok', error: 'fail' };

  function statusDot(status) {
    // last_backup_status can carry a trailing host-key note, e.g.
    // "changed (host key not previously known)" — only the leading word
    // decides the color.
    const key = (status || '').split(' ')[0];
    // This column is 28px of icon with no header — the word itself is in
    // the "Last backup" column beside it — so the mark carries a name of
    // its own rather than being decorative.
    return App.statusMark(STATUS_TONE[key] || 'none', '', status || 'not backed up yet');
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
    // Which paramiko this process actually loaded belongs on the strip, not
    // only in a failed connection's error text: "I installed 3.4 and it still
    // says 5.0" is a question the status line should answer at a glance.
    const ssh = worker.ssh || {};
    if (ssh.paramiko) {
      parts.push(`paramiko ${ssh.paramiko.split(' (')[0]}`);
      if (ssh.legacy_implemented === false) parts.push('no SHA-1 key exchange');
      else if (ssh.legacy_offered === false) parts.push('legacy SSH off');
    }
    App.el('cx-counters').textContent = parts.join(' · ');
  }

  /* ------------------------------------------------------------- devices */

  const COLUMNS = [
    { key: 'check', label: '', sortable: false, fixed: true, width: 34,
      // See the Nodes device list.
      cell: (r) => `<input type="checkbox" class="cx-check" aria-label="Select ${
        escape(r.name || r.ip || 'device')}"${
        view.devicesChecked.has(r.id) ? ' checked' : ''}>` },
    { key: 'backup_enabled', label: '', width: 28, on: true, sortable: false,
      cell: (r) => (r.backup_enabled ? statusDot(r.last_backup_status) : '') },
    { key: 'name', label: 'Device', width: 220, on: true,
      cell: (r) => `${escape(r.name)}<div class="hint">${escape(r.ip)}</div>` },
    // The vendor the backup would actually RUN as, not the one Nodes
    // detected: an explicit per-device override wins, and the column marks
    // it so the list and the worker cannot silently disagree.
    { key: 'vendor', label: 'Vendor', width: 130, on: true,
      value: (r) => r.effective_vendor || '',
      cell: (r) => escape(r.effective_vendor || '\u2014')
        + (r.vendor_is_override ? ' <span class="hint">(override)</span>' : '') },
    { key: 'last_backup_status', label: 'Last backup', width: 110, on: true,
      // An in-flight backup wins over the last completed one: the row used to
      // sit on a stale "unchanged" for the whole minute a backup was running.
      cell: (r) => (r.backing_up ? '<span class="hint">backing up…</span>'
        : r.backup_queued ? '<span class="hint">queued…</span>'
        : r.last_backup_error
          ? `<span title="${escape(r.last_backup_error)}">error</span>`
          : escape(r.last_backup_status || (r.backup_enabled ? 'pending' : '\u2014'))) },
    { key: 'last_backup_ts', label: 'When', width: 100, numeric: true, on: true,
      value: (r) => r.last_backup_ts || 0, cell: (r) => ago(r.last_backup_ts) },
    { key: 'detected_vendor', label: 'Detected vendor', width: 130,
      value: (r) => r.vendor || '', cell: (r) => escape(r.vendor || '\u2014') },
    { key: 'ssh_username', label: 'SSH user', width: 120,
      cell: (r) => escape(r.ssh_username || '\u2014') },
    { key: 'ssh_port', label: 'Port', width: 70, numeric: true },
    { key: 'has_credential', label: 'Credential', width: 90,
      value: (r) => (r.has_credential ? 1 : 0),
      cell: (r) => (r.has_credential ? 'stored' : '\u2014') },
  ];

  const deviceColumns = () => App.visibleColumns(
    COLUMNS, (App.state.configrxSettings || {}).table_columns);

  function onDeviceSort(key, descending) {
    view.deviceSort = { key, descending };
    drawDevices();
  }

  function drawDevices() {
    const columns = deviceColumns();
    const checked = view.devicesChecked;
    const table = App.grid(App.el('cx-devices'), {
      name: 'configrx-devices', columns,
      sort: view.deviceSort, onSort: onDeviceSort,
      selectAll: {
        key: 'check',
        checked: view.devices.length > 0 && view.devices.every((d) => checked.has(d.id)),
        some: view.devices.some((d) => checked.has(d.id)),
        onToggle: (on) => {
          checked.clear();
          if (on) for (const d of view.devices) checked.add(d.id);
          drawDevices();
        },
      } });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.devices, view.deviceSort.key,
                              view.deviceSort.descending, columns);
    App.drawRows(body, rows, columns, (tr, row) => {
      tr.className = 'clickable'
        + (view.selectedDeviceId === row.id ? ' selected' : '')
        + (view.devicesChecked.has(row.id) ? ' bulk-checked' : '');
      // The checkbox owns selection; the rest of the row owns the detail
      // pane — same convention as Nodes' and Alerts' own tables.
      const box = tr.querySelector('.cx-check');
      if (box) {
        box.onclick = (event) => {
          event.stopPropagation();
          toggleChecked(row.id, tr);
        };
      }
      tr.onclick = () => selectDevice(row.id);
    });
    table.appendChild(body);
    App.wireRowKeyboard(body);
    App.el('cx-device-count').textContent = `${view.devices.length} device(s)`;
    drawBulkBar();
  }

  /* ------------------------------------------------------- bulk actions */

  /* Given the row, only that row is touched: redrawing the whole table to
     change one checkbox is what made picking several devices feel slow. */
  function toggleChecked(id, tr) {
    const on = !view.devicesChecked.has(id);
    if (on) view.devicesChecked.add(id);
    else view.devicesChecked.delete(id);
    if (tr) {
      tr.classList.toggle('bulk-checked', on);
      const box = tr.querySelector('.cx-check');
      if (box) box.checked = on;
      App.refreshSelectAll(App.el('cx-devices'), view.devices.length,
                           view.devicesChecked.size);
      drawBulkBar();
      return;
    }
    drawDevices();
  }


  function bulkClearSelection() {
    view.devicesChecked.clear();
    drawDevices();
  }

  function drawBulkBar() {
    const n = view.devicesChecked.size;
    App.el('cx-bulk-bar').hidden = n === 0;
    if (n) App.el('cx-bulk-count').textContent = `${n} selected`;
  }

  /* Everything the single-device settings dialog covers, applied to every
     ticked device at once. Supersedes the credential-only bulk dialog: an
     operator setting up a batch of switches needs the vendor override and
     the enabled flag as much as the login, and two dialogs that overlap by
     three fields is how they drift apart.

     Every field is opt-in — a select or a blank box that means "leave this
     alone" — because a bulk form whose defaults silently rewrite settings
     you did not come here to change is a trap. backup_enabled in particular
     is a real tri-state now: the old dialog could only ever turn it ON. */
  function bulkSettings() {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    App.modal(`ConfigRX settings for ${ids.length} device(s)`, `
      <p class="hint">Only the fields you set are changed. Leave a box blank
        or a dropdown on <b>Leave unchanged</b> and those devices keep what
        they have.</p>
      <fieldset><legend>BACKUP</legend>
        <label>Back up these devices <select id="cx-bulk-enabled">
          <option value="">Leave unchanged</option>
          <option value="1">Yes — back them up</option>
          <option value="0">No — stop backing them up</option>
        </select></label>
        <label>Vendor override <input id="cx-bulk-vendor"
          placeholder="leave blank to leave unchanged"></label>
        <p class="hint">Recognized values: cisco, fortinet, juniper, mikrotik,
          hp, aruba. Setting this replaces whatever each device had; to clear
          it back to the vendor Nodes detected, use the single-device dialog.</p>
      </fieldset>
      <fieldset><legend>SSH CREDENTIAL</legend>
        <label>Port <input id="cx-bulk-port" type="number" min="1" max="65535"
          placeholder="leave blank to leave unchanged"></label>
        <label>Username <input id="cx-bulk-username"
          placeholder="leave blank to leave unchanged"></label>
        <label>Password <input id="cx-bulk-password" type="password"
          placeholder="leave blank to keep each device's own"></label>
        <p class="hint">A password is stored only when a username is given with
          it — the pair is what gets encrypted, and half of one would lock the
          batch out. Stored encrypted and never shown again.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        const username = m.querySelector('#cx-bulk-username').value.trim();
        const password = m.querySelector('#cx-bulk-password').value;
        const enabled = m.querySelector('#cx-bulk-enabled').value;
        const vendor = m.querySelector('#cx-bulk-vendor').value.trim();
        const port = m.querySelector('#cx-bulk-port').value.trim();
        if (password && !username) {
          alert('A username is required with a password.');
          return;
        }
        const fields = { device_ids: ids };
        if (enabled !== '') fields.backup_enabled = enabled === '1';
        if (vendor) fields.vendor_override = vendor;
        if (port) fields.ssh_port = Number(port);
        if (username) fields.ssh_username = username;
        // The credential POST encrypts the pair; the config POST stores the
        // rest. Both are optional, so a dialog where nothing was filled in
        // changes nothing rather than erroring.
        if (username && password) {
          await App.post('/api/configrx/devices/bulk-credential',
            { device_ids: ids, ssh_username: username, ssh_password: password });
        }
        if (Object.keys(fields).length > 1) {
          await App.post('/api/configrx/devices/bulk-config', fields);
        }
        App.closeModal();
        view.devicesChecked.clear();
        await App.refreshNow('configrx');
      } },
    ]);
  }

  /* Back up every ticked device now. Settles off the POST result rather
     than watching, the way Nodes' bulk Poll now does: the device rows
     already carry backing_up/backup_queued, so the list itself shows
     progress and a second watch loop would only duplicate it. */
  async function bulkBackupNow() {
    const ids = [...view.devicesChecked];
    if (!ids.length) return;
    const button = App.el('cx-bulk-backup');
    if (button.disabled) return;
    const settle = (text) => {
      button.disabled = false;
      button.textContent = text;
      if (text !== 'Back up selected') {
        setTimeout(() => {
          if (button.textContent === text) button.textContent = 'Back up selected';
        }, 4000);
      }
    };
    button.disabled = true;
    button.textContent = 'Queueing…';
    let result;
    try {
      result = await App.post('/api/configrx/devices/bulk-backup',
                              { device_ids: ids });
    } catch (error) {
      // The worker being stopped is one fact about the server, and the API
      // says it once for the whole request rather than per device.
      settle('Failed');
      alert(error.message);
      return;
    }
    const queued = (result.queued || []).length;
    const busy = (result.already_queued || []).length;
    const off = (result.not_enabled || []).length;
    const parts = [];
    if (queued) parts.push(`${queued} queued`);
    if (busy) parts.push(`${busy} already queued`);
    if (off) parts.push(`${off} not enabled`);
    settle(parts.length ? parts.join(', ') : 'Nothing to back up');
    await App.refreshNow('configrx');
  }

  async function selectDevice(deviceId) {
    // Moving to another device drops the backup selection with it — a bulk
    // delete must never act on rows that belong to the device you left.
    if (view.selectedDeviceId !== deviceId) view.backupsChecked.clear();
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

  const BACKUP_COLUMNS = [
    { key: 'check', label: '', sortable: false, fixed: true, width: 30,
      cell: (r) => `<input type="checkbox" class="cx-bcheck"${
        view.backupsChecked.has(r.id) ? ' checked' : ''}>` },
    { key: 'ts', label: 'Taken', width: 150, numeric: true, on: true,
      align: 'left', descendingFirst: true,
      cell: (r) => escape(new Date(r.ts * 1000).toLocaleString()) },
    { key: 'size_bytes', label: 'Size', width: 80, numeric: true, on: true,
      cell: (r) => bytesText(r.size_bytes) },
    { key: 'sha256', label: 'Digest', width: 110,
      cell: (r) => escape(r.sha256.slice(0, 12)) },
  ];

  const backupColumns = () => App.visibleColumns(
    BACKUP_COLUMNS, (App.state.configrxSettings || {}).table_columns_backups);

  function onBackupSort(key, descending) {
    view.backupSort = { key, descending };
    drawBackups();
  }

  function drawBackups() {
    const device = view.devices.find((d) => d.id === view.selectedDeviceId);
    App.el('cx-backup-header').textContent = device
      ? `BACKUPS \u2014 ${device.name}` : 'BACKUPS';
    App.el('cx-backup-now').hidden = !device || !device.backup_enabled;
    App.el('cx-device-settings').hidden = !device;
    const empty = App.el('cx-backup-empty');
    const wrap = App.el('cx-backup-wrap');
    if (!view.backups.length) {
      empty.hidden = false;
      wrap.hidden = true;
      App.el('cx-backup-bulk').hidden = true;
      return;
    }
    empty.hidden = true;
    wrap.hidden = false;
    const columns = backupColumns();
    const checked = view.backupsChecked;
    const table = App.grid(App.el('cx-backups'), {
      name: 'configrx-backups', columns,
      sort: view.backupSort, onSort: onBackupSort,
      selectAll: {
        key: 'check',
        checked: view.backups.every((b) => checked.has(b.id)),
        some: view.backups.some((b) => checked.has(b.id)),
        onToggle: (on) => {
          checked.clear();
          if (on) for (const b of view.backups) checked.add(b.id);
          drawBackups();
        },
      } });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.backups, view.backupSort.key,
                              view.backupSort.descending, columns);
    App.drawRows(body, rows, columns, (tr, row) => {
      tr.className = 'clickable'
        + (view.selectedBackupId === row.id ? ' selected' : '')
        + (checked.has(row.id) ? ' bulk-checked' : '');
      const box = tr.querySelector('.cx-bcheck');
      if (box) {
        box.onclick = (event) => {
          event.stopPropagation();
          if (checked.has(row.id)) checked.delete(row.id);
          else checked.add(row.id);
          tr.classList.toggle('bulk-checked', checked.has(row.id));
          box.checked = checked.has(row.id);
          App.refreshSelectAll(App.el('cx-backups'), view.backups.length,
                               checked.size);
          drawBackupBulkBar();
        };
      }
      tr.onclick = () => selectBackup(row.id);
    });
    table.appendChild(body);
    App.wireRowKeyboard(body);
    drawBackupBulkBar();
  }

  function drawBackupBulkBar() {
    const n = view.backupsChecked.size;
    App.el('cx-backup-bulk').hidden = n === 0;
    if (n) App.el('cx-backup-bulk-count').textContent = `${n} selected`;
  }

  /* Deleting the NEWEST stored backup is not the same act as deleting an
     older one, and the confirmation says so: add_backup dedupes against the
     device's latest hash, so once the top row is gone the next scheduled run
     stores a "changed" backup for a config that has not changed. Better to
     say that than to let someone discover it from a diff. */
  function deleteBackups(ids) {
    if (!ids.length) return;
    const newest = view.backups.length
      ? view.backups.reduce((a, b) => (b.ts > a.ts ? b : a)) : null;
    const takingNewest = newest && ids.includes(newest.id);
    const device = view.devices.find((d) => d.id === view.selectedDeviceId);
    App.confirmDestructive(
      ids.length === 1 ? 'Delete this backup' : `Delete ${ids.length} backups`,
      `<p>Permanently delete <b>${ids.length}</b> stored config backup(s)` +
      `${device ? ` for <b>${escape(device.name)}</b>` : ''}? The stored config` +
      ' text is removed and cannot be recovered.</p>' +
      (takingNewest
        ? '<p class="hint">This includes the <b>most recent</b> backup. A new'
          + ' backup is only stored when it differs from the last one, so after'
          + ' this the next run will store the device\u2019s current config as a'
          + ' change even though nothing on the device has changed.</p>'
        : ''),
      'Delete',
      async () => {
        if (ids.length === 1) {
          await App.del(`/api/configrx/backups/${ids[0]}`, {});
        } else {
          await App.post('/api/configrx/backups/bulk-delete', { backup_ids: ids });
        }
        view.backupsChecked.clear();
        if (ids.includes(view.selectedBackupId)) {
          view.selectedBackupId = null;
          view.backupContent = '';
        }
        await selectDevice(view.selectedDeviceId);
      });
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

  /* The SSH host key this app remembers for the device's address and port —
     the same stored key the SSH terminal checks. Forget is gated on ConfigRX
     write, the permission that already decides which port and which
     credential the next connection uses; forgetting is the act that lets that
     connection accept whatever key it is offered. Fetched after the dialog
     opens and redrawn in place afterwards, so forgetting one does not close
     the settings form or reload the page. Dynamically built write-gated
     controls check canWrite themselves — applyPermissions() only ever hides
     what is already in the document.

     `box` is the one shared modal element, so a dialog that was cancelled and
     replaced while this fetch was in flight would otherwise paint device A's
     fingerprint (and a Forget bound to A) into device B's dialog. The target
     captured before the await is detached once the modal's innerHTML has been
     rewritten, so isConnected is the test for "this dialog is still open". */
  async function drawHostKey(box, device) {
    const target = box.querySelector('#cx-hostkey');
    if (!target) return;
    let key = null;
    try {
      key = (await App.get(`/api/ssh/devices/${device.id}/hostkey`, {})).host_key;
    } catch (error) {
      if (!target.isConnected) return;
      target.innerHTML = `<p class="hint">Host key: ${escape(error.message)}</p>`;
      return;
    }
    if (!target.isConnected) return;
    if (!key) {
      target.innerHTML = '<p class="hint">No host key stored yet. The first'
        + ' connection to this device — a backup or an SSH session — stores the'
        + ' key it presents, and every later one has to match it.</p>';
      return;
    }
    target.innerHTML =
      `<p>Host key: <b style="font-family:var(--mono)">${escape(key.fingerprint)}</b>`
      + ` (${escape(key.key_type)}), first seen ${App.stamp(key.first_seen_ts)}`
      + `${key.trusted_by ? `, trusted by ${escape(key.trusted_by)}` : ''}.</p>`
      + (App.canWrite('configrx')
        ? '<p><button id="cx-hostkey-forget">Forget</button>'
          + '<span class="hint"> Forget it only when this device was genuinely'
          + ' rebuilt or replaced: the next connection then stores whatever key'
          + ' it is offered, with nothing to check it against.</span></p>'
        : '');
    const forget = target.querySelector('#cx-hostkey-forget');
    if (forget) {
      forget.onclick = async () => {
        forget.disabled = true;
        try {
          await App.del(`/api/ssh/devices/${device.id}/hostkey`, {});
        } catch (error) {
          if (!target.isConnected) return;
          target.innerHTML += `<p class="hint" style="color:var(--fail)">`
            + `${escape(error.message)}</p>`;
          return;
        }
        if (!target.isConnected) return;
        await drawHostKey(box, device);
      };
    }
  }

  function deviceSettingsModal() {
    const device = view.devices.find((d) => d.id === view.selectedDeviceId);
    if (!device) return;
    const box = App.modal(`ConfigRX settings: ${device.name}`, `
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
      </fieldset>
      <fieldset><legend>HOST KEY</legend>
        <div id="cx-hostkey"><p class="hint">Loading…</p></div>
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
    drawHostKey(box, device);
  }

  /* ---------------------------------------------------------- settings */

  /* The two facts that decide whether a SHA-1-only device can be reached at
     all, stated up front rather than discovered from a failed backup: which
     paramiko is loaded (pip installs into whichever interpreter it was run
     from, and a downgrade needs a process restart) and whether the legacy
     algorithms are implemented by it and offered by us. */
  function sshReport() {
    const ssh = (App.state.serverState || {}).configrx?.ssh;
    if (!ssh || !ssh.paramiko) return '';
    if (!ssh.available) {
      return `<p class="hint">paramiko is ${escape(ssh.paramiko)}.</p>`;
    }
    let verdict;
    if (ssh.legacy_implemented === false) {
      verdict = '<b class="err">does not implement SHA-1 key exchange</b>, so ' +
        'a device that offers nothing newer cannot be reached whatever this ' +
        'checkbox says. Installing an older paramiko only helps if it goes to ' +
        'this same interpreter, and the app is restarted afterwards — a ' +
        'module already imported cannot be swapped underneath a running process.';
    } else if (ssh.legacy_implemented === true) {
      verdict = `implements SHA-1 key exchange, currently ` +
        `<b>${ssh.legacy_offered ? 'offered' : 'not offered'}</b>.`;
    } else {
      verdict = 'has not been probed yet — start the worker.';
    }
    return `<p class="hint">Loaded paramiko: <b>${escape(ssh.paramiko)}</b>. ` +
      `It ${verdict}</p>`;
  }

  function settingsDialog() {
    const s = App.state.configrxSettings || {};
    const settingsBox = App.modal('ConfigRX settings', `
      <fieldset><legend>SCHEDULE</legend>
        <label class="check"><input type="checkbox" id="cxs-enabled"
          ${s.enabled ? 'checked' : ''}> Run the backup worker</label>
        <label>Backup interval (hours) <input id="cxs-interval" type="number" min="1"
          value="${s.backup_interval_hours}"></label>
        <label>Capture timeout (seconds) <input id="cxs-capture" type="number" min="10"
          value="${s.capture_timeout_s}"></label>
        <p class="hint">A ceiling, not a wait: the capture ends the moment the
          device's prompt comes back, so a fast switch finishes in a second
          either way. Raise it if a device with a very large config over a slow
          link reports that the capture timeout was reached.</p>
      </fieldset>
      <fieldset><legend>RETENTION</legend>
        <label>Keep backups for (days) <input id="cxs-days" type="number" min="0"
          value="${s.retention_days}"></label>
        <label>Keep at most (per device) <input id="cxs-count" type="number" min="0"
          value="${s.retention_count_per_device}"></label>
        <p class="hint">An unchanged config never creates a new stored backup, so a
          device that never changes stays at one row regardless of these caps.</p>
      </fieldset>
      <fieldset><legend>SSH</legend>
        ${sshReport()}
        <label class="check"><input type="checkbox" id="cxs-legacy"
          ${s.allow_legacy_ssh !== false ? 'checked' : ''}> Allow legacy SSH
          algorithms</label>
        <p class="hint">Offers SHA-1 key exchange (diffie-hellman-group14-sha1 and
          older) and ssh-rsa host keys as a last resort, which is the best many
          older switches, routers and firewalls can do — and backing those up is
          what this module is for. A device that speaks something modern still
          negotiates it; these are only ever offered after the modern ones. Turn
          this off where policy forbids SHA-1 — it takes effect on save, like
          every other setting here. Enabling it can only help where the installed
          paramiko still implements those algorithms: paramiko 5 removed them
          outright, which is why this app pins paramiko below 5.</p>
      </fieldset>
      ${App.columnPickerFieldset('DEVICE LIST COLUMNS', 'cxdevices', COLUMNS,
                                 s.table_columns)}
      ${App.columnPickerFieldset('BACKUP LIST COLUMNS', 'cxbackups', BACKUP_COLUMNS,
                                 s.table_columns_backups)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        await App.post('/api/settings', { scope: 'configrx', values: {
          enabled: m.querySelector('#cxs-enabled').checked,
          backup_interval_hours: Number(m.querySelector('#cxs-interval').value),
          capture_timeout_s: Number(m.querySelector('#cxs-capture').value),
          retention_days: Number(m.querySelector('#cxs-days').value),
          retention_count_per_device: Number(m.querySelector('#cxs-count').value),
          allow_legacy_ssh: m.querySelector('#cxs-legacy').checked,
          table_columns: App.readColumnPicker(
            m.querySelector('#cols-cxdevices'), COLUMNS),
          table_columns_backups: App.readColumnPicker(
            m.querySelector('#cols-cxbackups'), BACKUP_COLUMNS),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('configrx');
      } },
    ]);
    App.wireColumnPickers(settingsBox);
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'configrx') return;
    drawStatus();
    const vendorSelect = App.el('cx-filter-vendor');
    const params = { q: App.el('cx-q').value.trim() };
    if (App.el('cx-enabled-only').checked) params.enabled_only = 1;
    if (vendorSelect.value) params.vendor = vendorSelect.value;
    const result = await App.get('/api/configrx/devices', params);
    view.devices = result.devices;
    drawVendorFilter(result.devices, vendorSelect);
    drawDevices();
    drawBackups();
  }

  /* Built from the vendors actually present rather than from the vendor
     catalogue, so the filter never offers a choice that returns nothing.
     While a vendor is selected the response only contains that vendor, so
     the current choice is kept in the list — otherwise picking one would
     immediately empty the control that made the choice. */
  function drawVendorFilter(devices, select) {
    const current = select.value;
    const seen = new Set(devices.map((d) => d.effective_vendor || '(none)'));
    if (current) seen.add(current);
    const options = [...seen].sort();
    select.innerHTML = '<option value="">All vendors</option>' +
      options.map((v) =>
        `<option value="${escape(v)}">${escape(v)}</option>`).join('');
    select.value = current;
  }

  function init() {
    App.el('cx-apply').onclick = () => App.refreshNow('configrx');
    App.el('cx-q').onkeydown = (event) => {
      if (event.key === 'Enter') App.refreshNow('configrx');
    };
    App.el('cx-enabled-only').onchange = () => App.refreshNow('configrx');
    App.el('cx-filter-vendor').onchange = () => App.refreshNow('configrx');
    App.el('cx-bulk-clear').onclick = bulkClearSelection;
    App.el('cx-backup-delete').onclick = () => deleteBackups([...view.backupsChecked]);
    App.el('cx-backup-clear').onclick = () => {
      view.backupsChecked.clear();
      drawBackups();
    };
    App.el('cx-bulk-settings').onclick = bulkSettings;
    App.el('cx-bulk-backup').onclick = bulkBackupNow;
    App.el('cx-settings').onclick = settingsDialog;
    App.el('cx-device-settings').onclick = deviceSettingsModal;
    /* Backing up with the worker stopped used to report success and do
       nothing — the queue it went into was never being drained. The server
       now refuses it, so say why rather than swallowing the rejection. */
    App.el('cx-backup-now').onclick = async () => {
      if (!view.selectedDeviceId) return;
      const button = App.el('cx-backup-now');
      const settle = (text) => {
        button.disabled = false;
        button.textContent = text;
        if (text !== 'Back up now') {
          setTimeout(() => {
            if (button.textContent === text) button.textContent = 'Back up now';
          }, 3000);
        }
      };
      button.disabled = true;
      button.textContent = 'Queueing…';
      try {
        const deviceId = view.selectedDeviceId;
        const before = (view.devices.find((d) => d.id === deviceId) || {})
          .last_backup_ts || 0;
        const result = await App.post(
          `/api/configrx/devices/${deviceId}/backup`, {});
        if (result.queued === false) { settle('Already queued…'); return; }
        button.textContent = 'Queued…';
        // Bounded, and reporting real state rather than a guess: a backup runs
        // on a worker thread, so the POST returning means "queued". The device
        // row now carries backing_up/backup_queued, and last_backup_ts moving
        // is what "done" actually means. Same shape as the Nodes Poll now
        // button, which had exactly this problem first.
        const deadline = Date.now() + 180000;
        const watch = async () => {
          if (view.selectedDeviceId !== deviceId || App.state.tab !== 'configrx') {
            settle('Back up now');
            return;
          }
          let payload;
          try {
            payload = await App.get(`/api/configrx/devices/${deviceId}`, {});
          } catch (error) {
            settle('Back up now');
            return;
          }
          const device = payload.device || {};
          if ((device.last_backup_ts || 0) > before) {
            settle(device.last_backup_status === 'error' ? 'Failed'
              : (device.last_backup_status || 'Done'));
            await selectDevice(deviceId);
            App.refreshNow('configrx');
            return;
          }
          if (Date.now() > deadline) { settle('Still running…'); return; }
          button.textContent = device.backing_up ? 'Backing up…' : 'Queued…';
          setTimeout(watch, 1000);
        };
        setTimeout(watch, 600);
      } catch (error) {
        settle('Back up now');
        App.modal('Cannot back up now',
          `<p>${escape(error.message)}</p>`,
          [{ label: 'Close', primary: true, onClick: App.closeModal }]);
      }
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

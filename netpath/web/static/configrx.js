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
    deviceSort: App.recallSort('configrx-devices', { key: 'name', descending: false }),
    backups: [],
    backupsChecked: new Set(),
    backupSort: App.recallSort('configrx-backups', { key: 'ts', descending: true }),
    selectedBackupId: null,
    backupContent: '',
    // The last /api/configrx/diff response, or null while the plain
    // single-backup viewer is showing instead — see showDiff/closeDiff.
    diff: null,
  };

  // One implementation, in app.js. This was twelve copies of the same
  // three lines, which is how one of them came to be missing a
  // character while the others were not.
  const escape = App.escapeHtml;

  // One relative-time vocabulary for the whole product: App.ago (app.js).
  const ago = App.ago;

  function bytesText(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  const STATUS_COLOR = { changed: 'var(--ok)', unchanged: 'var(--accent)',
    error: 'var(--fail)', suspect: 'var(--warn)' };
  /* Backup outcomes mapped onto the tones App.statusMark draws. "changed"
     is information rather than health — a device whose config differs from
     the last copy is working exactly as intended — so it takes the info
     tone and its own shape, instead of the green that means "up" on every
     other page in the product. "suspect" is a capture under a fifth of the
     device's previous one: stored, because refusing it outright is worse,
     but flagged rather than shown as an ordinary change (see configrx.py's
     SUSPECT_SHRINK_RATIO). */
  const STATUS_TONE = { changed: 'info', unchanged: 'ok', error: 'fail', suspect: 'warn' };

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
    App.el('cx-dot').style.background = worker.running ? 'var(--ok)' : 'var(--line)';
    App.el('cx-toggle').textContent = worker.running ? 'Stop worker' : 'Start worker';
    const c = worker.counters || {};
    const parts = [`${c.backups || 0} backup(s) run`, `${c.changed || 0} changed`,
      `${c.suspect || 0} suspect`, `${c.unchanged || 0} unchanged`, `${c.errors || 0} errors`];
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
          // last_backup_error also carries a reason for "suspect" now (see
          // configrx.py's SUSPECT_SHRINK_RATIO), so the word shown is
          // whatever status actually is, with the reason only in the title \u2014
          // it used to be the literal word "error" whenever a reason was
          // present at all.
          ? `<span title="${escape(r.last_backup_error)}">${
              escape((r.last_backup_status || 'error').split(' ')[0])}</span>`
          : escape(r.last_backup_status || (r.backup_enabled ? 'pending' : '\u2014'))) },
    { key: 'last_backup_ts', label: 'When', width: 100, numeric: true, on: true,
      value: (r) => r.last_backup_ts || 0, cell: (r) => App.agoCell(r.last_backup_ts) },
    { key: 'detected_vendor', label: 'Detected vendor', width: 130,
      value: (r) => r.vendor || '', cell: (r) => escape(r.vendor || '\u2014') },
    { key: 'ssh_username', label: 'SSH user', width: 120,
      cell: (r) => escape(r.ssh_username || '\u2014') },
    { key: 'ssh_port', label: 'Port', width: 70, numeric: true, on: true },
    { key: 'has_credential', label: 'Credential', width: 90, on: true,
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
      name: 'configrx-devices', caption: 'ConfigRX devices', columns,
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
    }, 'No devices match these filters. Widen the search or clear a filter.');
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

  /* Shared by the single-device and bulk settings dialogs, which both take
     an SSH port through a plain number input — `min`/`max` are advisory
     only, since App.modal's forms are novalidate. `allowBlank` is the bulk
     dialog's "leave unchanged" case; the single-device port is always a
     real value. */
  function checkPortField(box, selector, { allowBlank = false } = {}) {
    const el = box.querySelector(selector);
    const raw = el.value.trim();
    const port = Number(raw);
    if (raw && Number.isInteger(port) && port >= 1 && port <= 65535) return true;
    if (!raw && allowBlank) return true;
    App.showModalError(box, 'The SSH port must be a number from 1 to 65535.');
    el.setAttribute('aria-invalid', 'true');
    el.classList.add('invalid');
    el.addEventListener('input', () => {
      el.removeAttribute('aria-invalid');
      el.classList.remove('invalid');
    }, { once: true });
    el.focus();
    return false;
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
        ${App.canStoreSecrets()
          ? `<label>Password <input id="cx-bulk-password" type="password"
              placeholder="leave blank to keep each device's own"></label>`
          : App.credentialUnavailableHtml('An SSH password')}
        <p class="hint">A password is stored only when a username is given with
          it — the pair is what gets encrypted, and half of one would lock the
          batch out. Stored encrypted and never shown again.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        if (!checkPortField(m, '#cx-bulk-port', { allowBlank: true })) return;
        const username = m.querySelector('#cx-bulk-username').value.trim();
        const password = (m.querySelector('#cx-bulk-password') || {}).value || '';
        const enabled = m.querySelector('#cx-bulk-enabled').value;
        const vendor = m.querySelector('#cx-bulk-vendor').value.trim();
        const port = m.querySelector('#cx-bulk-port').value.trim();
        if (password && !username) {
          App.showModalError(m, 'A username is required with a password: the pair'
            + ' is what gets encrypted, and half of one would lock the batch out.');
          m.querySelector('#cx-bulk-username').focus();
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
      // The label IS the result — 'Queued for 12 devices', 'Failed' —
      // and a label rewritten in place is a silent DOM mutation to a
      // screen reader, so the result is said once as well. Inside the
      // branch, because the resting label is not a result.
      if (text !== 'Back up selected') {
        App.announce(text);
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
      App.toast(`Could not queue the backup: ${error.message}`, 'fail');
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
    closeDiff();
    App.setRoute(deviceId != null ? ['device', deviceId] : []);
    drawDevices();
    drawViewer();
    const result = await App.get(`/api/configrx/devices/${deviceId}/backups`, {});
    view.backups = result.backups;
    drawBackups();
  }

  /* ------------------------------------------------------------- backups */

  /* App.timeCell decides per row whether ITS OWN timestamp is "today" —
     fine for a table of current activity, but a device's stored backups
     span whatever the retention settings allow, so the row taken at 23:58
     yesterday showed a date and the one from 00:02 this morning did not,
     which read as though only some rows were dated at all. App.stamp's
     span argument makes every row in the list agree on whether the date is
     worth showing, based on how wide the whole list actually is. */
  function backupTimeSpan() {
    if (view.backups.length < 2) return 0;
    const times = view.backups.map((b) => b.ts);
    return Math.max(...times) - Math.min(...times);
  }

  const BACKUP_COLUMNS = [
    { key: 'check', label: '', sortable: false, fixed: true, width: 30,
      cell: (r) => `<input type="checkbox" class="cx-bcheck"${
        view.backupsChecked.has(r.id) ? ' checked' : ''}>` },
    { key: 'ts', label: 'Taken', width: 150, numeric: true, on: true,
      align: 'left', descendingFirst: true,
      title: App.timeZoneTitle(), cell: (r) => `<span class="when" title="${
        escape(App.when(r.ts))}">${App.stamp(r.ts, backupTimeSpan())}</span>` },
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
    const backupNowBtn = App.el('cx-backup-now');
    backupNowBtn.hidden = !device;
    // Visible-but-disabled rather than hidden when backups are off, so an
    // operator who came here to back up a device sees why the button will
    // not do it instead of wondering whether it exists at all. Skipped
    // while applyWriteGate already owns the button (data-requires-write on
    // this element is what disabled it) — its own reason takes precedence,
    // and it is the one thing on the page allowed to re-enable a control it
    // did not itself disable.
    if (device && !backupNowBtn.dataset.writeDenied) {
      const offReason = !device.backup_enabled
        ? 'Backups are switched off for this device — turn them on in Device settings.'
        : '';
      backupNowBtn.disabled = !!offReason;
      if (offReason) backupNowBtn.title = offReason;
      else backupNowBtn.removeAttribute('title');
    }
    App.el('cx-device-settings').hidden = !device;
    // "Diff with previous" only makes sense once a backup is selected AND
    // an older one exists to diff it against — the oldest stored backup
    // for a device has nothing before it. view.backups is always in the
    // server's newest-first order (drawBackups' own on-screen sort is a
    // display concern, applied only to the rendered rows below), so the
    // next array entry after the selected one IS the adjacent older backup.
    App.el('cx-backup-diff-prev').hidden =
      view.selectedBackupId == null || !adjacentOlderBackup(view.selectedBackupId);
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
      name: 'configrx-backups', caption: 'Stored backups', columns,
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
      tr.onclick = () => selectBackup(row.id).catch((error) =>
        App.toast(`Could not read that backup: ${error.message}`, 'fail'));
    });
    table.appendChild(body);
    App.wireRowKeyboard(body);
    drawBackupBulkBar();
  }

  function drawBackupBulkBar() {
    const n = view.backupsChecked.size;
    App.el('cx-backup-bulk').hidden = n === 0;
    if (n) App.el('cx-backup-bulk-count').textContent = `${n} selected`;
    // Diffing needs exactly two backups picked — one is "diff with
    // previous" above, and more than two has no obvious pairing to draw.
    App.el('cx-backup-diff-selected').hidden = n !== 2;
  }

  /* The adjacent OLDER backup to `id` in the server's own newest-first
     order — null when `id` is not stored, or is already the oldest one.
     "Diff with previous" and the button's own visibility (drawBackups)
     both read this rather than each re-deriving it. */
  function adjacentOlderBackup(id) {
    const index = view.backups.findIndex((b) => b.id === id);
    if (index === -1 || index + 1 >= view.backups.length) return null;
    return view.backups[index + 1];
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
    // Picking a single backup always means "show me its plain content" —
    // any diff left open from a previous pair is no longer about what's on
    // screen now.
    closeDiff();
    // #/configrx/device/4/backup/91 — a specific stored configuration, which
    // is what a change-control conversation is actually about.
    if (view.selectedDeviceId != null) {
      App.setRoute(['device', view.selectedDeviceId, 'backup', backupId]);
    }
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

  /* --------------------------------------------------------------- diff

     A unified diff between two stored backups (Tier 2: the hashes that
     detect the change are already stored — this is the view that reads
     them). `fromId` is the OLDER backup, `toId` the newer one; the server
     redacts both a second time regardless of how they were originally
     stored (see api.get_configrx_diff's own docstring for why), so nothing
     rendered here can ever be an unredacted secret. */
  function diffLineClass(line) {
    if (line.startsWith('+++') || line.startsWith('---')) return 'cx-diff-file';
    if (line.startsWith('@@')) return 'cx-diff-hunk';
    if (line.startsWith('+')) return 'cx-diff-add';
    if (line.startsWith('-')) return 'cx-diff-rem';
    return '';
  }

  /* Coloured with spans rather than a diff library: difflib's own unified
     format is three prefix characters ('+', '-', '@@ ', or a leading
     space for context) and nothing here needs more than that to colour a
     line — see app.css's .cx-diff-* for the palette these classes read. */
  function renderDiffHtml(text) {
    if (!text) return '';
    const lines = text.replace(/\n$/, '').split('\n');
    return lines.map((line) => {
      const cls = diffLineClass(line);
      return `<span${cls ? ` class="${cls}"` : ''}>${escape(line)}</span>`;
    }).join('\n');
  }

  async function showDiff(fromId, toId) {
    if (view.selectedDeviceId == null) return;
    let result;
    try {
      result = await App.get('/api/configrx/diff',
        { device: view.selectedDeviceId, from: fromId, to: toId });
    } catch (error) {
      App.toast(`Could not diff these backups: ${error.message}`, 'fail');
      return;
    }
    view.diff = result;
    App.el('cx-viewer').hidden = true;
    App.el('cx-diff-wrap').hidden = false;
    App.el('cx-diff-close').hidden = false;
    App.el('cx-diff-meta').textContent =
      `${App.stamp(result.from.ts)} → ${App.stamp(result.to.ts)}` +
      ` — +${result.additions} / −${result.removals}` +
      (result.identical ? ' — no differences' : '');
    // An empty diff is ambiguous on its own (O-57): this route redacts both
    // sides a second time no matter what each backup's own stored flag
    // says, so a secret that only changed VALUE — a rotated enable secret,
    // a new SNMP community, a changed local password — renders as the
    // identical "<redacted>" token on both sides and no line differs,
    // exactly like two backups that are genuinely the same. `identical`
    // and `redacted_only_change` are the two backups' own sha256 (never
    // redacted, always distinct here) telling those apart, so this says
    // which one actually happened rather than showing "no differences"
    // for both. Deliberately says only THAT something changed, never what:
    // no masked before/after, no hint at the old or new value, nothing
    // suggesting redaction can be turned off to see it — the whole point
    // of redacting a diff is that this view must not be the way to find
    // out. (A device with "keep secrets in backups" on does still store
    // the value verbatim, readable by a write account through the single
    // backup itself — this view simply is not that view.)
    App.el('cx-diff').innerHTML = result.identical
      ? '<span class="hint">No differences between these two backups.</span>'
      : result.diff
        ? renderDiffHtml(result.diff)
        : result.redacted_only_change
          ? '<span class="hint">These two backups differ, but only in a value this ' +
            'view redacts — an enable secret, an SNMP community, a local password. ' +
            'This view does not show what changed.</span>'
          : '<span class="hint">No differences between these two backups.</span>';
  }

  function closeDiff() {
    if (!view.diff) return;
    view.diff = null;
    App.el('cx-diff-wrap').hidden = true;
    App.el('cx-diff-close').hidden = true;
    App.el('cx-viewer').hidden = false;
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
      `<p>Host key: <b class="mono">${escape(key.fingerprint)}</b>`
      + ` (${escape(key.key_type)}), first seen ${App.when(key.first_seen_ts)}`
      + `${key.trusted_by ? `, trusted by ${escape(key.trusted_by)}` : ''}.</p>`
      + (App.canWrite('configrx')
        // danger, the same tier every other trust-destroying action in this
        // product uses: forgetting the key this device is checked against
        // leaves the next connection with nothing to catch a substituted
        // host, which is exactly the failure this key exists to catch.
        ? '<p><button id="cx-hostkey-forget" class="danger">Forget</button>'
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
          target.innerHTML += `<p class="hint err">${escape(error.message)}</p>`;
          return;
        }
        if (!target.isConnected) return;
        await drawHostKey(box, device);
      };
    }
  }

  /* The keys configrx_vendors.VENDORS knows, served by /api/config as
     configrx_vendors — label and key only, nothing that lets this page
     influence what a backup sends — plus free text (the "Other" option
     and its own box) for anything not in that table, which is exactly
     what vendor_override is documented as being for (e.g. HP/Aruba has
     no SNMP enterprise root registered in nodeoids.vendor_for() to
     auto-detect from, and a platform this build has not shipped a Vendor
     entry for yet still needs somewhere to type its key). */
  const VENDOR_OTHER = '__other__';

  function vendorChoices() {
    return ((App.state.config || {}).configrx_vendors || [])
      .map((v) => [v.key, v.label]);
  }

  function vendorFieldHtml(current) {
    const choices = vendorChoices();
    const known = choices.some(([key]) => key === current);
    const selected = !current ? '' : (known ? current : VENDOR_OTHER);
    return `<label>Vendor override <select id="cx-vendor">
        <option value=""${selected === '' ? ' selected' : ''}>Auto-detected from Nodes</option>
        ${choices.map(([key, label]) => `<option value="${escape(key)}"${
          selected === key ? ' selected' : ''}>${escape(label)} (${escape(key)})</option>`).join('')}
        <option value="${VENDOR_OTHER}"${selected === VENDOR_OTHER ? ' selected' : ''}
          >Other (type a vendor key)…</option>
      </select></label>
      <label id="cx-vendor-other-wrap"${selected === VENDOR_OTHER ? '' : ' hidden'}>Vendor key
        <input id="cx-vendor-other" value="${escape(known ? '' : current)}"
          placeholder="e.g. hpe-comware"></label>`;
  }

  /* The enable secret's own state (stored / not) and, when it is stored,
     a way to drop just it — DELETE .../credential/enable-secret, which
     touches nothing else — so a device that turns out not to need one is
     not stuck clearing the SSH password too just to get rid of it. */
  function enableSecretFieldHtml(device) {
    return `<label>Enable secret <input id="cx-enable-secret" type="password"
        placeholder="${device.has_enable_secret ? 'stored — leave blank to keep' : 'most platforms do not need this'}"></label>
      ${device.has_enable_secret && App.canWrite('configrx')
        // danger, same as Forget beside the host key above: it acts the
        // moment it is clicked, with no confirm of its own, so the tier
        // that usually says "second thought needed" is the only warning
        // this button gets before the click itself.
        ? '<p><button id="cx-enable-secret-clear" class="danger">Clear stored enable secret</button>'
          + '<span class="hint"> Leaves the SSH username and password untouched.</span></p>'
        : ''}`;
  }

  function wireEnableSecretClear(box, device) {
    const wrap = box.querySelector('#cx-enable-secret-wrap');
    const clearBtn = wrap.querySelector('#cx-enable-secret-clear');
    if (!clearBtn) return;
    clearBtn.onclick = async () => {
      clearBtn.disabled = true;
      try {
        await App.del(`/api/configrx/devices/${device.id}/credential/enable-secret`, {});
      } catch (error) {
        clearBtn.disabled = false;
        App.toast(`Could not clear the enable secret: ${error.message}`, 'fail');
        return;
      }
      device.has_enable_secret = false;
      wrap.innerHTML = enableSecretFieldHtml(device);
      wireEnableSecretClear(box, device);
      App.announce('Enable secret cleared.');
    };
  }

  function deviceSettingsModal() {
    const device = view.devices.find((d) => d.id === view.selectedDeviceId);
    if (!device) return;
    const box = App.modal(`ConfigRX settings: ${device.name}`, `
      <fieldset><legend>BACKUP</legend>
        <label class="check"><input type="checkbox" id="cx-enabled"
          ${device.backup_enabled ? 'checked' : ''}> Back up this device</label>
        ${vendorFieldHtml(device.vendor_override)}
        <p class="hint">Leave on <b>Auto-detected from Nodes</b> to use the vendor Nodes
          already detected over SNMP${device.vendor ? ` (currently ${escape(device.vendor)})` : ''}.
          Pick a platform from the list, or <b>Other</b> to type a vendor key this list
          does not cover — set this only when auto-detection is wrong or unset.</p>
      </fieldset>
      <fieldset><legend>SSH CREDENTIAL</legend>
        <label>Port <input id="cx-port" type="number" min="1" max="65535"
          value="${device.ssh_port}"></label>
        <label>Username <input id="cx-username" value="${escape(device.ssh_username)}"></label>
        ${App.canStoreSecrets()
          ? `<label>Password <input id="cx-password" type="password"
              placeholder="${device.has_credential ? 'stored — leave blank to keep' : ''}"></label>
            <div id="cx-enable-secret-wrap">${enableSecretFieldHtml(device)}</div>`
          : App.credentialUnavailableHtml('An SSH password')}
        <p class="hint">Stored encrypted; never shown again once saved. ConfigRX only ever
          runs one fixed, read-only "show config" command for this device's vendor — there
          is no way to run any other command from here. The enable secret is only needed for
          a platform whose login lands in user EXEC rather than privileged mode — currently
          just Cisco ASA — and is saved only together with the SSH password above.</p>
      </fieldset>
      <fieldset><legend>HOST KEY</legend>
        <div id="cx-hostkey"><p class="hint">Loading…</p></div>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (m) => {
        if (!checkPortField(m, '#cx-port')) return;
        const vendorChoice = m.querySelector('#cx-vendor').value;
        const vendorOverride = vendorChoice === VENDOR_OTHER
          ? m.querySelector('#cx-vendor-other').value.trim() : vendorChoice;
        await App.post(`/api/configrx/devices/${device.id}/config`, {
          backup_enabled: m.querySelector('#cx-enabled').checked,
          ssh_port: Number(m.querySelector('#cx-port').value),
          ssh_username: m.querySelector('#cx-username').value.trim(),
          vendor_override: vendorOverride,
        });
        const password = (m.querySelector('#cx-password') || {}).value || '';
        const username = m.querySelector('#cx-username').value.trim();
        const enableSecret = (m.querySelector('#cx-enable-secret') || {}).value || '';
        if (password && username) {
          const credential = { ssh_username: username, ssh_password: password };
          // Omitted entirely when blank, same as the password field's own
          // "leave blank to keep" — the API's own default for an absent key
          // is "leave whatever is stored untouched" (see api.py).
          if (enableSecret) credential.enable_secret = enableSecret;
          await App.post(`/api/configrx/devices/${device.id}/credential`, credential);
        }
        App.closeModal();
        await App.refreshNow('configrx');
      } },
    ]);
    const vendorSelect = box.querySelector('#cx-vendor');
    const vendorOtherWrap = box.querySelector('#cx-vendor-other-wrap');
    vendorSelect.onchange = () => {
      vendorOtherWrap.hidden = vendorSelect.value !== VENDOR_OTHER;
    };
    if (App.canStoreSecrets()) wireEnableSecretClear(box, device);
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
      { label: 'Save', primary: true, onClick: (m, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
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
        })()) },
    ]);
    App.wireColumnPickers(settingsBox);
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'configrx') return;
    drawStatus();
    const vendorSelect = App.el('cx-filter-vendor');
    // The vendor list is built from this very response, so on the load after
    // a reload the restored choice is not on the element yet; the fetch has
    // to read it from the store or the list would contradict the filter. Once
    // the list exists the control answers for itself, "All vendors" included.
    const vendor = App.controlOrSaved('configrx', 'cx-filter-vendor');
    const params = { q: App.el('cx-q').value.trim() };
    if (App.el('cx-enabled-only').checked) params.enabled_only = 1;
    if (vendor) params.vendor = vendor;
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
    const fromSelect = select.value;
    const current = fromSelect ||
      App.savedControl('configrx', 'cx-filter-vendor') || '';
    const seen = new Set(devices.map((d) => d.effective_vendor || '(none)'));
    // A choice made ON the control is kept in the list whatever the response
    // holds — the response only holds that vendor, so dropping it would empty
    // the control that made the choice. A choice restored from the STORE is
    // kept only if some device really has that vendor: re-adding it
    // unconditionally is what left a device list permanently empty behind a
    // filter naming a vendor nothing carried any more.
    if (current && (fromSelect || seen.has(current))) seen.add(current);
    const options = [...seen].sort();
    select.innerHTML = '<option value="">All vendors</option>' +
      options.map((v) =>
        `<option value="${escape(v)}">${escape(v)}</option>`).join('');
    select.value = current;
    // Dropped from the store as well as from the control: while it is stored,
    // refresh() above would go on filtering by a vendor with no devices and
    // no way to clear it, since the filter shows blank rather than the value.
    if (select.selectedIndex < 0) {
      select.value = '';
      App.rememberControl('configrx', 'cx-filter-vendor', '');
    }
  }

  function init() {
    /* Registered before this module's own onchange handlers below, so a
       filter change writes the store before the refresh those handlers start
       reads it back — listeners run in registration order. restoreControls
       stays at the end and assigns from script, which fires no event. */
    const CONTROLS = ['cx-q', 'cx-filter-vendor', 'cx-enabled-only'];
    App.rememberControls('configrx', CONTROLS);
    App.filterBar('configrx', {
      text: ['cx-q'], selects: ['cx-filter-vendor'],
      apply: 'cx-apply', clear: 'cx-clear', clears: ['cx-q', 'cx-filter-vendor', 'cx-enabled-only'],
    });
    App.el('cx-bulk-clear').onclick = bulkClearSelection;
    App.el('cx-backup-delete').onclick = () => deleteBackups([...view.backupsChecked]);
    App.el('cx-backup-clear').onclick = () => {
      view.backupsChecked.clear();
      drawBackups();
    };
    App.el('cx-backup-diff-prev').onclick = () => {
      const older = adjacentOlderBackup(view.selectedBackupId);
      if (older) showDiff(older.id, view.selectedBackupId);
    };
    App.el('cx-backup-diff-selected').onclick = () => {
      const ids = [...view.backupsChecked];
      if (ids.length !== 2) return;
      const [older, newer] = ids
        .map((id) => view.backups.find((b) => b.id === id))
        .filter(Boolean)
        .sort((a, b) => a.ts - b.ts);
      if (older && newer) showDiff(older.id, newer.id);
    };
    // Both buttons carry data-requires-write="configrx" in index.html, left
    // over from before 4.48.0 moved fetching a single stored backup to
    // ConfigRX read (get_configrx_backup). Diffing two backups a reader can
    // already open one at a time is not a write, and it is the single most
    // common thing anyone does with a config backup — "what changed on this
    // switch before it stopped answering" is a reader's question, not a
    // writer's. Undone here rather than in the markup (not mine to edit):
    // the attribute is stripped so applyPermissions' generic write-gate
    // (app.js), which only ever walks `[data-requires-write]`, never reaches
    // these two again — but loadState() runs applyPermissions() before any
    // module's init() (see app.js's start()), so a read-only account has
    // already had both buttons disabled-with-reason by the time this line
    // runs; stripping the attribute alone would stop future re-disabling
    // without ever undoing that first pass. So this also reverses it by
    // hand, the same way applyWriteGate's own "allowed" branch would.
    // /api/configrx/diff itself still requires write server-side
    // (server.py:479) — until that changes to match get_configrx_backup's
    // R, a read-only account clicking either button gets showDiff's own
    // "Could not diff these backups: ..." toast instead of a 403 with no
    // explanation, which is at least an honest answer while the two catch up.
    for (const id of ['cx-backup-diff-prev', 'cx-backup-diff-selected']) {
      const btn = App.el(id);
      btn.removeAttribute('data-requires-write');
      if (btn.dataset.writeDenied) {
        btn.disabled = false;
        delete btn.dataset.writeDenied;
        btn.removeAttribute('title');
      }
      btn.classList.remove('write-denied');
    }
    App.el('cx-diff-close').onclick = closeDiff;
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
        // The label IS the result — 'Queued for 12 devices', 'Failed' —
        // and a label rewritten in place is a silent DOM mutation to a
        // screen reader, so the result is said once as well. Inside the
        // branch, because the resting label is not a result.
        if (text !== 'Back up now') {
          App.announce(text);
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
            const failed = device.last_backup_status === 'error';
            settle(failed ? 'Failed' : (device.last_backup_status || 'Done'));
            // The button label flicking to "Failed" said THAT it failed and
            // nothing else — the reason lived only in the Last backup
            // column's title, which nobody is hovering right after a click.
            if (failed) {
              App.toast(`Backup of ${device.name || device.ip || 'this device'} `
                + `failed: ${device.last_backup_error || 'unknown error'}`, 'fail');
            }
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

    // Last thing in init(): refresh() reads the search and the tickbox
    // straight off the DOM, so the first search already carries them. The
    // vendor list is late-filled — see drawVendorFilter.
    App.restoreControls('configrx', CONTROLS);
  }

  /* #/configrx/device/<id> and .../backup/<bid>. Runs after refresh(), so
     the device list is populated; selectDevice fetches that device's backups
     before the backup half is applied. */
  async function activate(opts) {
    if (!opts || !opts.parts || opts.parts[0] !== 'device') return;
    const deviceId = Number(opts.parts[1]);
    if (!Number.isFinite(deviceId)) return;
    if (view.selectedDeviceId !== deviceId) {
      await selectDevice(deviceId).catch(() => { /* a link to a gone device */ });
    }
    if (opts.parts[2] !== 'backup' || opts.parts[3] === undefined) return;
    const backupId = Number(opts.parts[3]);
    if (!Number.isFinite(backupId)) return;
    await selectBackup(backupId).catch(() => { /* pruned backup */ });
  }

  App.pages.configrx = { init, refresh, activate, fastTick: drawStatus };
})();

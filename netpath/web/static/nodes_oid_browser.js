/* NODES' OID browser dialog, fetched by App.loadExtra the first time the
   Browse OIDs button is pressed. Registers on App.extras, not App.pages —
   it is an extension of that page, not a tab module of its own. */
(() => {
  const escape = App.escapeHtml;

  // Set by init() on every open (idempotent) so oidBrowser/useOidFor keep
  // reading them as free variables, same as in nodes.js.
  let view, displayName, loadDetail;

  function init(ctx) {
    ({ view, displayName, loadDetail } = ctx);
  }

  /* What a device actually answers, decoded against every MIB this app
     knows. Deliberately subtree-at-a-time rather than a walk of the whole
     tree: a switch is tens of thousands of objects and minutes of GETNEXTs,
     and nobody reads that. The three offered subtrees cover "what is this
     box" and "what are its ports"; anything else is one box and one click. */
  function oidBrowser() {
    const deviceId = view.selected;
    if (!deviceId) return;
    const device = view.devices.find((d) => d.id === deviceId);
    // Same ticket idiom the interface dialog uses: App.modal reuses one
    // #modal-box, so a slow walk must not paint into whatever dialog is
    // open by the time it lands.
    let token = null;
    const current = () => App.modalIsCurrent(token);

    const box = App.modal(`Browse OIDs — ${displayName(device || {})}`, `
      <div class="bar wrap">
        <label>Start at <input id="oid-base" size="24" value="1.3.6.1.2.1.1"></label>
        <button id="oid-walk">Walk from here</button>
        <span id="oid-quick" class="hint"></span>
        <span class="grow"></span>
        <button id="oid-full">Download full walk</button>
        <button id="oid-full-cancel" hidden>Cancel</button>
      </div>
      <div id="oid-full-status" class="hint" hidden></div>
      <p class="hint">Each walk reads the device live over SNMP. Names come
        from the MIBs uploaded under Profiles &amp; MIBs — an OID no MIB
        describes is shown as its number rather than guessed at.</p>
      <div id="oid-status" class="hint"></div>
      <div class="table-wrap scrollbox large"><table id="oid-table"></table></div>`, [
      { label: 'Close', onClick: App.closeModal },
    ], { buttonsTop: true });
    // Stamped by App.modal above; every paint below checks it first.
    token = App.modalToken();
    box.classList.add('wide');

    const COLS = [
      { key: 'oid', label: 'OID', width: 210 },
      { key: 'name', label: 'Name', width: 200 },
      { key: 'suffix', label: 'Index', width: 70 },
      { key: 'type', label: 'Type', width: 90 },
      { key: 'value', label: 'Value', width: 280 },
      // The point of browsing is usually "which OID holds this?", and the
      // answer is only useful if you can act on it. Setting the field from
      // a row whose value is on screen is the difference between choosing an
      // OID and guessing one.
      { key: 'use', label: 'Use as', width: 150, sortable: false },
    ];
    let rows = [];
    let sort = { key: 'oid', descending: false };

    function draw() {
      const table = App.grid(box.querySelector('#oid-table'),
        { name: 'nodes-oids', caption: 'OID walk results',
          columns: COLS, sort, onSort: (key, descending) => {
          sort = { key, descending }; draw();
        } });
      const body = document.createElement('tbody');
      // Sorted numerically by arc, not as text: "1.3.6.1.2.1.1.10" must not
      // sort between ".1" and ".2".
      const ordered = sort.key === 'oid'
        ? rows.slice().sort((a, b) => (sort.descending ? -1 : 1) * oidCompare(a.oid, b.oid))
        : App.sortRows(rows, sort.key, sort.descending, COLS);
      for (const row of ordered) {
        const tr = document.createElement('tr');
        tr.innerHTML =
          `<td>${escape(row.oid)}</td>` +
          `<td>${row.name ? escape(row.name) : '<span class="hint">—</span>'}</td>` +
          `<td>${escape(row.suffix || '')}</td>` +
          `<td>${escape(row.type)}</td>` +
          `<td>${escape(row.value)}</td>` +
          '<td><button class="linkish oid-use-vendor">vendor</button> ' +
          '<button class="linkish oid-use-location">location</button></td>';
        tr.querySelector('.oid-use-vendor').onclick =
          () => useOidFor('vendor_oid', row);
        tr.querySelector('.oid-use-location').onclick =
          () => useOidFor('location_oid', row);
        body.appendChild(tr);
      }
      table.appendChild(body);
      App.wireRowKeyboard(body);
    }

    async function walk(base) {
      box.querySelector('#oid-base').value = base;
      box.querySelector('#oid-status').textContent = `Walking ${base}…`;
      rows = [];
      draw();
      let payload;
      try {
        payload = await App.get(`/api/nodes/devices/${deviceId}/oids`, { oid: base });
      } catch (error) {
        if (!current()) return;
        box.querySelector('#oid-status').innerHTML =
          `<span class="err">${escape(error.message)}</span>`;
        return;
      }
      if (!current()) return;
      rows = payload.rows || [];
      // A walk that stopped early says so: a truncated list that looks
      // complete is worse than no list.
      const named = rows.filter((r) => r.name).length;
      box.querySelector('#oid-status').innerHTML = rows.length
        ? `${rows.length} object(s), ${named} named` +
          (payload.complete ? '' :
            ` · <span class="err">${escape(payload.stopped)}</span>`)
        : `<span class="hint">Nothing under ${escape(base)}` +
          (payload.complete ? '' : ` — ${escape(payload.stopped)}`) + '</span>';
      draw();
    }

    App.get(`/api/nodes/devices/${deviceId}/oids`, {}).then((payload) => {
      if (!current()) return;
      const quick = box.querySelector('#oid-quick');
      quick.textContent = '';
      for (const base of payload.bases || []) {
        const button = document.createElement('button');
        button.textContent = base.label;
        button.onclick = () => walk(base.oid);
        quick.appendChild(button);
      }
    }).catch(() => {});

    /* The whole device, as a file. Runs server-side as a background job —
       a full walk of a core switch is tens of thousands of GETNEXTs and
       minutes of SNMP, which is exactly why the table above browses one
       subtree at a time — so this shows a live count and a cancel, and
       downloads only once the job is finished. */
    const fullBtn = box.querySelector('#oid-full');
    const cancelBtn = box.querySelector('#oid-full-cancel');
    const fullStatus = box.querySelector('#oid-full-status');
    let watchTimer = null;                // the poll's stop function
    // Starting a walk is a write (it drives the device over SNMP), and
    // applyPermissions only ever runs over markup that already exists, so
    // dynamically-built controls check canWrite themselves — see app.js.
    // Disabled with a reason, not hidden: hiding taught a read-only operator
    // that the feature simply is not there, the same failure applyPermissions
    // itself moved away from for exactly this reason (see its own comment in
    // app.js) — the button sits alone at the end of the bar with nothing
    // after it, so disabling it in place costs nothing layout has to absorb.
    if (!App.canWrite('nodes')) {
      fullBtn.disabled = true;
      fullBtn.title = 'Needs Nodes write';
    }

    function stopWatching() {
      if (watchTimer) watchTimer();
      watchTimer = null;
      fullBtn.disabled = false;
      cancelBtn.hidden = true;
    }
    window.addEventListener('modal-closed', stopWatching, { once: true });

    function say(html, error) {
      fullStatus.hidden = false;
      fullStatus.innerHTML = error ? `<span class="err">${html}</span>` : html;
    }

    async function finishFullWalk() {
      // download=1 hands over the text and drops the rows server-side, so a
      // 100k-object walk does not sit in memory for the life of the process.
      // Which is exactly why this must run once: a second call would find
      // the rows already dropped and report an empty walk. The watch is
      // stopped before the request, not after it.
      const done = await App.get(`/api/nodes/devices/${deviceId}/oid-walk`,
                                 { download: 1 });
      if (!current()) return;
      if (!done.text) { say('The walk produced nothing.', true); return; }
      // Same App.download every export in this app uses; no server-side
      // Content-Disposition anywhere in this app.
      const filename = done.filename || 'snmp-walk.txt';
      App.download(new Blob([done.text], { type: 'text/plain' }), filename);
      const walkInfo = done.walk || {};
      say(`Downloaded ${walkInfo.rows || 0} object(s) as ` +
          `${escape(filename)}` +
          (walkInfo.complete ? '.' :
            ` — <b>incomplete</b>: ${escape(walkInfo.stopped || '')}`));
    }

    async function pollFullWalk() {
      let payload;
      try {
        payload = await App.get(`/api/nodes/devices/${deviceId}/oid-walk`);
      } catch (error) {
        stopWatching();
        if (current()) say(escape(error.message), true);
        return;
      }
      if (!current()) { stopWatching(); return; }
      const walkInfo = payload.walk;
      if (!walkInfo) { stopWatching(); return; }
      if (walkInfo.state === 'failed') {
        stopWatching();
        say(escape(walkInfo.error || 'The walk failed.'), true);
        return;
      }
      if (walkInfo.state === 'done') {
        // Stop the interval BEFORE the download request: formatting a
        // 100,000-row walk can take longer than the one-second tick, and a
        // second finishFullWalk would race the first one's own cleanup.
        stopWatching();
        fullBtn.disabled = true;
        say('Preparing the download…');
        try {
          await finishFullWalk();
        } catch (error) {
          if (current()) say(escape(error.message), true);
        }
        fullBtn.disabled = false;
        return;
      }
      say(`Walking the whole device — ${walkInfo.rows} object(s) so far, ` +
          `${Math.round(walkInfo.elapsed)}s elapsed.`);
    }

    fullBtn.onclick = async () => {
      fullBtn.disabled = true;
      cancelBtn.hidden = false;
      say('Starting the walk…');
      try {
        await App.post(`/api/nodes/devices/${deviceId}/oid-walk`, {});
      } catch (error) {
        stopWatching();
        say(escape(error.message), true);
        return;
      }
      if (!current()) { stopWatching(); return; }
      watchTimer = App.pollWhileModal(token, 1000,
        () => { pollFullWalk().catch(() => {}); });
      pollFullWalk().catch(() => {});
    };

    cancelBtn.onclick = async () => {
      cancelBtn.disabled = true;
      await App.del(`/api/nodes/devices/${deviceId}/oid-walk`, {}).catch(() => {});
      cancelBtn.disabled = false;
      // The job stops at its next request and reports "done" with a
      // cancelled reason, so the rows walked so far still download — a
      // cancel is "enough, give me what you have", not "throw it away".
    };

    box.querySelector('#oid-walk').onclick =
      () => walk(box.querySelector('#oid-base').value.trim());
    draw();
    walk('1.3.6.1.2.1.1');
  }

  /* Sets the browsed OID as the open device's vendor or location source.

     Applied straight away rather than through a confirm: it is a plain
     device override, reversible by clearing the field in Edit, and this app
     reserves confirmation dialogs for destructive actions. The browser stays
     open — an operator setting one of the two usually wants the other — and
     the status line says what happened, including the value the OID answered
     with, so the choice is visibly the one that was made. */
  async function useOidFor(field, row) {
    const deviceId = view.selected;
    const status = document.getElementById('oid-status');
    if (!deviceId) return;
    const what = field === 'vendor_oid' ? 'Vendor' : 'Location';
    try {
      await App.put(`/api/nodes/devices/${deviceId}`, { [field]: row.oid });
    } catch (error) {
      if (status) {
        status.innerHTML = `<span class="err">${escape(error.message)}</span>`;
      }
      return;
    }
    if (status) {
      status.innerHTML = `${what} now reads from <code>${escape(row.oid)}</code>` +
        ` — currently <b>${escape(row.value)}</b>.` +
        (field === 'vendor_oid'
          ? ' <span class="hint">Displayed vendor only; ConfigRX and the' +
            ' Cisco MAC-table read keep using the detected vendor.</span>'
          : '');
    }
    await loadDetail();
    App.refreshNow('nodes');
  }

  /* Numeric arc-by-arc, so 1.3.6.1.2.1.1.10 sorts after .9 rather than
     between .1 and .2 the way string order would put it. */
  function oidCompare(a, b) {
    const x = String(a).split('.').map(Number);
    const y = String(b).split('.').map(Number);
    for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
      const d = (x[i] || 0) - (y[i] || 0);
      if (d) return d;
    }
    return 0;
  }

  App.extras.nodesOidBrowser = { init, open: oidBrowser };
})();

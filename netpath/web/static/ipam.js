/* The IPAM page: subnet discovery and inventory, IP conflicts, and read-only
   browsing of what a Windows DHCP server reports about its own scopes and
   leases. Three sub-views inside one tab, switched locally rather than as
   separate top-level tabs — none of them is a whole module on its own. */
(() => {
  const view = {
    sub: 'subnets',
    subnets: [], subnetId: null,
    hosts: [], hostSort: { key: 'ip', descending: false },
    conflicts: [],
    dhcpServers: [], dhcpServerId: null,
    dhcpScopes: [], dhcpScopeId: null, dhcpLeases: [],
    leaseSort: { key: 'ip', descending: false },
    scopeSort: 'least',
    scopeTrendWindow: '24h', scopeTrend: [],
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

  /* A small utilization donut, drawn with the standard stroke-dasharray
     trick — one circle per slice, each dashed to show only its own arc —
     rather than computing SVG arc paths by hand for three fixed slices.
     Takes slices directly so subnets and DHCP scopes, which break their
     addresses down into genuinely different categories, can both use it. */
  function donut(slices, size) {
    const total = slices.reduce((sum, s) => sum + (s.value || 0), 0);
    const radius = size / 2 - 3;
    const circumference = 2 * Math.PI * radius;
    const svg = App.svgNode('svg', { width: size, height: size,
      viewBox: `0 0 ${size} ${size}`, class: 'usage-donut' });
    if (!total) {
      svg.appendChild(App.svgNode('circle', {
        cx: size / 2, cy: size / 2, r: radius, fill: 'none',
        stroke: 'var(--hairline)', 'stroke-width': 5,
      }));
      return svg;
    }
    let offset = 0;
    for (const slice of slices) {
      if (!slice.value) continue;
      const length = (slice.value / total) * circumference;
      svg.appendChild(App.svgNode('circle', {
        cx: size / 2, cy: size / 2, r: radius, fill: 'none',
        stroke: slice.color, 'stroke-width': 5,
        'stroke-dasharray': `${length} ${circumference - length}`,
        'stroke-dashoffset': -offset,
        transform: `rotate(-90 ${size / 2} ${size / 2})`,
      }));
      offset += length;
    }
    return svg;
  }

  function usageDonut(usage, size) {
    const u = usage || {};
    return donut([
      { value: u.alive || 0, color: 'var(--ok)' },
      { value: u.seen_down || 0, color: 'var(--warn)' },
      { value: u.never_seen || 0, color: 'var(--hairline)' },
    ], size);
  }

  function scopeDonut(usage, size) {
    const u = usage || {};
    return donut([
      { value: u.leased || 0, color: 'var(--ok)' },
      { value: u.reserved || 0, color: 'var(--accent)' },
      { value: u.available || 0, color: 'var(--hairline)' },
    ], size);
  }

  function usageTooltipText(subnet) {
    const u = subnet.usage || {};
    const pct = (n) => u.total ? `${Math.round((n / u.total) * 100)}%` : '0%';
    return [
      `${subnet.label} — ${subnet.cidr}`,
      `${u.total || 0} usable address(es)`,
      `alive        ${u.alive || 0}  (${pct(u.alive || 0)})`,
      `seen, down   ${u.seen_down || 0}  (${pct(u.seen_down || 0)})`,
      `never seen   ${u.never_seen || 0}  (${pct(u.never_seen || 0)})`,
    ].join('\n');
  }

  /* The larger chart for whichever subnet is currently selected, above its
     host table — same donut helper as the sidebar, just bigger, with the
     counts spelled out beside it rather than left to a tooltip. */
  function drawSubnetDetail() {
    const container = App.el('ipam-subnet-detail');
    const subnet = view.subnets.find((s) => s.id === view.subnetId);
    container.innerHTML = '';
    if (!subnet) {
      container.innerHTML = '<p class="hint">Add a subnet on the left to see its address usage here.</p>';
      return;
    }

    container.appendChild(usageDonut(subnet.usage, 120));

    const u = subnet.usage || {};
    const total = u.total || 0;
    const pct = (n) => total ? `${Math.round((n / total) * 100)}%` : '0%';
    const scan = subnet.last_scan;
    const scanLine = subnet.scanning ? 'Scanning now\u2026'
      : scan ? `Last scan ${ago(scan.finished)} \u00b7 ${scan.alive}/${scan.addresses} answered` +
               (scan.conflicts ? `, ${scan.conflicts} new conflict(s)` : '')
      : 'Never scanned yet';

    const text = document.createElement('div');
    text.className = 'subnet-detail-text';
    text.innerHTML =
      `<div class="subnet-detail-title">${escape(subnet.label)}` +
      `${subnet.enabled ? '' : ' (disabled)'} \u2014 ${escape(subnet.cidr)}</div>` +
      `<div class="subnet-detail-rows">` +
      `<div><span class="legend-dot" style="background:var(--ok)"></span>Alive` +
      ` <b>${u.alive || 0}</b> <span class="hint">(${pct(u.alive || 0)})</span></div>` +
      `<div><span class="legend-dot" style="background:var(--warn)"></span>Seen before, now down` +
      ` <b>${u.seen_down || 0}</b> <span class="hint">(${pct(u.seen_down || 0)})</span></div>` +
      `<div><span class="legend-dot" style="background:var(--hairline)"></span>Never seen` +
      ` <b>${u.never_seen || 0}</b> <span class="hint">(${pct(u.never_seen || 0)})</span></div>` +
      `</div>` +
      `<div class="hint">${total} usable address(es) \u00b7 ${escape(scanLine)}</div>`;
    container.appendChild(text);
  }

  /* -------------------------------------------------------------- sub-tabs */

  function selectSub(name) {
    view.sub = name;
    for (const btn of document.querySelectorAll('#page-ipam .subtab')) {
      btn.classList.toggle('active', btn.dataset.subtab === name);
    }
    for (const page of document.querySelectorAll('#page-ipam .subpage')) {
      page.classList.toggle('active', page.id === `ipam-sub-${name}`);
    }
  }

  /* ---------------------------------------------------------------- status */

  function drawStatus() {
    const ipam = (App.state.serverState || {}).ipam || {};
    const dot = App.el('ipam-dot');
    dot.style.background = ipam.running ? 'var(--ok)' : 'var(--faint)';
    App.el('ipam-status').textContent = ipam.running
      ? 'Worker running' : 'Worker stopped';
    const parts = [];
    if (ipam.scanning && ipam.scanning.length) parts.push(`scanning ${ipam.scanning.length} subnet(s)`);
    if (ipam.polling && ipam.polling.length) parts.push(`polling ${ipam.polling.length} DHCP server(s)`);
    App.el('ipam-counters').textContent = parts.join(' · ');

    const badge = App.el('ipam-conflict-badge');
    const count = ipam.open_conflicts || 0;
    badge.textContent = count;
    badge.hidden = count === 0;
  }

  /* -------------------------------------------------------------- subnets */

  function renderSubnets() {
    const table = App.el('ipam-subnet-table');
    table.innerHTML = '';
    const body = document.createElement('tbody');
    for (const subnet of view.subnets) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (subnet.id === view.subnetId ? ' selected' : '');
      const scan = subnet.last_scan;
      const scanText = subnet.scanning ? 'scanning…'
        : scan ? `${scan.alive}/${scan.addresses} alive · ${ago(scan.finished)}`
        : 'never scanned';

      const td = document.createElement('td');
      const row = document.createElement('div');
      row.className = 'subnet-row';
      row.appendChild(usageDonut(subnet.usage, 30));
      const text = document.createElement('div');
      text.className = 'subnet-row-text';
      text.innerHTML =
        `<div class="name">${escape(subnet.label)}${subnet.enabled ? '' : ' (disabled)'}</div>` +
        `<div class="host">${escape(subnet.cidr)}</div>` +
        `<div class="hint">${escape(scanText)}</div>`;
      row.appendChild(text);
      td.appendChild(row);
      tr.appendChild(td);

      const tip = usageTooltipText(subnet);
      tr.addEventListener('mousemove', (event) => App.tooltip(tip, event));
      tr.addEventListener('mouseleave', App.hideTooltip);
      tr.onclick = () => {
        view.subnetId = subnet.id;
        renderSubnets();
        drawSubnetDetail();
        loadHosts();
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  function subnetForm(subnet) {
    const s = subnet || {};
    return `
      <fieldset><legend>SUBNET</legend>
        <label>CIDR <input id="sn-cidr" placeholder="10.20.3.0/24" value="${escape(s.cidr ?? '')}"></label>
        <label>Label <input id="sn-label" value="${escape(s.label ?? '')}"></label>
        <label>VLAN <input id="sn-vlan" value="${escape(s.vlan ?? '')}"></label>
        <p class="hint" id="sn-error"></p>
      </fieldset>`;
  }

  async function addSubnet() {
    App.modal('Add subnet', subnetForm(null), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        try {
          const payload = await App.post('/api/ipam/subnets', {
            cidr: b.querySelector('#sn-cidr').value.trim(),
            label: b.querySelector('#sn-label').value.trim(),
            vlan: b.querySelector('#sn-vlan').value.trim(),
          });
          view.subnetId = payload.id;
          App.closeModal();
          await loadSubnets();
        } catch (error) {
          b.querySelector('#sn-error').innerHTML =
            `<span class="err">${escape(error.message)}</span>`;
        }
      } },
    ]);
  }

  async function editSubnet() {
    const subnet = view.subnets.find((s) => s.id === view.subnetId);
    if (!subnet) return;
    App.modal('Edit subnet', subnetForm(subnet) +
      `<label class="check"><input type="checkbox" id="sn-enabled" ${subnet.enabled ? 'checked' : ''}> Enabled</label>`,
      [
        { label: 'Cancel', onClick: App.closeModal },
        { label: 'Remove subnet', onClick: async () => {
          await App.del(`/api/ipam/subnets/${subnet.id}`);
          view.subnetId = null;
          App.closeModal();
          await loadSubnets();
        } },
        { label: 'Clear stats', onClick: async (b) => {
          try {
            const result = await App.post(`/api/ipam/subnets/${subnet.id}/clear`, {});
            b.querySelector('#sn-error').innerHTML =
              `<span style="color:var(--ok)">Cleared ${result.hosts} host(s) and ` +
              `${result.scans} scan record(s). The subnet itself is unchanged ` +
              `and its conflict history is kept — the next scan starts fresh.</span>`;
            await loadSubnets();
          } catch (error) {
            b.querySelector('#sn-error').innerHTML =
              `<span class="err">${escape(error.message)}</span>`;
          }
        } },
        { label: 'Save', primary: true, onClick: async (b) => {
          await App.put(`/api/ipam/subnets/${subnet.id}`, {
            cidr: b.querySelector('#sn-cidr').value.trim(),
            label: b.querySelector('#sn-label').value.trim(),
            vlan: b.querySelector('#sn-vlan').value.trim(),
            enabled: b.querySelector('#sn-enabled').checked,
          });
          App.closeModal();
          await loadSubnets();
        } },
      ]);
  }

  async function scanNow() {
    if (!view.subnetId) return;
    await App.post(`/api/ipam/subnets/${view.subnetId}/scan`, {});
    App.refreshNow('ipam');
  }

  async function loadSubnets() {
    const payload = await App.get('/api/ipam/subnets');
    view.subnets = payload.subnets;
    if (view.subnetId && !view.subnets.some((s) => s.id === view.subnetId)) {
      view.subnetId = null;
    }
    if (!view.subnetId && view.subnets.length) view.subnetId = view.subnets[0].id;
    renderSubnets();
    drawSubnetDetail();
    await loadHosts();
  }

  /* ---------------------------------------------------------------- hosts */

  /* `last_up` is when the address last actually replied; `first_seen` is
     when it was first probed, which is not the same thing and was labelled
     as though it were. An address that has never answered now shows "never"
     rather than a recent-looking timestamp left by the last sweep. */
  const HOST_COLUMNS = [
    { key: 'ip', label: 'IP address', width: 130, value: (r) => r.ip },
    { key: 'mac', label: 'MAC', width: 150, value: (r) => r.mac || '' },
    { key: 'alive', label: 'Alive', width: 70, value: (r) => (r.alive ? 1 : 0) },
    { key: 'hostname', label: 'Hostname', width: 220, value: (r) => r.hostname || '' },
    { key: 'last_up', label: 'Last reply', width: 110, numeric: true,
      align: 'left', descendingFirst: true, value: (r) => r.last_up },
    { key: 'first_seen', label: 'First probed', width: 120, numeric: true,
      align: 'left', value: (r) => r.first_seen },
  ];

  function onHostSort(key, descending) {
    view.hostSort = { key, descending };
    drawHosts();
  }

  function drawHosts() {
    const table = App.grid(App.el('ipam-hosts-table'),
      { name: 'ipam-hosts', columns: HOST_COLUMNS, sort: view.hostSort, onSort: onHostSort });
    const body = document.createElement('tbody');
    const aliveOnly = App.el('ipam-alive-only').checked;
    const rows = App.sortRows(
      aliveOnly ? view.hosts.filter((h) => h.alive) : view.hosts,
      view.hostSort.key, view.hostSort.descending, HOST_COLUMNS);
    for (const host of rows) {
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${escape(host.ip)}</td>` +
        `<td>${escape(host.mac || '—')}</td>` +
        `<td>${host.alive ? '<span class="sev sev-3">up</span>' : '<span class="sev sev-7">down</span>'}</td>` +
        `<td>${escape(host.hostname || '')}</td>` +
        `<td>${ago(host.last_up)}</td>` +
        `<td>${ago(host.first_seen)}</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('ipam-hosts-count').textContent = `${rows.length} of ${view.hosts.length}`;
  }

  async function loadHosts() {
    if (!view.subnetId) {
      view.hosts = [];
      drawHosts();
      return;
    }
    const payload = await App.get('/api/ipam/hosts', { subnet_id: view.subnetId });
    view.hosts = payload.hosts;
    drawHosts();
  }

  /* ----------------------------------------------------------- conflicts */

  function drawConflicts() {
    const table = App.el('ipam-conflicts-table');
    table.innerHTML = '<thead><tr><th>IP address</th><th>First MAC</th>' +
      '<th>Second MAC</th><th>Source</th><th>Detected</th><th>Last seen</th>' +
      '<th></th></tr></thead>';
    const body = document.createElement('tbody');
    for (const c of view.conflicts) {
      const tr = document.createElement('tr');
      const sourceText = c.source === 'scan_dhcp'
        ? 'wire vs. DHCP lease' : 'wire, two scans';
      tr.innerHTML =
        `<td>${escape(c.ip)}</td><td>${escape(c.mac_a)}</td><td>${escape(c.mac_b)}</td>` +
        `<td>${sourceText}</td><td>${ago(c.detected)}</td><td>${ago(c.last_seen)}</td><td></td>`;
      if (!c.resolved) {
        const button = document.createElement('button');
        button.textContent = 'Mark resolved';
        button.onclick = async () => {
          await App.post(`/api/ipam/conflicts/${c.id}/resolve`, {});
          await loadConflicts();
        };
        tr.lastElementChild.appendChild(button);
      } else {
        tr.lastElementChild.textContent = `resolved ${ago(c.resolved)}`;
      }
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('ipam-conflicts-count').textContent =
      `${view.conflicts.length} ${App.el('ipam-show-resolved').checked ? '' : 'open '}conflict(s)`;
  }

  async function loadConflicts() {
    const resolved = App.el('ipam-show-resolved').checked;
    const payload = await App.get('/api/ipam/conflicts', resolved ? { resolved: 1 } : {});
    view.conflicts = payload.conflicts;
    drawConflicts();
  }

  /* ---------------------------------------------------------------- dhcp */

  /* One DHCP server is picked at a time via a dropdown rather than a full
     sidebar table -- that sidebar space belongs to SCOPES now, mirroring
     Subnets & Hosts, and most installs have only a couple of servers
     (a failover pair, typically) rather than a long list worth scrolling. */
  function renderDhcpServerSelect() {
    const select = App.el('ipam-dhcp-server-select');
    select.innerHTML = view.dhcpServers.length
      ? view.dhcpServers.map((s) =>
          `<option value="${s.id}" ${s.id === view.dhcpServerId ? 'selected' : ''}>` +
          `${escape(s.label)}${s.enabled ? '' : ' (disabled)'}</option>`).join('')
      : '<option value="">No DHCP servers configured</option>';

    const server = view.dhcpServers.find((s) => s.id === view.dhcpServerId);
    const statusEl = App.el('ipam-dhcp-server-status');
    if (!server) {
      statusEl.textContent = '';
      return;
    }
    const statusText = server.polling ? 'polling…'
      : server.last_status === 'ok' ? `ok · ${ago(server.last_poll)}`
      : server.last_status === 'error' ? `error · ${ago(server.last_poll)}`
      : 'never polled';
    const authText = server.has_credential
      ? `stored credential · ${escape(server.username || '')}` : 'ambient identity';
    statusEl.className = server.last_status === 'error' ? 'sev sev-1' : 'hint';
    statusEl.textContent = `${server.address} · ${authText} · ${statusText}`;
  }

  function dhcpServerForm(server) {
    const s = server || {};
    return `
      <fieldset><legend>SERVER</legend>
        <label>Hostname or address <input id="dh-address" placeholder="dhcp01.corp.local" value="${escape(s.address ?? '')}"></label>
        <label>Label <input id="dh-label" value="${escape(s.label ?? '')}"></label>
        <p class="hint">Read-only: scopes and leases only, never a write.</p>
      </fieldset>
      <fieldset><legend>AUTHENTICATION</legend>
        <label>Username <input id="dh-username" placeholder="CORP\\svc-sappiwhere-ro" value="${escape(s.username ?? '')}"></label>
        <label>Password <input id="dh-password" type="password" autocomplete="new-password" placeholder="${s.has_credential ? 'stored — leave blank to keep it' : 'leave blank to skip a stored credential'}"></label>
        <p class="hint">${s.has_credential
          ? 'A credential is stored, encrypted for this machine only. Fill in both fields to replace it, or leave both blank and save to keep it as is.'
          : 'Leave both blank to authenticate as whichever Windows account runs SappiWhere, or via a matching entry in Windows Credential Manager for this server\u2019s name — nothing is stored either way. Fill in both to store a read-only credential instead, encrypted for this machine.'}</p>
      </fieldset>
      <div class="hint" id="dh-error"></div>`;
  }

  function readDhcpForm(box) {
    return {
      address: box.querySelector('#dh-address').value.trim(),
      label: box.querySelector('#dh-label').value.trim(),
      username: box.querySelector('#dh-username').value.trim(),
      password: box.querySelector('#dh-password').value,
    };
  }

  /* Saves address/label, then applies whatever the credential fields say:
     both filled -> store/replace it; both blank -> leave it as it was. A
     single filled field is treated as blank, since a lone username or a lone
     password is not something the backend can act on either. */
  async function applyCredential(serverId, fields) {
    if (fields.username && fields.password) {
      await App.post(`/api/ipam/dhcp/servers/${serverId}/credential`,
        { username: fields.username, password: fields.password });
    }
  }

  async function addDhcpServer() {
    App.modal('Add DHCP server', dhcpServerForm(null), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        const fields = readDhcpForm(b);
        try {
          const payload = await App.post('/api/ipam/dhcp/servers', {
            address: fields.address, label: fields.label,
          });
          await applyCredential(payload.id, fields);
          view.dhcpServerId = payload.id;
          App.closeModal();
          await loadDhcpServers();
        } catch (error) {
          b.querySelector('#dh-error').innerHTML =
            `<span class="err">${escape(error.message)}</span>`;
        }
      } },
    ]);
  }

  async function editDhcpServer() {
    const server = view.dhcpServers.find((s) => s.id === view.dhcpServerId);
    if (!server) return;
    const box = App.modal('Edit DHCP server', dhcpServerForm(server) +
      `<label class="check"><input type="checkbox" id="dh-enabled" ${server.enabled ? 'checked' : ''}> Enabled</label>`,
      [
        { label: 'Cancel', onClick: App.closeModal },
        { label: 'Remove server', onClick: async () => {
          await App.del(`/api/ipam/dhcp/servers/${server.id}`);
          view.dhcpServerId = null;
          App.closeModal();
          await loadDhcpServers();
        } },
        { label: 'Clear credential', onClick: async (b) => {
          await App.del(`/api/ipam/dhcp/servers/${server.id}/credential`);
          b.querySelector('#dh-username').value = '';
          b.querySelector('#dh-password').value = '';
          b.querySelector('#dh-error').innerHTML =
            '<span style="color:var(--ok)">Stored credential cleared.</span>';
        } },
        { label: 'Test connection', onClick: async (b, button) => {
          const fields = readDhcpForm(b);
          // An untouched password field means "use whatever is already
          // configured" -- the stored credential if there is one, ambient
          // identity otherwise -- rather than testing with a blank password.
          const payload = fields.password
            ? { username: fields.username, password: fields.password } : {};
          const errorBox = b.querySelector('#dh-error');
          const label = button.textContent;
          // This can take a while -- it's a PowerShell round trip to the
          // DHCP server, over WinRM when a credential is set -- so say so
          // immediately rather than leaving the dialog looking inert until
          // the response lands.
          button.disabled = true;
          button.textContent = 'Testing…';
          errorBox.innerHTML = '<span class="hint">Testing connection — this can take up to '
            + 'thirty seconds…</span>';
          try {
            const result = await App.post(`/api/ipam/dhcp/servers/${server.id}/test`, payload);
            // Test failures can carry PowerShell's exact multi-line output
            // (stdout/stderr, exit code) rather than a one-line summary; a
            // <pre> preserves that formatting instead of collapsing it into
            // an unreadable run-on line.
            errorBox.innerHTML = result.ok
              ? `<span style="color:var(--ok)">Reachable — DHCP Server ${escape(result.version)}, ${result.scope_count} scope(s)</span>`
              : `<pre class="err">${escape(result.error)}</pre>`;
          } catch (error) {
            errorBox.innerHTML = `<span class="err">${escape(error.message)}</span>`;
          } finally {
            button.disabled = false;
            button.textContent = label;
          }
        } },
        { label: 'Save', primary: true, onClick: async (b) => {
          const fields = readDhcpForm(b);
          await App.put(`/api/ipam/dhcp/servers/${server.id}`, {
            address: fields.address, label: fields.label,
            enabled: b.querySelector('#dh-enabled').checked,
          });
          await applyCredential(server.id, fields);
          App.closeModal();
          await loadDhcpServers();
        } },
      ]);
  }

  async function pollNow() {
    if (!view.dhcpServerId) return;
    await App.post(`/api/ipam/dhcp/servers/${view.dhcpServerId}/poll`, {});
    App.refreshNow('ipam');
  }

  /* Mirrors renderSubnets(): one row per scope with a mini utilization
     donut, in the sidebar this now shares the same layout with. */
  function scopeTooltipText(scope) {
    const u = scope.usage || {};
    const pct = (n) => u.total ? `${Math.round((n / u.total) * 100)}%` : '0%';
    return [
      `${scope.name || scope.scope_id} — ${scope.start_ip}–${scope.end_ip}`,
      `${u.total ?? '?'} address(es) in range`,
      `leased       ${u.leased || 0}  (${pct(u.leased || 0)})`,
      `reserved     ${u.reserved || 0}  (${pct(u.reserved || 0)})`,
      `available    ${u.available ?? '?'}  (${pct(u.available || 0)})`,
    ].join('\n');
  }

  /* Dotted-quad to a comparable integer -- plain string comparison would put
     "10.0.10.0" before "10.0.2.0", which is not the order anyone means by
     "sort by IP address". */
  function ipToNumber(ip) {
    const parts = String(ip || '0.0.0.0').split('.').map(Number);
    return ((parts[0] || 0) * 2 ** 24) + ((parts[1] || 0) * 2 ** 16) +
      ((parts[2] || 0) * 2 ** 8) + (parts[3] || 0);
  }

  function sortedScopes() {
    const scopes = view.dhcpScopes.slice();
    if (view.scopeSort === 'most') {
      // A scope whose range couldn't be parsed sorts last rather than
      // masquerading as the roomiest one.
      scopes.sort((a, b) => (b.usage?.available ?? -1) - (a.usage?.available ?? -1));
    } else if (view.scopeSort === 'name') {
      scopes.sort((a, b) =>
        (a.name || a.scope_id).localeCompare(b.name || b.scope_id, undefined,
                                             { numeric: true, sensitivity: 'base' }));
    } else if (view.scopeSort === 'ip') {
      scopes.sort((a, b) => ipToNumber(a.scope_id) - ipToNumber(b.scope_id));
    } else {
      // Default: least available first, so the scope closest to running out
      // is the first thing you see. An unparseable range sorts last here
      // too, rather than masquerading as the most urgent one.
      scopes.sort((a, b) => (a.usage?.available ?? Infinity) - (b.usage?.available ?? Infinity));
    }
    return scopes;
  }

  function renderDhcpScopes() {
    const table = App.el('ipam-dhcp-scope-table');
    table.innerHTML = '';
    const body = document.createElement('tbody');
    for (const scope of sortedScopes()) {
      const tr = document.createElement('tr');
      tr.className = 'clickable' + (scope.id === view.dhcpScopeId ? ' selected' : '');

      const td = document.createElement('td');
      const row = document.createElement('div');
      row.className = 'subnet-row';
      row.appendChild(scopeDonut(scope.usage, 30));
      const text = document.createElement('div');
      text.className = 'subnet-row-text';
      text.innerHTML =
        `<div class="name">${escape(scope.name || scope.scope_id)}</div>` +
        `<div class="host">${escape(scope.start_ip)} – ${escape(scope.end_ip)}</div>` +
        `<div class="hint">${escape(scope.state || '')}</div>`;
      row.appendChild(text);
      td.appendChild(row);
      tr.appendChild(td);

      const tip = scopeTooltipText(scope);
      tr.addEventListener('mousemove', (event) => App.tooltip(tip, event));
      tr.addEventListener('mouseleave', App.hideTooltip);
      tr.onclick = () => {
        view.dhcpScopeId = scope.id;
        view.scopeTrend = [];
        renderDhcpScopes();
        drawScopeDetail();
        loadDhcpLeases();
        loadScopeTrend();
      };
      body.appendChild(tr);
    }
    table.appendChild(body);
  }

  /* The larger chart for whichever scope is currently selected, above its
     lease table — same layout as drawSubnetDetail(), plus a thin trend
     strip underneath showing how the leased-IP count has moved recently. */
  function drawScopeDetail() {
    const container = App.el('ipam-scope-detail');
    const scope = view.dhcpScopes.find((s) => s.id === view.dhcpScopeId);
    container.classList.add('scope-detail-stacked');
    container.innerHTML = '';
    if (!scope) {
      container.innerHTML = '<p class="hint">Pick a scope on the left to see its address usage here.</p>';
      return;
    }

    const top = document.createElement('div');
    top.className = 'subnet-detail-row';
    top.appendChild(scopeDonut(scope.usage, 120));

    const u = scope.usage || {};
    const total = u.total || 0;
    const pct = (n) => total ? `${Math.round((n / total) * 100)}%` : '0%';

    const text = document.createElement('div');
    text.className = 'subnet-detail-text';
    text.innerHTML =
      `<div class="subnet-detail-title">${escape(scope.name || scope.scope_id)}` +
      ` — ${escape(scope.start_ip)}–${escape(scope.end_ip)}</div>` +
      `<div class="hint">Subnet ${escape(scope.subnet || 'unknown')} · Router ` +
      `${escape(scope.router || 'not set')}</div>` +
      `<div class="subnet-detail-rows">` +
      `<div><span class="legend-dot" style="background:var(--ok)"></span>Leased` +
      ` <b>${u.leased || 0}</b> <span class="hint">(${pct(u.leased || 0)})</span></div>` +
      `<div><span class="legend-dot" style="background:var(--accent)"></span>Reserved` +
      ` <b>${u.reserved || 0}</b> <span class="hint">(${pct(u.reserved || 0)})</span></div>` +
      `<div><span class="legend-dot" style="background:var(--hairline)"></span>Available` +
      ` <b>${u.available || 0}</b> <span class="hint">(${pct(u.available || 0)})</span></div>` +
      `</div>` +
      `<div class="hint">${total} address(es) in range \u00b7 ${escape(scope.state || '')} \u00b7 ` +
      `polled ${ago(scope.polled)}</div>`;
    top.appendChild(text);
    container.appendChild(top);
    container.appendChild(scopeTrendSection());
    drawScopeTrend();
  }

  /* --------------------------------------------------------- leased-IP trend */

  function scopeTrendSection() {
    const wrap = document.createElement('div');
    wrap.className = 'scope-trend';
    const header = document.createElement('div');
    header.className = 'scope-trend-header';
    const label = document.createElement('span');
    label.id = 'ipam-scope-trend-label';
    label.className = 'hint';
    label.textContent = 'Leased IPs';
    header.appendChild(label);

    const toggle = document.createElement('div');
    toggle.className = 'scope-trend-toggle';
    for (const [key, text] of [['24h', '24h'], ['7d', '7d']]) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'linkish' + (view.scopeTrendWindow === key ? ' active' : '');
      btn.textContent = text;
      btn.onclick = () => {
        view.scopeTrendWindow = key;
        loadScopeTrend();
      };
      toggle.appendChild(btn);
    }
    header.appendChild(toggle);
    wrap.appendChild(header);

    const chart = document.createElement('div');
    chart.id = 'ipam-scope-trend-chart';
    chart.className = 'scope-trend-chart';
    wrap.appendChild(chart);
    return wrap;
  }

  async function loadScopeTrend() {
    const scope = view.dhcpScopes.find((s) => s.id === view.dhcpScopeId);
    if (!scope) { view.scopeTrend = []; drawScopeTrend(); return; }
    const now = Date.now() / 1000;
    const span = view.scopeTrendWindow === '7d' ? 7 * 86400 : 86400;
    const payload = await App.get('/api/ipam/dhcp/scope-history', {
      server_id: view.dhcpServerId, scope_id: scope.scope_id,
      t0: now - span, t1: now,
    });
    view.scopeTrend = payload.points;
    drawScopeTrend();
  }

  function drawScopeTrend() {
    const chartEl = App.el('ipam-scope-trend-chart');
    const labelEl = App.el('ipam-scope-trend-label');
    if (!chartEl) return;   // the scope changed again before this landed
    chartEl.innerHTML = '';

    const points = view.scopeTrend || [];
    const windowText = view.scopeTrendWindow === '7d' ? 'last 7 days' : 'last 24 hours';
    if (points.length < 2) {
      if (labelEl) labelEl.textContent = `Leased IPs (${windowText}): not enough history yet`;
      return;
    }

    const width = chartEl.clientWidth || 400;
    const height = 40;
    const padX = 2, padY = 4;
    const t0 = points[0].ts;
    const t1 = points[points.length - 1].ts;
    const span = Math.max(t1 - t0, 1);
    const maxLeased = Math.max(1, ...points.map((p) => p.leased));
    const x = (ts) => padX + ((ts - t0) / span) * (width - padX * 2);
    const y = (v) => height - padY - (v / maxLeased) * (height - padY * 2);

    const line = points.map((p) => `${x(p.ts).toFixed(1)},${y(p.leased).toFixed(1)}`).join(' ');
    const area = `${x(t0).toFixed(1)},${height - padY} ${line} ${x(t1).toFixed(1)},${height - padY}`;

    const svg = App.svgNode('svg', {
      width: '100%', height, viewBox: `0 0 ${width} ${height}`,
      preserveAspectRatio: 'none',
    });
    svg.appendChild(App.svgNode('polygon', { points: area, fill: 'var(--ok)', opacity: 0.15 }));
    svg.appendChild(App.svgNode('polyline', {
      points: line, fill: 'none', stroke: 'var(--ok)', 'stroke-width': 1.5,
      'vector-effect': 'non-scaling-stroke',
    }));

    const tip = points.map((p) =>
      `${new Date(p.ts * 1000).toLocaleString()}  ${p.leased} leased` +
      (p.total ? ` (${Math.round((p.leased / p.total) * 100)}%)` : '')).join('\n');
    svg.addEventListener('mousemove', (event) => App.tooltip(tip, event));
    svg.addEventListener('mouseleave', App.hideTooltip);
    chartEl.appendChild(svg);

    const last = points[points.length - 1].leased;
    const first = points[0].leased;
    const delta = last - first;
    const deltaText = delta === 0 ? 'flat' : (delta > 0 ? `up ${delta}` : `down ${-delta}`);
    if (labelEl) {
      labelEl.textContent =
        `Leased IPs (${windowText}): ${last} now, ${deltaText} over the window`;
    }
  }

  const LEASE_COLUMNS = [
    { key: 'ip', label: 'IP address', width: 130, value: (r) => r.ip },
    { key: 'mac', label: 'MAC', width: 150, value: (r) => r.mac || '' },
    { key: 'hostname', label: 'Hostname', width: 200, value: (r) => r.hostname || '' },
    { key: 'state', label: 'State', width: 140, value: (r) => r.address_state || '' },
    { key: 'expires', label: 'Lease expires', width: 150, numeric: true,
      align: 'left', value: (r) => r.lease_expires || 0 },
  ];

  function onLeaseSort(key, descending) {
    view.leaseSort = { key, descending };
    drawLeases();
  }

  function drawLeases() {
    const table = App.grid(App.el('ipam-dhcp-lease-table'),
      { name: 'ipam-leases', columns: LEASE_COLUMNS, sort: view.leaseSort, onSort: onLeaseSort });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.dhcpLeases, view.leaseSort.key,
      view.leaseSort.descending, LEASE_COLUMNS);
    for (const lease of rows) {
      const tr = document.createElement('tr');
      const state = lease.is_reservation
        ? `<span class="sev sev-5">${escape(lease.address_state || 'reservation')}</span>`
        : escape(lease.address_state || '');
      tr.innerHTML =
        `<td>${escape(lease.ip)}</td><td>${escape(lease.mac || '')}</td>` +
        `<td>${escape(lease.hostname || lease.description || '')}</td>` +
        `<td>${state}</td>` +
        `<td>${lease.lease_expires ? App.stamp(lease.lease_expires) : ''}</td>`;
      body.appendChild(tr);
    }
    table.appendChild(body);
    App.el('ipam-lease-count').textContent = `${rows.length} lease(s)`;
  }

  async function loadDhcpServers() {
    const payload = await App.get('/api/ipam/dhcp/servers');
    view.dhcpServers = payload.servers;
    if (view.dhcpServerId && !view.dhcpServers.some((s) => s.id === view.dhcpServerId)) {
      view.dhcpServerId = null;
    }
    if (!view.dhcpServerId && view.dhcpServers.length) view.dhcpServerId = view.dhcpServers[0].id;
    renderDhcpServerSelect();
    await loadDhcpScopes();
  }

  async function loadDhcpScopes() {
    if (!view.dhcpServerId) {
      view.dhcpScopes = []; view.dhcpScopeId = null; view.dhcpLeases = [];
      renderDhcpScopes(); drawScopeDetail(); drawLeases();
      return;
    }
    const payload = await App.get('/api/ipam/dhcp/scopes', { server_id: view.dhcpServerId });
    view.dhcpScopes = payload.scopes;
    if (view.dhcpScopeId && !view.dhcpScopes.some((s) => s.id === view.dhcpScopeId)) {
      view.dhcpScopeId = null;
    }
    if (!view.dhcpScopeId && view.dhcpScopes.length) view.dhcpScopeId = view.dhcpScopes[0].id;
    renderDhcpScopes();
    drawScopeDetail();
    await loadDhcpLeases();
    await loadScopeTrend();
  }

  async function loadDhcpLeases() {
    if (!view.dhcpScopeId) {
      view.dhcpLeases = [];
      drawLeases();
      return;
    }
    const scope = view.dhcpScopes.find((s) => s.id === view.dhcpScopeId);
    const payload = await App.get('/api/ipam/dhcp/leases',
      { server_id: view.dhcpServerId, scope_id: scope ? scope.scope_id : '' });
    view.dhcpLeases = payload.leases;
    drawLeases();
  }

  /* ------------------------------------------------------------- settings */

  function settingsDialog() {
    const s = App.state.ipamSettings || {};
    const check = (id, label, on) =>
      `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}> ${label}</label>`;
    const number = (id, label, value, attrs = '') =>
      `<label>${label} <input id="${id}" type="number" ${attrs} value="${value}"></label>`;
    App.modal('IPAM settings', `
      <fieldset><legend>SCANNING</legend>
        ${check('i-enabled', 'Run the IPAM worker', s.enabled)}
        ${number('i-interval', 'Scan every', s.scan_interval_minutes, 'min=5')} minutes
        ${number('i-timeout', 'Ping timeout (ms)', s.ping_timeout_ms, 'min=100 step=100')}
        ${number('i-workers', 'Concurrent pings', s.ping_workers, 'min=1 max=256')}
        ${number('i-maxaddr', 'Largest subnet allowed (addresses)', s.max_scan_addresses, 'min=16 step=256')}
        <p class="hint">A subnet larger than this is refused when added, not silently truncated —
          raise it deliberately if you mean to sweep something this size. Conflict detection needs
          SappiWhere to be on the same network segment as a subnet; ARP does not cross a router,
          so a remote subnet still reports which addresses are alive, just not their MAC addresses.</p>
      </fieldset>
      <fieldset><legend>DHCP</legend>
        ${number('i-dhcp-interval', 'Poll every', s.dhcp_poll_interval_minutes, 'min=5')} minutes
        ${number('i-dhcp-timeout', 'Poll timeout (s)', s.dhcp_timeout_s, 'min=5')}
        ${check('i-resolve', 'Resolve discovered hosts to names', s.resolve_hosts)}
      </fieldset>
      <fieldset><legend>RETENTION</legend>
        ${number('i-host-days', 'Forget addresses not seen for', s.host_retention_days, 'min=1')} days
        ${number('i-conflict-days', 'Forget resolved conflicts after', s.conflict_retention_days, 'min=1')} days
        ${number('i-scan-days', 'Keep scan history for', s.scan_history_days, 'min=1')} days
        ${number('i-dhcp-history-days', 'Keep DHCP leased-IP history for', s.dhcp_history_days, 'min=7')} days
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const on = (id) => box.querySelector(id).checked;
        const num = (id) => Number(box.querySelector(id).value);
        await App.post('/api/settings', { scope: 'ipam', values: {
          enabled: on('#i-enabled'),
          scan_interval_minutes: num('#i-interval'),
          ping_timeout_ms: num('#i-timeout'),
          ping_workers: num('#i-workers'),
          max_scan_addresses: num('#i-maxaddr'),
          dhcp_poll_interval_minutes: num('#i-dhcp-interval'),
          dhcp_timeout_s: num('#i-dhcp-timeout'),
          resolve_hosts: on('#i-resolve'),
          host_retention_days: num('#i-host-days'),
          conflict_retention_days: num('#i-conflict-days'),
          scan_history_days: num('#i-scan-days'),
          dhcp_history_days: num('#i-dhcp-history-days'),
        } });
        await App.loadState();
        App.closeModal();
      } },
    ], { buttonsTop: true });
  }

  /* --------------------------------------------------------------- lifecycle */

  async function refresh() {
    await Promise.all([loadSubnets(), loadConflicts(), loadDhcpServers()]);
    drawStatus();
  }

  /* --------------------------------------------------------------- search

     The reverse direction from browsing a subnet: "what's the IP for
     printer-3rd-floor" or "who is aa:bb:cc:dd:ee:ff" rather than "what's
     on 10.20.3.0/24". Matches IP, MAC and hostname against everything
     IPAM has -- hosts its own sweep discovered, DHCP leases and
     reservations, and the shared reverse-DNS cache -- server-side (see
     Service.ipam_search), and shows whatever it finds in a modal rather
     than a dedicated view: this is a lookup, not something that needs
     its own place in the page. A result can land outside every subnet
     configured here; that's DHCP polling reading a server's scopes on
     its own, not this host being pulled from somewhere unexpected, and
     the Source column always says which of the three found it. */

  async function searchHosts() {
    const query = App.el('ipam-search-q').value.trim();
    if (query.length < 2) {
      App.modal('Find', '<p>Type at least two characters of a hostname, IP or MAC.</p>',
        [{ label: 'OK', primary: true, onClick: App.closeModal }]);
      return;
    }
    let payload;
    try {
      payload = await App.get('/api/ipam/search', { q: query });
    } catch (error) {
      App.modal('Find', `<p class="err">${escape(error.message)}</p>`,
        [{ label: 'OK', primary: true, onClick: App.closeModal }]);
      return;
    }
    App.modal(`Find: “${escape(query)}”`, resultsTable(payload.results),
      [{ label: 'Close', primary: true, onClick: App.closeModal }]);
  }

  function resultsTable(results) {
    if (!results.length) {
      return '<p>Nothing IPAM has discovered, been told about by DHCP, or '
        + 'resolved a name for matches that.</p>';
    }
    const rows = results.map((r) => `<tr>` +
      `<td>${escape(r.hostname || '—')}</td>` +
      `<td style="white-space:nowrap">${escape(r.ip)}</td>` +
      `<td style="white-space:nowrap">${escape(r.mac || '—')}</td>` +
      `<td>${r.alive == null ? '<span class="hint">not a discovered host</span>'
        : r.alive ? '<span class="sev sev-3">up</span>' : '<span class="sev sev-7">down</span>'}</td>` +
      `<td>${escape(r.subnet || '—')}</td>` +
      `<td class="hint">${escape(r.sources.join(', '))}</td>` +
      `</tr>`).join('');
    return `<div class="table-wrap" style="max-height:50vh">
      <table><thead><tr><th>Hostname</th><th>IP</th><th>MAC</th>
      <th>Status</th><th>Subnet</th><th>Source</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  }

  function init() {
    for (const btn of document.querySelectorAll('#page-ipam .subtab')) {
      btn.onclick = () => selectSub(btn.dataset.subtab);
    }
    App.el('ipam-settings').onclick = settingsDialog;
    App.el('ipam-add-subnet').onclick = addSubnet;
    App.el('ipam-edit-subnet').onclick = editSubnet;
    App.el('ipam-scan-now').onclick = scanNow;
    App.el('ipam-add-dhcp').onclick = addDhcpServer;
    App.el('ipam-edit-dhcp').onclick = editDhcpServer;
    App.el('ipam-poll-now').onclick = pollNow;
    App.el('ipam-dhcp-server-select').onchange = (event) => {
      view.dhcpServerId = Number(event.target.value) || null;
      view.dhcpScopeId = null;
      loadDhcpScopes();
    };
    App.el('ipam-scope-sort').onchange = (event) => {
      view.scopeSort = event.target.value;
      renderDhcpScopes();
    };
    App.el('ipam-alive-only').onchange = drawHosts;
    App.el('ipam-show-resolved').onchange = loadConflicts;
    App.el('ipam-search-btn').onclick = searchHosts;
    App.el('ipam-search-q').onkeydown = (e) => { if (e.key === 'Enter') searchHosts(); };
  }

  App.pages.ipam = { init, refresh, fastTick: drawStatus };
})();

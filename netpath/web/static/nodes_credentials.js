/* NODES' polling-profile dialogs (additional credentials included), fetched
   by App.loadExtra the first time Add, Edit, Remove or Set default is
   pressed on the Profiles subtab. Registers on App.extras, not App.pages. */
(() => {
  const escape = App.escapeHtml;

  // Set by init() on every entry (idempotent) so these bodies keep reading
  // them as free variables, same as in nodes.js. blankToNull itself stays
  // in nodes.js core (deviceOverrides needs it there too).
  let view, credentialBody, v3AuthOptions, v3PrivOptions, helpLinkNamed, levelText,
      mibOptionsHtml, identityOidFieldsHtml, identityOidValues, blankToNull;

  function init(ctx) {
    ({ view, credentialBody, v3AuthOptions, v3PrivOptions, helpLinkNamed, levelText,
       mibOptionsHtml, identityOidFieldsHtml, identityOidValues, blankToNull } = ctx);
  }

  /* A profile's own version/community/v3-user fields above are its always-
     present "primary" credential. This section manages the group_credentials
     list the poller falls back to, in order, for a device on this profile
     that doesn't answer the primary — a mix of vendors or SNMP versions on
     one profile. Requires the profile to already exist (a new, unsaved
     profile has nowhere to attach a credential row to yet — same rule the
     device-level credential form already follows). */

  function credentialSummary(c) {
    const ver = { 0: 'v1', 1: 'v2c', 3: 'v3' }[c.snmp_version] || c.snmp_version;
    const who = c.snmp_version === 3 ? (c.v3_user || '(no username)') : (c.community || '(no community)');
    return `${ver} · ${who}`;
  }

  function credentialsListHtml(credentials) {
    if (!credentials.length) return App.emptyState('No additional credentials yet.');
    const rows = credentials.map((c) => `
      <tr>
        <td>${escape(c.label || '—')}</td>
        <td>${escape(credentialSummary(c))}</td>
        <td>${c.snmp_version === 3
          ? escape((c.has_credential ? 'password stored' : 'no password yet') + levelText(c))
          : ''}</td>
        <td><button type="button" class="cred-remove" data-cred-id="${c.id}">Remove</button></td>
      </tr>`).join('');
    return `<table><caption class="sr-only">Stored credentials</caption><thead><tr><th scope="col">Label</th><th scope="col">Credential</th><th scope="col"></th><th scope="col"></th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  function addCredentialFormHtml() {
    return `
      <label>Label <input id="nd-pc-label" placeholder="optional, e.g. “Cisco gear”"></label>
      <label>SNMP version <select id="nd-pc-version">
        <option value="0">v1</option>
        <option value="1" selected>v2c</option>
        <option value="3">v3</option>
      </select></label>
      <label>Community (v1/v2c) <input id="nd-pc-community"></label>
      <label>v3 username <input id="nd-pc-v3user"></label>
      <label>v3 auth protocol <select id="nd-pc-authproto">
        ${v3AuthOptions()}
      </select></label>
      ${App.canStoreSecrets()
        ? '<label>v3 auth password <input id="nd-pc-authpass" type="password"></label>'
        : App.credentialUnavailableHtml('An SNMPv3 auth password')}
      <label>v3 privacy protocol <select id="nd-pc-privproto">
        ${v3PrivOptions()}
      </select></label>
      ${App.canStoreSecrets()
        ? '<label>v3 privacy password <input id="nd-pc-privpass" type="password"></label>'
        : App.credentialUnavailableHtml('An SNMPv3 privacy password')}
      <button type="button" id="nd-pc-add">Add credential</button>
      <p class="hint" id="nd-pc-status"></p>`;
  }

  function credentialsSectionHtml(g) {
    if (!g.id) {
      return `<fieldset><legend>ADDITIONAL CREDENTIALS</legend>
        <p class="hint">Save this profile first, then reopen Edit to add more
          credentials for it.</p></fieldset>`;
    }
    return `<fieldset><legend>ADDITIONAL CREDENTIALS</legend>
      <p class="hint">Tried, in order, after the primary credential above,
        for any device on this profile that doesn't answer it.</p>
      <div id="nd-p-creds-list">${credentialsListHtml(g.credentials || [])}</div>
      ${addCredentialFormHtml()}
    </fieldset>`;
  }

  async function refreshCredentialsList(box, groupId) {
    const payload = await App.get('/api/nodes/groups');
    const g = (payload.groups || []).find((x) => x.id === groupId);
    box.querySelector('#nd-p-creds-list').innerHTML = credentialsListHtml((g && g.credentials) || []);
    wireCredentialRemoveButtons(box, groupId);
  }

  function wireCredentialRemoveButtons(box, groupId) {
    for (const btn of box.querySelectorAll('.cred-remove')) {
      btn.onclick = () => {
        // Nested in the profile dialog, so reopen that on the way out —
        // unsaved edits to the profile's own fields are lost, which is the
        // same trade the wireless controller list already makes.
        App.confirmDestructive('Remove credential',
          '<p>Remove this stored SNMP credential from the profile?</p>' +
          '<p class="hint">Devices in this profile stop trying it on their next ' +
          'poll. Any device already using it falls back to the profile\'s other ' +
          'credentials.</p>', 'Remove', async () => {
            await App.del(`/api/nodes/groups/${groupId}/credentials/${btn.dataset.credId}`);
            view.configAt = 0;
          }, (confirmed) => { if (!confirmed) editProfile(); });
      };
    }
  }

  function wireCredentialsSection(box, groupId) {
    const addBtn = box.querySelector('#nd-pc-add');
    if (!addBtn) return;   // no groupId yet — the "save first" hint is shown instead
    const status = box.querySelector('#nd-pc-status');
    addBtn.onclick = async () => {
      const fields = {
        label: box.querySelector('#nd-pc-label').value.trim(),
        snmp_version: Number(box.querySelector('#nd-pc-version').value),
        community: box.querySelector('#nd-pc-community').value.trim(),
        v3_user: box.querySelector('#nd-pc-v3user').value.trim(),
        v3_auth_proto: box.querySelector('#nd-pc-authproto').value,
        v3_priv_proto: box.querySelector('#nd-pc-privproto').value || null,
      };
      status.innerHTML = '';
      addBtn.disabled = true;
      try {
        const credential = credentialBody(box, '#nd-pc-authpass', '#nd-pc-privpass', fields);
        // The credential row and its optional v3 password are two
        // separate requests — a DPAPI failure on the second (this
        // machine can't encrypt a stored secret) must not make it look
        // like "Add credential" silently did nothing: the row itself is
        // still created and shown, just without a password stored yet.
        const result = await App.post(`/api/nodes/groups/${groupId}/credentials`, fields);
        if (credential) {
          try {
            await App.post(`/api/nodes/groups/${groupId}/credentials/${result.id}/secret`,
              credential);
          } catch (error) {
            status.innerHTML = `<span class="err">Credential added, but its password ` +
              `wasn't stored: ${escape(error.message)}</span>`;
          }
        }
        await refreshCredentialsList(box, groupId);
        view.configAt = 0;
        // The password fields are absent on a host that cannot store secrets.
        for (const id of ['nd-pc-label', 'nd-pc-community', 'nd-pc-v3user',
          'nd-pc-authpass', 'nd-pc-privpass']) {
          const field = box.querySelector(`#${id}`);
          if (field) field.value = '';
        }
      } catch (error) {
        status.innerHTML = `<span class="err">${escape(error.message)}</span>`;
      } finally {
        addBtn.disabled = false;
      }
    };
    wireCredentialRemoveButtons(box, groupId);
  }

  function profileForm(g) {
    const p = g || {};
    return `
      <label>Name <input id="nd-p-name" value="${escape(p.name || '')}" ${p.is_default ? 'readonly' : ''}></label>
      <label>SNMP version <select id="nd-p-version">
        <option value="0" ${p.snmp_version === 0 ? 'selected' : ''}>v1</option>
        <option value="1" ${p.snmp_version === undefined || p.snmp_version === 1 ? 'selected' : ''}>v2c</option>
        <option value="3" ${p.snmp_version === 3 ? 'selected' : ''}>v3</option>
      </select></label>
      <label>Community (v1/v2c) <input id="nd-p-community" value="${escape(p.community || 'public')}"></label>
      <label>v3 username <input id="nd-p-v3user" value="${escape(p.v3_user || '')}"></label>
      <label>v3 auth protocol <select id="nd-p-authproto">
        ${v3AuthOptions(p.v3_auth_proto)}
      </select></label>
      ${App.canStoreSecrets()
        ? `<label>v3 auth password <input id="nd-p-authpass" type="password"
            placeholder="${p.has_credential ? 'stored — leave blank to keep' : ''}"></label>`
        : App.credentialUnavailableHtml('An SNMPv3 auth password')}
      <label>v3 privacy protocol <select id="nd-p-privproto">
        ${v3PrivOptions(p.v3_priv_proto)}
      </select></label>
      ${App.canStoreSecrets()
        ? `<label>v3 privacy password <input id="nd-p-privpass" type="password"
            placeholder="${p.has_priv_credential ? 'stored — leave blank to keep' : ''}"></label>`
        : App.credentialUnavailableHtml('An SNMPv3 privacy password')}
      <p class="hint">${p.security_level ? `This profile's v3 requests go out at <b>${escape(p.security_level)}</b>. ` : ''}An
        auth password alone is authNoPriv; add a privacy protocol and password for
        authPriv (what PAN-OS and most firewalls provision). Setting the privacy
        protocol to none drops the stored privacy password.</p>
      <label>Poll interval <input id="nd-p-interval" type="number" min="10" value="${p.poll_interval_s || 120}"> s</label>
      <label>SNMP timeout <input id="nd-p-timeout" type="number" step="0.5" min="0.5" value="${p.snmp_timeout_s || 3}"> s</label>
      <label>SNMP retries <input id="nd-p-retries" type="number" min="0" value="${p.snmp_retries != null ? p.snmp_retries : 2}"></label>
      <div class="row start">
        <label class="check"><input type="checkbox" id="nd-p-ping" ${p.ping_enabled !== false ? 'checked' : ''}> Ping</label>${helpLinkNamed('nodes.profile.ping', 'Ping')}
        <label class="check"><input type="checkbox" id="nd-p-snmp" ${p.snmp_enabled !== false ? 'checked' : ''}> SNMP</label>${helpLinkNamed('nodes.profile.snmp', 'SNMP')}
      </div>
      <label>Ping probes per poll <input id="nd-p-pingcount" type="number" min="1" max="20"
        placeholder="inherit" value="${p.ping_count ?? ''}"></label>
      <label>Ping timeout <input id="nd-p-pingtimeout" type="number" min="100" step="100"
        placeholder="inherit" value="${p.ping_timeout_ms ?? ''}"> ms</label>
      <label>Down needs both ping and SNMP to fail <select id="nd-p-pingonly">
        <option value="" ${p.unreachable_ping_only == null ? 'selected' : ''}>Inherit the Nodes setting</option>
        <option value="1" ${p.unreachable_ping_only === 1 ? 'selected' : ''}>Yes — SNMP failing alone is not down</option>
        <option value="0" ${p.unreachable_ping_only === 0 ? 'selected' : ''}>No — SNMP failing alone is down</option>
      </select></label>
      <p class="hint">Blank ping fields inherit the Nodes settings.</p>
      <label>Learn MAC addresses every <input id="nd-p-mactable" type="number" min="0"
        step="60" placeholder="inherit" value="${p.mac_table_interval_s ?? ''}"> s</label>
      <p class="hint">Walks each switch's forwarding table on this separate,
        slower schedule so MAC addresses can be searched for in the Find box.
        <b>0 switches it off</b>, and off is the default. A forwarding-table
        walk uses GETBULK, so it now costs only a few dozen SNMP requests per
        switch rather than hundreds to thousands — <b>300 (five minutes)</b>
        is a sensible starting point.</p>
      <label>Read the ARP cache every <input id="nd-p-arptable" type="number" min="0"
        step="60" placeholder="inherit" value="${p.arp_table_interval_s ?? ''}"> s</label>
      <p class="hint">Walks each router's ARP cache — which IP holds which MAC on
        which routed interface — for the device's ARP tab and the Find box.
        <b>Off by default</b>, and blank means off here rather than an hour: a
        distribution router's cache runs to tens of thousands of rows where
        an access switch's forwarding table runs to hundreds, so this is
        switched on per profile for the routers that matter rather than
        walked everywhere unasked. Entries age out on the same
        <b>Forget a learned MAC after</b> clock as the MAC table.</p>
      <label>Walk VLAN membership every <input id="nd-p-vlaninterval" type="number" min="0"
        step="60" placeholder="inherit" value="${p.vlan_interval_s ?? ''}"> s</label>
      <p class="hint">Per-port VLAN membership (Q-BRIDGE/CISCO-VTP, falling back to VLANs
        seen in the MAC table) — MAPPER's strand colours come from this. <b>3600 (one
        hour) is the shipped default</b>; an explicit 0 switches it off for every device
        on this profile that does not override it.</p>
      <label>Walk per-VLAN spanning tree every <input id="nd-p-stpinterval" type="number" min="30"
        step="60" placeholder="inherit" value="${p.stp_interval_s ?? ''}"> s</label>
      <p class="hint">PVST+ blocking state per VLAN, on its own cadence — not tied to the
        VLAN membership interval above, so a new block is found even with that walk off.
        <b>300 (five minutes) is the shipped default</b>.</p>
      <label>Custom MIB <select id="nd-p-mib">${mibOptionsHtml(p.mib_file_id, true)}</select></label>
      <p class="hint">Polls that MIB's own scalar objects for every device on this
        profile (unless a device overrides it), shown under its own names.</p>
      <fieldset><legend>IDENTITY</legend>
        ${identityOidFieldsHtml(p, true)}
      </fieldset>
      ${credentialsSectionHtml(p)}`;
  }

  function profileFields(box) {
    return {
      name: box.querySelector('#nd-p-name').value.trim(),
      snmp_version: Number(box.querySelector('#nd-p-version').value),
      community: box.querySelector('#nd-p-community').value.trim(),
      v3_user: box.querySelector('#nd-p-v3user').value.trim(),
      v3_auth_proto: box.querySelector('#nd-p-authproto').value,
      v3_priv_proto: box.querySelector('#nd-p-privproto').value || null,
      poll_interval_s: Number(box.querySelector('#nd-p-interval').value),
      snmp_timeout_s: Number(box.querySelector('#nd-p-timeout').value),
      snmp_retries: Number(box.querySelector('#nd-p-retries').value),
      ping_enabled: box.querySelector('#nd-p-ping').checked,
      snmp_enabled: box.querySelector('#nd-p-snmp').checked,
      // Blank means "inherit", which is NULL in the column, not 0 — a
      // Number('') of 0 would read as "never ping".
      ping_count: blankToNull(box.querySelector('#nd-p-pingcount').value),
      ping_timeout_ms: blankToNull(box.querySelector('#nd-p-pingtimeout').value),
      unreachable_ping_only: blankToNull(box.querySelector('#nd-p-pingonly').value),
      // Blank inherits (NULL); an explicit 0 means "never walk", which is
      // the shipped behaviour and a real choice, not the same as blank.
      mac_table_interval_s: blankToNull(box.querySelector('#nd-p-mactable').value),
      vlan_interval_s: blankToNull(box.querySelector('#nd-p-vlaninterval').value),
      arp_table_interval_s: blankToNull(box.querySelector('#nd-p-arptable').value),
      stp_interval_s: blankToNull(box.querySelector('#nd-p-stpinterval').value),
      mib_file_id: Number(box.querySelector('#nd-p-mib').value) || null,
      ...identityOidValues(box, true),
    };
  }

  function addProfile() {
    const box = App.modal('Add polling profile', profileForm({}), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (box) => {
        const fields = profileFields(box);
        if (!fields.name) return;
        const credential = credentialBody(box, '#nd-p-authpass', '#nd-p-privpass', fields);
        const result = await App.post('/api/nodes/groups', fields);
        if (credential) {
          await App.post(`/api/nodes/groups/${result.id}/credential`, credential);
        }
        App.closeModal();
        view.configAt = 0;
        App.refreshNow('nodes');
      } },
    ]);
    box.classList.add('wide');
  }

  function editProfile() {
    const g = view.groups.find((x) => x.id === view.groupSelected);
    if (!g) return;
    const box = App.modal(`Edit ${g.name}`, profileForm(g), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (box) => {
        const fields = profileFields(box);
        const credential = credentialBody(box, '#nd-p-authpass', '#nd-p-privpass', fields);
        await App.put(`/api/nodes/groups/${g.id}`, fields);
        if (credential) {
          await App.post(`/api/nodes/groups/${g.id}/credential`, credential);
        }
        App.closeModal();
        view.configAt = 0;
        App.refreshNow('nodes');
      } },
    ]);
    box.classList.add('wide');
    wireCredentialsSection(box, g.id);
  }

  function profileStatus(message, isError) {
    const el = App.el('nd-profile-status');
    el.innerHTML = isError ? `<span class="err">${escape(message)}</span>` : escape(message || '');
    if (message) App.announce(message);
  }

  function removeProfile() {
    const g = view.groups.find((x) => x.id === view.groupSelected);
    if (!g) return;
    // The refusal used to close the dialog and put the reason on the page
    // behind it, where a profile the operator had just been editing was no
    // longer on screen. It now stays in the dialog that asked.
    App.confirmDestructive('Remove profile',
      `<p>Remove <b>${escape(g.name)}</b>?${g.is_default
        ? ' It is currently the default profile — another remaining profile becomes default in its place.'
        : ' Devices using it fall back to the Default profile.'}</p>`,
      'Remove',
      () => App.del(`/api/nodes/groups/${g.id}`),
      (confirmed) => {
        if (!confirmed) return;
        profileStatus('');
        view.groupSelected = null;
        view.configAt = 0;
        App.refreshNow('nodes');
      });
  }

  async function setDefaultProfile() {
    const g = view.groups.find((x) => x.id === view.groupSelected);
    if (!g || g.is_default) return;
    try {
      await App.post(`/api/nodes/groups/${g.id}/default`, {});
    } catch (error) {
      profileStatus(error.message, true);
      return;
    }
    profileStatus(`${g.name} is now the default profile.`);
    view.configAt = 0;
    App.refreshNow('nodes');
  }

  App.extras.nodesCredentials = { init, addProfile, editProfile, removeProfile, setDefaultProfile };
})();

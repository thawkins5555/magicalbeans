/* MAPPER's upstream-suggestions dialog, cut out of mapper.js (5.13.0) and
   fetched by App.loadExtra the first time the button is pressed. It is an
   extension of that page, not a tab module: it registers on App.extras
   rather than App.pages and needs nothing of mapper.js's own state. */
(() => {
  const escape = App.escapeHtml;

  /* ------------------------------------------------ upstream suggestions

     Rolling a device's alerts up under its upstream's outage (alertrules.py's
     ROLLED_UP_BY) needs devices.upstream_id set, and a guessed neighbour
     match may never drive that on its own. nodesdb.upstream_suggestions()
     turns the same LLDP/CDP matches into candidates for this dialog, which
     is what turns one into an operator's decision. Nothing here ever
     applies one by itself — every assignment sent to the apply route came
     from a checkbox or a radio an operator actually set.

     It lives on MAPPER because reviewing the fleet's L2 parentage is what
     this page is for; it sat on Nodes only because Nodes is where the
     TOPOLOGY subtab it shipped on used to be. The two routes behind it
     stay NODES-gated — what Apply writes is devices.upstream_id, a Nodes
     field, and a mapper-gated alias would hand a mapper-only account a
     Nodes write. So Apply is offered against App.canWrite('nodes'), not
     this page's own module, and an account with no Nodes grant at all is
     refused by the route rather than by anything here — the toast carries
     the server's own reason, which is the only place that knows it. The
     list is fleet-wide, so unlike everything in the action bar it works
     with no map selected and is not in drawToolbarState's gates. */

  const CONFIDENCE_COLOR = { high: 'var(--ok)', medium: 'var(--warn)', low: 'var(--muted)' };
  const MATCH_KIND_LABEL = { chassis_mac: 'MAC address match', sys_name: 'name match' };

  // nodes.js's display-name precedence, copied for the same reason the
  // device-status vocabulary above is: reaching into another lazy module is
  // what test_frontend_contracts' rule forbids, and App.deviceIndex hands
  // back the raw device rows either way.
  function deviceDisplayName(d) {
    if (d.display_name_source === 'manual') return d.name || d.ip;
    return d.sys_name || d.name || d.ip;
  }

  function confidenceBadgeHtml(c) {
    return `<span style="color:${CONFIDENCE_COLOR[c.confidence] || 'var(--muted)'}">${
      escape(c.confidence)}</span>`;
  }

  /* What lets an operator say "yes, that is the uplink" without opening a
     cable schedule: which protocol(s) saw it, on which of THIS device's own
     ports, and whether the neighbour that reported it is still there. A
     confidence word alone is a number asking to be trusted; this is the
     evidence behind it. */
  function candidateEvidenceHtml(c) {
    const proto = (c.protocols || []).map((p) => p.toUpperCase()).join('/') || '—';
    const port = c.local_port ? ` on ${escape(c.local_port)}` : '';
    const stale = c.stale
      ? ' <span class="warn-text">— stale, not seen on the last walk</span>' : '';
    return `${escape(MATCH_KIND_LABEL[c.match_kind] || c.match_kind)}${port} ` +
      `(${escape(proto)})${stale} · last seen ${App.ago(c.seen_ts)}`;
  }

  /* The apply route's own cycle guard names the devices it walked as bare
     ids ("...through device(s): 41 -> 42 -> 41") — correct for a server
     that has no reason to hold display names, useless to an operator who
     was never shown an id anywhere else in this dialog. Resolved through
     the same shared device index every cross-module device link already
     uses, rather than a second lookup invented for this one error. Falls
     back to the original message untouched if the wording ever changes
     under this — a mis-parsed guess would be worse than the ids. */
  async function humanizeUpstreamCycleError(error) {
    const message = (error && error.message) || '';
    const marker = 'device(s): ';
    const at = message.indexOf(marker);
    if (at === -1) return error;
    const ids = message.slice(at + marker.length).split('->')
      .map((s) => s.trim()).filter(Boolean);
    if (!ids.length || !ids.every((s) => /^\d+$/.test(s))) return error;
    const { byId } = await App.deviceIndex();
    const names = ids.map((idText) => {
      const device = byId.get(Number(idText));
      return device ? deviceDisplayName(device) : `device ${idText}`;
    });
    return new Error(message.slice(0, at + marker.length) + names.join(' -> '));
  }

  /* Both suggestion shapes name two devices, and both are in Nodes. The
     plain escaped form stays alongside the link because the checkbox's
     aria-label reads it, and an <a> in an attribute is markup, not a link. */
  const suggestionName = (s) => s.device_name || s.device_ip || `device ${s.device_id}`;
  const candidateLink = (c) => (c.matched_device_name
    ? App.deviceNameLink(c.matched_device_name, { id: c.matched_device_id })
    : '—');

  function confidentSuggestionRowHtml(s, writable) {
    const c = s.candidates[0];
    const label = escape(suggestionName(s));
    return `<tr data-device-id="${s.device_id}">
      <td><input type="checkbox" class="us-confident-check" data-device-id="${s.device_id}"
        data-upstream-id="${c.matched_device_id}" data-confidence="${escape(c.confidence)}"
        aria-label="Set upstream for ${label}"${writable ? '' : ' disabled'}></td>
      <td>${App.deviceNameLink(suggestionName(s), { id: s.device_id })}</td>
      <td>${candidateLink(c)}</td>
      <td>${candidateEvidenceHtml(c)}</td>
      <td>${confidenceBadgeHtml(c)}</td>
    </tr>`;
  }

  /* Two or more plausible upstreams for the same device is not a list to
     tick — every candidate is shown, but the only way to act on one is to
     pick it by hand, one radio group per device; "Skip — decide later" is
     what a device starts on and what leaving it alone means, said outright
     rather than left as an absence nothing here would otherwise explain. */
  function ambiguousSuggestionBlockHtml(s, writable) {
    const label = App.deviceNameLink(suggestionName(s), { id: s.device_id });
    const name = `us-amb-${s.device_id}`;
    const options = s.candidates.map((c) => `
      <label class="check"><input type="radio" name="${name}" class="us-amb-pick"
        data-device-id="${s.device_id}" value="${c.matched_device_id}"${writable ? '' : ' disabled'}>
        ${candidateLink(c)} — ${candidateEvidenceHtml(c)} ${confidenceBadgeHtml(c)}</label>`
    ).join('');
    return `<div class="us-amb-block">
      <p><b>${label}</b> — ${s.candidates.length} possible upstream(s), pick one</p>
      <label class="check"><input type="radio" name="${name}" class="us-amb-pick"
        data-device-id="${s.device_id}" value="" checked${writable ? '' : ' disabled'}>
        Skip — decide later</label>
      ${options}
    </div>`;
  }

  async function upstreamSuggestionsDialog() {
    let payload;
    try {
      payload = await App.get('/api/nodes/upstream-suggestions');
    } catch (error) {
      App.toast(`Could not read upstream suggestions: ${error.message}`, 'fail');
      return;
    }
    const suggestions = payload.suggestions || [];
    const writable = App.canWrite('nodes');
    if (!suggestions.length) {
      // total: 0 covers a few different situations an operator reads very
      // differently — LLDP/CDP has never walked; it walked and nothing
      // reported resolved to a known device; or it resolved plenty, but
      // every one of those devices already has an upstream set. lldp_walks
      // (node_poller's own counter, already on App.state from every poll)
      // tells the first apart from the rest for free; the rest collapse
      // into one honest sentence rather than a second fetch to tell them
      // apart.
      const walks = ((App.state.serverState || {}).nodes || {}).counters || {};
      const lead = !walks.lldp_walks
        ? 'No suggestions yet. Neighbour discovery (LLDP/CDP) runs as ' +
          'part of the regular poll cycle and has not completed a walk yet ' +
          '— check back once devices have been polled a few times.'
        : 'No upstream suggestions right now — either every device with a ' +
          'matched neighbour already has an upstream set, or none of the ' +
          'reported neighbours matched another device in this fleet.';
      App.modal('Upstream suggestions', `<p class="hint">${lead}</p>`,
        [{ label: 'Close', onClick: App.closeModal }]);
      return;
    }
    const confident = suggestions.filter((s) => !s.ambiguous);
    const ambiguous = suggestions.filter((s) => s.ambiguous);
    const box = App.modal('Upstream suggestions', `
      <p class="hint">Matches against ${confident.length + ambiguous.length} device(s) with
        no upstream set, from LLDP/CDP neighbours already matched to a device in this fleet.
        ${writable ? 'Nothing is applied until you press Apply.'
                   : 'Read-only: needs Nodes write to apply.'}</p>
      ${confident.length ? `
      <div class="bar wrap"><span class="section">CONFIDENT MATCHES — ${confident.length} device(s)</span>
        <span class="grow"></span>
        <span id="us-selected-count" class="hint"></span>
        ${writable ? `<button type="button" id="us-select-high">Select all high-confidence</button>
        <button type="button" id="us-select-none">Clear selection</button>` : ''}</div>
      <div class="table-wrap scrollbox large"><table id="us-confident-table">
        <caption class="sr-only">Confident upstream matches</caption>
        <thead><tr><th scope="col"></th><th scope="col">Device</th><th scope="col">Matched upstream</th>
          <th scope="col">Evidence</th><th scope="col">Confidence</th></tr></thead>
        <tbody>${confident.map((s) => confidentSuggestionRowHtml(s, writable)).join('')}</tbody>
      </table></div>` : ''}
      ${ambiguous.length ? `
      <div class="bar"><span class="section">AMBIGUOUS — ${ambiguous.length} device(s), pick one</span></div>
      <div class="scrollbox large">
        ${ambiguous.map((s) => ambiguousSuggestionBlockHtml(s, writable)).join('')}
      </div>` : ''}`, [
      { label: 'Cancel', onClick: App.closeModal },
      ...(writable ? [{ label: 'Apply', primary: true, onClick: async (dialogBox, button) => {
        const assignments = [];
        for (const cb of dialogBox.querySelectorAll('.us-confident-check:checked')) {
          assignments.push({ device_id: Number(cb.dataset.deviceId),
                            upstream_id: Number(cb.dataset.upstreamId) });
        }
        for (const radio of dialogBox.querySelectorAll('.us-amb-pick:checked')) {
          if (!radio.value) continue;   // "Skip — decide later"
          assignments.push({ device_id: Number(radio.dataset.deviceId),
                            upstream_id: Number(radio.value) });
        }
        if (!assignments.length) {
          throw new Error('Nothing selected — tick a confident match, or pick one for an ambiguous device.');
        }
        return App.runJob(button, { queued: 'Applying…',
          done: (result) => `Applied ${result.updated}.` }, (async () => {
          let result;
          try {
            result = await App.post('/api/nodes/upstream-suggestions/apply', { assignments });
          } catch (error) {
            throw await humanizeUpstreamCycleError(error);
          }
          App.closeModal();
          // What the batch wrote is a Nodes field, so Nodes is the page
          // that has to redraw — a no-op when that module has not been
          // loaded in this session, which is the common case from here.
          App.refreshNow('nodes');
          return result;
        })());
      } }] : []),
    ], { buttonsTop: true });
    box.classList.add('wide');
    if (writable) {
      const updateSelectedCount = () => {
        const n = box.querySelectorAll('.us-confident-check:checked').length +
          box.querySelectorAll('.us-amb-pick:checked:not([value=""])').length;
        const el = box.querySelector('#us-selected-count');
        if (el) el.textContent = n ? `${n} selected` : '';
      };
      box.addEventListener('change', updateSelectedCount);
      const selectHigh = box.querySelector('#us-select-high');
      if (selectHigh) selectHigh.onclick = () => {
        for (const cb of box.querySelectorAll('.us-confident-check')) {
          cb.checked = cb.dataset.confidence === 'high';
        }
        updateSelectedCount();
      };
      const selectNone = box.querySelector('#us-select-none');
      if (selectNone) selectNone.onclick = () => {
        for (const cb of box.querySelectorAll('.us-confident-check')) cb.checked = false;
        updateSelectedCount();
      };
    }
  }

  App.extras.mapperUpstream = { dialog: upstreamSuggestionsDialog };
})();

/* The NetPath page: destination list, route graph and the three-lane timeline.
   Both drawings are SVG built by hand, mirroring what the desktop widgets drew. */
(() => {
  const NODE_W = 212, NODE_H = 66, COL_GAP = 54, ROW_GAP = 18;
  const PAD_X = 10, TICKS_H = 7, LABEL_H = 13, LANE_GAP = 9, AXIS_H = 20;
  const STATUS_H = 26, MIN_BLOCK_PX = 3;
  const LANE_ORDER = ['rtt', 'loss', 'status'];

  const STATUS_COLOR = {
    ok: 'var(--ok)', warn: 'var(--warn)', fail: 'var(--fail)',
    blocked: 'var(--blocked)', overrun: 'var(--overrun)',
    error: 'var(--error)', none: 'var(--nodata)',
  };
  const STATUS_LABEL = {
    ok: 'Healthy', warn: 'Degraded', fail: 'No reply',
    blocked: 'Refused (ICMP unreachable)',
    overrun: 'Skipped — previous trace still running',
    error: 'Probe failed', none: 'No data',
  };

  const view = {
    targets: [],
    targetId: null,
    windows: {},
    windowFor: null,
    t0: Date.now() / 1000 - 3600,
    t1: Date.now() / 1000,
    follow: true,
    pinned: null,
    expanded: new Set(),
    expandAll: false,
    zoom: 1,
    userZoom: false,
    pan: { x: 0, y: 0 },
    frame: null,
    panDrag: null,
    dragMoved: false,
    timeline: null,
    topology: null,
    drag: null,
  };

  /* ----------------------------------------------------------- helpers */

  const clampSpan = (s) => Math.min(Math.max(s, 60), 2592000 * 4);

  /* ------------------------------------------- per-destination windows */

  /* One window for the whole page meant switching destinations dragged the
     last one's range along: a link you watch by the hour and one you watch by
     the minute could not both keep their own. Each destination now remembers
     its own, in this browser. */
  const WINDOW_KEY = 'sappiwhere.netpath.windows';
  const DEFAULT_RANGE = 3600;

  function loadWindows() {
    try {
      const stored = JSON.parse(localStorage.getItem(WINDOW_KEY) || '{}');
      return stored && typeof stored === 'object' ? stored : {};
    } catch (error) {
      return {};
    }
  }

  function saveWindows() {
    try {
      localStorage.setItem(WINDOW_KEY, JSON.stringify(view.windows));
    } catch (error) { /* private browsing, or storage full: not worth failing */ }
  }

  function rememberWindow() {
    if (view.targetId === null) return;
    view.windows[String(view.targetId)] = {
      t0: view.t0, t1: view.t1, follow: view.follow,
      range: App.el('range-select').value,
    };
    saveWindows();
  }

  function applyWindow(targetId) {
    view.windowFor = targetId;
    const select = App.el('range-select');
    const stored = targetId === null ? null : view.windows[String(targetId)];
    if (!stored) {
      // A destination seen for the first time starts on the page's own
      // default rather than inheriting whatever the last one was showing.
      const now = Date.now() / 1000;
      view.t0 = now - DEFAULT_RANGE;
      view.t1 = now;
      view.follow = true;
      select.value = String(DEFAULT_RANGE);
    } else {
      view.follow = stored.follow !== false;
      if (view.follow) {
        // A following window is anchored to now, not to whenever it was left.
        view.t1 = Date.now() / 1000;
        view.t0 = view.t1 - Math.max(stored.t1 - stored.t0, 60);
      } else {
        view.t0 = stored.t0;
        view.t1 = stored.t1;
      }
      if (stored.range) select.value = stored.range;
    }
    App.el('tl-follow').checked = view.follow;
    rememberWindow();
  }

  /* Destinations come and go; without this the key would grow forever. */
  function pruneWindows() {
    const live = new Set(view.targets.map((t) => String(t.id)));
    let dropped = false;
    for (const key of Object.keys(view.windows)) {
      if (!live.has(key)) {
        delete view.windows[key];
        dropped = true;
      }
    }
    if (dropped) saveWindows();
  }

  function setWindow(t0, t1, follow) {
    if (t1 - t0 < 60) t1 = t0 + 60;
    view.t0 = t0; view.t1 = t1;
    if (follow !== undefined) {
      view.follow = follow;
      App.el('tl-follow').checked = follow;
    }
    rememberWindow();
    App.refreshNow('netpath');
  }

  function zoom(factor) {
    const s = clampSpan((view.t1 - view.t0) * factor);
    if (view.follow) setWindow(view.t1 - s, view.t1);
    else {
      const mid = (view.t0 + view.t1) / 2;
      setWindow(mid - s / 2, mid + s / 2);
    }
  }

  function pan(fraction) {
    const shift = (view.t1 - view.t0) * fraction;
    setWindow(view.t0 + shift, view.t1 + shift, false);
  }

  function resetWindow() {
    const seconds = Number(App.el('range-select').value) || 3600;
    const now = Date.now() / 1000;
    setWindow(now - seconds, now, true);
  }

  /* ------------------------------------------------------ destinations */

  function currentTarget() {
    return view.targets.find((t) => t.id === view.targetId) || null;
  }

  /* The terms this destination is judged by, in one line. Without these the
     colours on the timeline are a verdict with the criteria hidden. */
  function renderTerms() {
    const t = currentTarget();
    const el = App.el('target-terms');
    if (!t) { el.textContent = ''; return; }
    const budget = Math.round(t.max_hops * t.probes * t.timeout_s + 15);
    el.innerHTML =
      `<b>every</b> ${App.span(t.interval_s)} · ` +
      `<b>warn above</b> ${t.warn_rtt_ms} ms or ${t.warn_loss}% loss · ` +
      `<b>probe</b> ${t.max_hops} hops × ${t.probes} at ${t.timeout_s}s ` +
      `(worst case ${budget}s)`;
  }

  function renderTargets() {
    const list = App.el('target-list');
    list.innerHTML = '';
    for (const target of view.targets) {
      const li = document.createElement('li');
      li.className = target.id === view.targetId ? 'selected' : '';
      li.onclick = () => {
        view.targetId = target.id;
        App.setRoute([target.id]);
        view.pinned = null;
        view.expanded.clear();
        view.expandAll = false;
        view.userZoom = false;
        renderTargets();
        App.refreshNow('netpath');
      };
      const dot = document.createElement('span');
      dot.className = 'dot';
      dot.style.background = target.status === 'none'
        ? 'transparent' : STATUS_COLOR[target.status];
      if (target.status === 'none') dot.style.border = '1px solid var(--line)';
      // The dot was the only signal of a destination's state, and three of
      // the six colours are the same khaki to a deuteranope. The word goes
      // in the title for a mouse and in an sr-only span for everything else.
      const statusWord = STATUS_LABEL[target.status] || target.status || 'No data';
      dot.title = statusWord;
      const spoken = document.createElement('span');
      spoken.className = 'sr-only';
      spoken.textContent = `${statusWord}: `;
      const text = document.createElement('span');
      text.innerHTML = `<div class="name">${escape(target.label)}` +
                       (target.hop_probe_enabled
                         ? ' <span title="Continuous per-hop probing is on for this destination" style="color:var(--accent);font-size:var(--fs-2xs);font-weight:700;">MTR</span>'
                         : '') +
                       `</div><div class="host">${escape(target.host)}</div>`;
      li.append(dot, spoken, text);
      list.appendChild(li);
    }
  }

  // One implementation, in app.js. This was twelve copies of the same
  // three lines, which is how one of them came to be missing a
  // character while the others were not.
  const escape = App.escapeHtml;

  function targetForm(target) {
    const d = App.state.settings;
    const t = target || {};
    const field = (label, id, value, attrs = '') =>
      `<label>${label} <input id="${id}" ${attrs} value="${value}"></label>`;
    return `
      <fieldset><legend>DESTINATION</legend>
        ${field('Host', 'f-host', escape(t.host ?? ''))}
        ${field('Name', 'f-label', escape(t.label ?? ''))}
      </fieldset>
      <fieldset><legend>PROBE</legend>
        ${field('Trace every (s)', 'f-interval', t.interval_s ?? d.default_interval_s, 'type=number min=15')}
        ${field('Max hops', 'f-hops', t.max_hops ?? d.default_max_hops, 'type=number min=1 max=64')}
        ${field('Probes per hop', 'f-probes', t.probes ?? d.default_probes, 'type=number min=1 max=10')}
        ${field('Probe timeout (s)', 'f-timeout', t.timeout_s ?? d.default_timeout_s, 'type=number min=0.5 step=0.5')}
        <p class="hint" id="f-budget"></p>
      </fieldset>
      <fieldset><legend>THRESHOLDS</legend>
        ${field('Warn above (ms)', 'f-warn-rtt', t.warn_rtt_ms ?? d.default_warn_rtt_ms, 'type=number min=1')}
        ${field('Warn at loss (%)', 'f-warn-loss', t.warn_loss ?? d.default_warn_loss, 'type=number min=0 max=100')}
      </fieldset>
      ${target ? `
      <fieldset><legend>CONTINUOUS PROBING</legend>
        <label class="check"><input type="checkbox" id="f-hop-probe" ${t.hop_probe_enabled ? 'checked' : ''}>
          Ping every hop continuously for live loss/RTT (MTR-style)</label>
        <p class="hint">Adds a steady stream of ICMP pings to each hop on this
          path, on top of the scheduled traceroute above. Off by default —
          only turn this on for paths you want to watch closely, since it is
          sustained extra traffic for as long as it stays on.</p>
      </fieldset>` : ''}`;
  }

  function wireBudget(box) {
    const update = () => {
      const hops = Number(box.querySelector('#f-hops').value) || 30;
      const probes = Number(box.querySelector('#f-probes').value) || 3;
      const timeout = Number(box.querySelector('#f-timeout').value) || 2;
      box.querySelector('#f-budget').textContent =
        `A dead destination ties up a worker for up to ` +
        `${Math.round(hops * probes * timeout + 15)}s with these settings.`;
    };
    for (const id of ['#f-hops', '#f-probes', '#f-timeout']) {
      box.querySelector(id).oninput = update;
    }
    update();
  }

  function readTargetForm(box) {
    const value = (id) => box.querySelector(id).value;
    const probeEl = box.querySelector('#f-hop-probe');
    return {
      host: value('#f-host').trim(),
      label: value('#f-label').trim(),
      interval_s: Number(value('#f-interval')),
      max_hops: Number(value('#f-hops')),
      probes: Number(value('#f-probes')),
      timeout_s: Number(value('#f-timeout')),
      warn_rtt_ms: Number(value('#f-warn-rtt')),
      warn_loss: Number(value('#f-warn-loss')),
      // Only present on the edit form — a target must exist before it can
      // opt in to continuous probing.
      ...(probeEl ? { hop_probe_enabled: probeEl.checked } : {}),
    };
  }

  async function addTarget() {
    const box = App.modal('Add destination', targetForm(null), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        try {
          const payload = await App.post('/api/netpath/targets', readTargetForm(b));
          view.targetId = payload.id;
          App.closeModal();
          await refresh();
        } catch (error) {
          b.querySelector('#f-budget').innerHTML =
            `<span class="err">${escape(error.message)}</span>`;
        }
      } },
    ]);
    wireBudget(box);
  }

  async function editTarget() {
    const target = view.targets.find((t) => t.id === view.targetId);
    if (!target) return;
    const box = App.modal('Edit destination', targetForm(target), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (b) => {
        await App.put(`/api/netpath/targets/${target.id}`, readTargetForm(b));
        App.closeModal();
        await refresh();
      } },
    ]);
    wireBudget(box);
  }

  async function removeTarget() {
    const target = view.targets.find((t) => t.id === view.targetId);
    if (!target) return;
    App.confirmDestructive('Remove destination',
      `<p>Remove <b>${escape(target.label)}</b> and all of its stored traces?</p>`,
      'Remove',
      () => App.del(`/api/netpath/targets/${target.id}`),
      (confirmed) => {
        if (!confirmed) return;
        view.targetId = null;
        refresh();
      });
  }

  async function netpathSettings() {
    const s = App.state.settings;
    const box = App.modal('NetPath settings', `
      <fieldset><legend>MONITORING</legend>
        <label>Concurrent traces <input id="s-workers" type="number" min="1" max="64" value="${s.trace_workers}"></label>
        <label>Keep traces for <input id="s-retention" type="number" min="1" max="3650" value="${s.trace_retention_days}"> days</label>
        <p class="hint">Traces wait on a subprocess rather than the CPU, so extra workers are
          cheap. Raise this if the Debug page shows destinations sitting in queued.</p>
        <label>Drop hops unseen for <input id="s-stale" type="number" min="0" step="1"
          value="${s.topology_stale_hours}"> hours</label>
        <p class="hint">A router that leaves the path stops being drawn once it has been
          absent this long, so the diagram shows the current path rather than every
          address ever seen. Measured against the end of the window you are looking at,
          so scrolling back through history still draws the path as it was then. 0 keeps
          every hop the window covers.</p>
      </fieldset>
      <fieldset><legend>DEFAULTS FOR NEW DESTINATIONS</legend>
        <label>Trace every <input id="s-interval" type="number" min="15" value="${s.default_interval_s}"> s</label>
        <label>Max hops <input id="s-hops" type="number" min="1" max="64" value="${s.default_max_hops}"></label>
        <label>Probes per hop <input id="s-probes" type="number" min="1" max="10" value="${s.default_probes}"></label>
        <label>Probe timeout <input id="s-timeout" type="number" min="0.5" step="0.5" value="${s.default_timeout_s}"> s</label>
        <label>Warn above <input id="s-warn-rtt" type="number" min="1" value="${s.default_warn_rtt_ms}"> ms</label>
        <label>Warn at loss <input id="s-warn-loss" type="number" min="0" max="100" value="${s.default_warn_loss}"> %</label>
        <p class="hint">These only seed the Add dialog. Changing them leaves existing
          destinations alone.</p>
      </fieldset>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (b) => {
        const n = (id) => Number(b.querySelector(id).value);
        await App.post('/api/settings', { scope: 'netpath', values: {
          trace_workers: n('#s-workers'),
          trace_retention_days: n('#s-retention'),
          topology_stale_hours: n('#s-stale'),
          default_interval_s: n('#s-interval'),
          default_max_hops: n('#s-hops'),
          default_probes: n('#s-probes'),
          default_timeout_s: n('#s-timeout'),
          default_warn_rtt_ms: n('#s-warn-rtt'),
          default_warn_loss: n('#s-warn-loss'),
        } });
        await App.loadState();
        App.closeModal();
      } },
    ]);
    return box;
  }

  /* ------------------------------------------------------- route graph */

  function silentRuns(topo) {
    return (topo.silent_runs || []).map(([a, b]) => [a, b]);
  }

  function drawRoute() {
    const svg = App.el('route-svg');
    svg.innerHTML = '';
    const topo = view.topology;
    const box = App.el('route-canvas').getBoundingClientRect();
    const width = Math.max(box.width, 200), height = Math.max(box.height, 200);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

    if (!topo || !topo.nodes.length) {
      const message = topo && topo.snapshot && topo.snapshot.found === false
        && view.pinned ? 'No trace recorded near that time.' : 'No traces in this window.';
      svg.appendChild(App.svgNode('text', {
        x: width / 2, y: height / 2, 'text-anchor': 'middle',
        fill: 'var(--canvas-faint)', 'font-size': 'var(--fs-sm)',
      }, message));
      return;
    }

    const byKey = Object.fromEntries(topo.nodes.map((n) => [n.key, n]));
    const runs = silentRuns(topo);
    const collapsed = runs.filter(([a, b]) => !view.expanded.has(`${a}-${b}`));
    const expanded = runs.filter(([a, b]) => view.expanded.has(`${a}-${b}`));

    const ttls = Object.keys(topo.columns).map(Number).sort((a, b) => a - b);
    const slots = [];
    for (const ttl of ttls) {
      const run = collapsed.find(([a, b]) => ttl >= a && ttl <= b);
      if (!run) slots.push({ kind: 'nodes', ttl });
      else if (ttl === run[0]) slots.push({ kind: 'collapsed', run });
    }

    const anchors = {};      // id -> {left, right, y}
    const keyToId = {};
    const columnX = {};
    const group = App.svgNode('g');
    const edgeLayer = App.svgNode('g');
    const nodeLayer = App.svgNode('g');
    group.append(edgeLayer, nodeLayer);
    svg.appendChild(group);

    nodeLayer.appendChild(nodeBox(0, -NODE_H / 2, {
      label: 'this host', hostname: '', rtt: null, share: 1,
      is_destination: false, is_timeout: false, refusal: null, eyebrow: 'Source',
    }));
    anchors.origin = { left: 0, right: NODE_W, y: 0 };

    slots.forEach((slot, index) => {
      const x = (index + 1) * (NODE_W + COL_GAP);
      if (slot.kind === 'collapsed') {
        const [start, end] = slot.run;
        nodeLayer.appendChild(collapsedBox(x, -NODE_H / 2, start, end));
        anchors[`c${start}-${end}`] = { left: x, right: x + NODE_W, y: 0 };
        for (let ttl = start; ttl <= end; ttl += 1) {
          columnX[ttl] = x;
          for (const key of topo.columns[String(ttl)] || []) {
            keyToId[key] = `c${start}-${end}`;
          }
        }
        return;
      }
      const keys = topo.columns[String(slot.ttl)] || [];
      columnX[slot.ttl] = x;
      const block = keys.length * NODE_H + (keys.length - 1) * ROW_GAP;
      let y = -block / 2;
      // Above the top of this column, not a fixed offset: a single-node column
      // starts at -33 and a fixed -30 label landed inside the box.
      nodeLayer.appendChild(App.svgNode('text', {
        x, y: y - 8, fill: 'var(--canvas-faint)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)', 'font-weight': 700,
      }, `HOP ${slot.ttl}`));
      for (const key of keys) {
        const node = byKey[key];
        nodeLayer.appendChild(nodeBox(x, y, node));
        anchors[key] = { left: x, right: x + NODE_W, y: y + NODE_H / 2 };
        keyToId[key] = key;
        y += NODE_H + ROW_GAP;
      }
    });

    for (const [start, end] of expanded) {
      if (columnX[start] === undefined || columnX[end] === undefined) continue;
      const left = columnX[start];
      const w = columnX[end] + NODE_W - left;
      const tab = App.svgNode('g', { class: 'run-tab', style: 'cursor:pointer' });
      tab.appendChild(App.svgNode('rect', {
        x: left, y: -54, width: w, height: 18, rx: 4,
        fill: 'none', stroke: 'var(--canvas-faint)', 'stroke-dasharray': '4 3',
      }));
      tab.appendChild(App.svgNode('text', {
        x: left + w / 2, y: -42, 'text-anchor': 'middle',
        fill: 'var(--canvas-faint)', 'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, `${end - start + 1} silent hops — click to collapse`));
      tab.onclick = () => {
        if (view.dragMoved) return;
        view.expanded.delete(`${start}-${end}`);
        drawRoute();
      };
      nodeLayer.appendChild(tab);
    }

    const links = new Map();
    const addLink = (src, dst, share) => {
      if (!src || !dst || src === dst) return;
      const id = `${src}>${dst}`;
      links.set(id, Math.max(links.get(id) || 0, share));
    };
    for (const edge of topo.edges) addLink(keyToId[edge.src], keyToId[edge.dst], edge.share);
    const firstTtl = ttls[0];
    for (const key of topo.columns[String(firstTtl)] || []) {
      addLink('origin', keyToId[key], byKey[key] ? byKey[key].share : 1);
    }
    for (const [id, share] of links) {
      const [src, dst] = id.split('>');
      if (!anchors[src] || !anchors[dst]) continue;
      edgeLayer.appendChild(edgePath(anchors[src], anchors[dst], share));
    }

    fit(svg, group, width, height);
  }

  /* Mirrors monitor.py's classify(): the same warn/fail thresholds a
     scheduled trace is judged by, applied to a hop's live continuous
     (MTR-style) probe stats instead of a single trace. null means this
     node either has no continuous probing running, or its live stats are
     within the destination's own thresholds. */
  function mtrSeverity(node, target) {
    if (!target || !node.probe_count) return null;
    const loss = node.probe_loss || 0;
    // probe_rtt_min is set the first time a continuous probe ever succeeds
    // and then never cleared (db.py's record_hop_probe only ever carries it
    // forward), so it stays a true "has this hop ever replied" even once
    // loss has since climbed back to 100% — unlike probe_rtt_avg, which is
    // *derived* from rtt_sum/(probes-lost) and goes null the instant
    // cumulative loss reaches 100%, same as a hop that never answered at
    // all. A hop that rate-limits or silently drops ICMP by nature sits at
    // 100% loss forever without that meaning anything changed, so only a
    // hop with a real answer on record is worth flagging for it.
    const hasAnswered = node.probe_rtt_min !== null && node.probe_rtt_min !== undefined;
    if (loss >= 100) return hasAnswered ? 'fail' : null;
    if (loss > target.warn_loss) return 'warn';
    if (hasAnswered && node.probe_rtt_avg !== null && node.probe_rtt_avg !== undefined
        && node.probe_rtt_avg > target.warn_rtt_ms) return 'warn';
    return null;
  }

  function attachTip(element, text) {
    element.addEventListener('mousemove', (event) => {
      if (view.panDrag) return;   // a pan is not a hover
      App.tooltip(text, event);
    });
    element.addEventListener('mouseleave', App.hideTooltip);
  }

  function nodeBox(x, y, node) {
    const g = App.svgNode('g', { transform: `translate(${x},${y})` });
    const mtr = mtrSeverity(node, currentTarget());
    let border = 'var(--canvas-hairline)', accent = 'var(--canvas-accent)';
    if (node.refusal) { border = accent = 'var(--canvas-blocked)'; }
    else if (node.is_timeout) { border = accent = 'var(--canvas-faint)'; }
    // A live continuous-probe problem is a more urgent, more current signal
    // than the traceroute-derived verdicts below it, so it outranks even
    // "this is the destination" — a target that's currently degraded should
    // not be painted the same reassuring green as a healthy one.
    else if (mtr === 'fail') { border = accent = 'var(--canvas-fail)'; }
    else if (mtr === 'warn') { border = accent = 'var(--canvas-warn)'; }
    else if (node.is_destination) { border = accent = 'var(--canvas-ok)'; }
    else if (node.share < 0.99) border = 'var(--canvas-warn)';

    g.appendChild(App.svgNode('rect', {
      x: 0.5, y: 0.5, width: NODE_W - 1, height: NODE_H - 1, rx: 5,
      fill: 'var(--canvas-panel)', stroke: border,
      'stroke-dasharray': node.share < 0.99 ? '4 3' : null,
    }));
    const barH = Math.max(4, (NODE_H - 12) * Math.min(node.share, 1));
    g.appendChild(App.svgNode('rect', {
      x: 6, y: 6, width: 4, height: NODE_H - 12, rx: 2, fill: 'var(--canvas-grid)',
    }));
    g.appendChild(App.svgNode('rect', {
      x: 6, y: NODE_H - 6 - barH, width: 4, height: barH, rx: 2, fill: accent,
    }));

    const text = (tx, ty, value, size, fill, weight) => g.appendChild(App.svgNode('text', {
      x: tx, y: ty, fill, 'font-family': 'var(--mono)', 'font-size': size,
      'font-weight': weight || 400,
    }, value));

    text(18, 20, node.label, 'var(--fs-xs)', node.is_timeout ? 'var(--canvas-muted)' : 'var(--canvas-text)', 700);
    if (node.hostname) {
      const name = node.hostname.length > 26
        ? `${node.hostname.slice(0, 12)}…${node.hostname.slice(-12)}` : node.hostname;
      text(18, 35, name, 'var(--fs-2xs)', 'var(--canvas-muted)');
    }
    text(18, 54, node.rtt === null || node.rtt === undefined
      ? '—' : `${node.rtt.toFixed(1)} ms`, 'var(--fs-2xs)', 'var(--canvas-muted)');
    const pct = App.svgNode('text', {
      x: NODE_W - 10, y: 54, 'text-anchor': 'end', fill: 'var(--canvas-faint)',
      'font-family': 'var(--mono)', 'font-size': 'var(--fs-xs)',
    }, `${Math.round(node.share * 100)}%`);
    g.appendChild(pct);

    if (node.refusal) {
      text(NODE_W - 8, 18, `REFUSED ${node.refusal}`, 'var(--fs-2xs)', 'var(--canvas-blocked)', 700)
        .setAttribute('text-anchor', 'end');
    } else if (mtr === 'fail') {
      text(NODE_W - 8, 18, 'MTR: HIGH LOSS', 'var(--fs-2xs)', 'var(--canvas-fail)', 700)
        .setAttribute('text-anchor', 'end');
    } else if (mtr === 'warn') {
      text(NODE_W - 8, 18, 'MTR: DEGRADED', 'var(--fs-2xs)', 'var(--canvas-warn)', 700)
        .setAttribute('text-anchor', 'end');
    } else if (node.is_destination) {
      text(NODE_W - 8, 18, 'TARGET', 10, 'var(--canvas-ok)', 700)
        .setAttribute('text-anchor', 'end');
    } else if (node.eyebrow) {
      text(NODE_W - 8, 18, node.eyebrow, 10, 'var(--canvas-faint)', 700)
        .setAttribute('text-anchor', 'end');
    }

    const tip = [`Address   ${node.label}`];
    // Saying where the name came from matters here: a hop named from the
    // Nodes inventory is a device this app monitors, and a PTR-derived name
    // looks identical to one.
    if (node.hostname) {
      tip.push(`Name      ${node.hostname}` +
               (node.hostname_source === 'nodes' ? '  (from Nodes)' : ''));
    }
    if (node.asn) {
      tip.push(`Network   AS${node.asn}${node.asn_org ? ` (${node.asn_org})` : ''}`);
    }
    if (node.rtt) tip.push(`Avg RTT   ${node.rtt.toFixed(1)} ms`);
    if (!node.is_timeout) tip.push(`Loss      ${Math.round(node.loss || 0)}%`);
    if (node.traces) {
      tip.push(`Seen in   ${node.traces} traces (${Math.round(node.share * 100)}%)`);
    }
    if (node.refusal) tip.push(`Refused   ${node.refusal} — ${node.refusal_text}`);
    if (node.probe_count) {
      const rttMin = node.probe_rtt_min, rttAvg = node.probe_rtt_avg, rttMax = node.probe_rtt_max;
      tip.push(`Continuous ${node.probe_count} probes, ` +
        `${Math.round(node.probe_loss || 0)}% loss`);
      if (rttAvg !== null && rttAvg !== undefined) {
        tip.push(`RTT (live) ${rttMin.toFixed(1)}/${rttAvg.toFixed(1)}/${rttMax.toFixed(1)} ms (min/avg/max)`);
      }
      if (mtr === 'fail') tip.push('Continuous probing: HIGH LOSS');
      else if (mtr === 'warn') tip.push('Continuous probing: degraded (over the warn threshold)');
    }
    attachTip(g, tip.join('\n'));
    return g;
  }

  function collapsedBox(x, y, start, end) {
    const g = App.svgNode('g', { transform: `translate(${x},${y})`, style: 'cursor:pointer' });
    g.appendChild(App.svgNode('rect', {
      x: 0.5, y: 0.5, width: NODE_W - 1, height: NODE_H - 1, rx: 5,
      fill: 'var(--canvas)', stroke: 'var(--canvas-faint)', 'stroke-dasharray': '4 3',
    }));
    for (let i = 0; i < 3; i += 1) {
      g.appendChild(App.svgNode('circle', {
        cx: 20 + i * 9, cy: NODE_H / 2 - 8, r: 2, fill: 'var(--canvas-faint)',
      }));
    }
    const text = (ty, value, size, weight) => g.appendChild(App.svgNode('text', {
      x: 50, y: ty, fill: 'var(--canvas-muted)', 'font-family': 'var(--mono)',
      'font-size': size, 'font-weight': weight || 400,
    }, value));
    text(24, `${end - start + 1} hops, no reply`, 'var(--fs-2xs)', 700);
    text(40, `hops ${start}–${end}`, 'var(--fs-2xs)');
    text(55, 'click to expand', 'var(--fs-2xs)');
    g.onclick = () => {
      if (view.dragMoved) return;   // that was a pan, not a click
      view.expanded.add(`${start}-${end}`);
      drawRoute();
    };
    attachTip(g, `Hops ${start}–${end} never replied.\nClick to expand them.`);
    return g;
  }

  function edgePath(from, to, share) {
    const span = (to.left - from.right) * 0.5;
    const d = `M ${from.right} ${from.y} C ${from.right + span} ${from.y}, ` +
              `${to.left - span} ${to.y}, ${to.left} ${to.y}`;
    return App.svgNode('path', {
      d, fill: 'none', stroke: 'var(--canvas-accent)',
      'stroke-opacity': 0.35 + 0.6 * Math.min(share, 1),
      'stroke-width': 1 + 3.5 * Math.min(share, 1),
      'stroke-dasharray': share < 0.5 ? '6 4' : null,
      'stroke-linecap': 'round',
    });
  }

  function fit(svg, group, width, height) {
    const bounds = group.getBBox ? group.getBBox() : null;
    if (!bounds || !bounds.width) return;
    if (!view.userZoom) {
      view.zoom = Math.min(width / (bounds.width + 60), height / (bounds.height + 60), 1);
      view.pan = { x: 0, y: 0 };
    }
    // Kept so the wheel handler can work out which scene point is under the
    // pointer without re-measuring the drawing.
    view.frame = {
      width, height,
      cx: bounds.x + bounds.width / 2,
      cy: bounds.y + bounds.height / 2,
    };
    const { tx, ty } = translation(view.zoom);
    group.setAttribute('transform', `translate(${tx},${ty}) scale(${view.zoom})`);
    App.el('route-zoom').textContent = `${Math.round(view.zoom * 100)}%`;
  }

  function translation(scale) {
    const f = view.frame;
    return {
      tx: f.width / 2 - f.cx * scale + view.pan.x,
      ty: f.height / 2 - f.cy * scale + view.pan.y,
    };
  }

  /* Pointer coordinates in viewBox units. The SVG is scaled to its box, so a
     client pixel is not a viewBox unit unless the two happen to match. */
  function pointerAt(event, svg) {
    const rect = svg.getBoundingClientRect();
    return {
      x: (event.clientX - rect.left) * (view.frame.width / Math.max(rect.width, 1)),
      y: (event.clientY - rect.top) * (view.frame.height / Math.max(rect.height, 1)),
    };
  }

  function wheelZoom(event) {
    if (!view.frame) return;
    event.preventDefault();
    const factor = event.deltaY < 0 ? 1.15 : 1 / 1.15;
    const from = view.zoom;
    const to = from * factor;
    if (to < 0.15 || to > 6) return;

    const svg = App.el('route-svg');
    const pointer = pointerAt(event, svg);
    const before = translation(from);
    // Hold the point under the cursor still: convert it to scene coordinates
    // at the old scale, then choose the pan that puts it back under the cursor
    // at the new one.
    const sceneX = (pointer.x - before.tx) / from;
    const sceneY = (pointer.y - before.ty) / from;
    const f = view.frame;
    view.pan.x = pointer.x - sceneX * to - (f.width / 2 - f.cx * to);
    view.pan.y = pointer.y - sceneY * to - (f.height / 2 - f.cy * to);
    view.zoom = to;
    view.userZoom = true;
    drawRoute();
  }

  function beginPan(event) {
    if (event.button !== 0 || !event.isPrimary || !view.frame) return;
    // Suppress the browser's own drag-select before it begins.
    event.preventDefault();
    // Captured: the svg keeps receiving the gesture after the pointer has
    // left it, which is what "a drag that leaves the canvas still ends"
    // needs — and a finger or a pen gets the same treatment as a mouse.
    event.currentTarget.setPointerCapture(event.pointerId);
    const selection = window.getSelection();
    if (selection) selection.removeAllRanges();
    view.panDrag = {
      x: event.clientX, y: event.clientY,
      pan: { ...view.pan },
      moved: false,
    };
    view.dragMoved = false;
    App.el('route-svg').classList.add('dragging');
  }

  function movePan(event) {
    if (!view.panDrag) return;
    const svg = App.el('route-svg');
    const rect = svg.getBoundingClientRect();
    const scaleX = view.frame.width / Math.max(rect.width, 1);
    const scaleY = view.frame.height / Math.max(rect.height, 1);
    const dx = (event.clientX - view.panDrag.x) * scaleX;
    const dy = (event.clientY - view.panDrag.y) * scaleY;
    App.hideTooltip();
    if (Math.abs(dx) + Math.abs(dy) > 3) {
      view.panDrag.moved = true;
      view.dragMoved = true;
      view.userZoom = true;   // panning is a deliberate view choice too
    }
    view.pan.x = view.panDrag.pan.x + dx;
    view.pan.y = view.panDrag.pan.y + dy;
    drawRoute();
  }

  function endPan() {
    if (!view.panDrag) return;
    view.panDrag = null;
    App.el('route-svg').classList.remove('dragging');
  }

  function zoomGraph(factor) {
    const next = view.zoom * factor;
    if (next < 0.15 || next > 6) return;
    view.zoom = next;
    view.userZoom = true;
    drawRoute();
  }

  /* ---------------------------------------------------------- timeline */

  function lanes(width, height) {
    const usable = width - 2 * PAD_X;
    let spare = height - AXIS_H - TICKS_H - 3 * LABEL_H - 2 * LANE_GAP - STATUS_H;
    spare = Math.max(spare, 44);
    const heights = {
      rtt: Math.max(spare * 0.55, 22),
      loss: Math.max(spare - Math.max(spare * 0.55, 22), 22),
      status: STATUS_H,
    };
    const out = {};
    let y = TICKS_H + LABEL_H;
    for (const name of LANE_ORDER) {
      out[name] = { x: PAD_X, y, w: usable, h: heights[name] };
      y += heights[name] + LANE_GAP + LABEL_H;
    }
    return out;
  }

  function drawTimeline() {
    const svg = App.el('timeline-svg');
    svg.innerHTML = '';
    const box = App.el('timeline').getBoundingClientRect();
    const width = Math.max(box.width, 300), height = Math.max(box.height, 150);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

    const data = view.timeline;
    const t0 = view.t0, t1 = view.t1;
    const xFor = (ts) => PAD_X + (ts - t0) / Math.max(t1 - t0, 1e-6) * (width - 2 * PAD_X);
    const timeAt = (x) => t0 + (x - PAD_X) / Math.max(width - 2 * PAD_X, 1) * (t1 - t0);
    const L = lanes(width, height);

    const peak = data ? Math.max(...data.buckets.map((b) => b.avg_rtt || 0), 0) : 0;
    const label = (lane, title, scale) => {
      svg.appendChild(App.svgNode('text', {
        x: lane.x, y: lane.y - 4, fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)', 'font-weight': 700,
      }, title));
      if (scale) {
        svg.appendChild(App.svgNode('text', {
          x: lane.x + lane.w, y: lane.y - 4, 'text-anchor': 'end',
          fill: 'var(--dim)', 'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
        }, scale));
      }
      svg.appendChild(App.svgNode('line', {
        x1: lane.x, y1: lane.y + lane.h, x2: lane.x + lane.w, y2: lane.y + lane.h,
        stroke: 'var(--grid)',
      }));
    };
    label(L.rtt, 'ROUND-TRIP TIME', peak ? `peak ${Math.round(peak)} ms` : '');
    label(L.loss, 'PACKET LOSS', '100%');
    label(L.status, 'STATUS', '');

    // The warn thresholds, drawn where the eye already is. A bar crossing the
    // dashed line is exactly why the block below it turned amber.
    const target = currentTarget();
    if (target) {
      if (peak > 0 && target.warn_rtt_ms <= peak) {
        const y = L.rtt.y + L.rtt.h - L.rtt.h * (target.warn_rtt_ms / peak);
        threshold(svg, L.rtt, y, `warn ${target.warn_rtt_ms} ms`);
      }
      if (target.warn_loss > 0 && target.warn_loss < 100) {
        const y = L.loss.y + L.loss.h - L.loss.h * (target.warn_loss / 100);
        threshold(svg, L.loss, y, `warn ${target.warn_loss}%`);
      }
    }

    if (data) {
      for (const bucket of data.buckets) {
        const x0 = xFor(bucket.t0), x1b = xFor(bucket.t1);
        const w = Math.max(x1b - x0, 1);
        const gap = w > 4 ? 1 : 0;
        const bw = Math.max(w - gap, 1);
        if (x1b < PAD_X || x0 > width - PAD_X) continue;

        if (bucket.avg_rtt !== null && peak > 0) {
          const h = Math.max(L.rtt.h * (bucket.avg_rtt / peak), 1.5);
          svg.appendChild(App.svgNode('rect', {
            x: x0, y: L.rtt.y + L.rtt.h - h, width: bw, height: h,
            fill: 'var(--accent)', 'fill-opacity': 0.8,
          }));
        }
        if (bucket.total) {
          const pct = bucket.avg_loss || 0;
          if (pct <= 0.5) {
            svg.appendChild(App.svgNode('rect', {
              x: x0, y: L.loss.y + L.loss.h - 2, width: bw, height: 2, fill: 'var(--ok)',
            }));
          } else {
            const h = Math.max(L.loss.h * Math.min(pct, 100) / 100, 2);
            svg.appendChild(App.svgNode('rect', {
              x: x0, y: L.loss.y + L.loss.h - h, width: bw, height: h,
              fill: pct > 25 ? 'var(--fail)' : 'var(--warn)',
            }));
          }
        }
        const cell = App.svgNode('rect', {
          x: x0, y: L.status.y, width: bw, height: L.status.h,
          fill: STATUS_COLOR[bucket.status] || 'var(--nodata)',
          'fill-opacity': bucket.status === 'none' ? 1 : 0.85,
        });
        svg.appendChild(cell);
        // Refused was hatched and skipped was striped from the start; the
        // rest of the vocabulary now comes from the same shared definitions
        // the device status timeline uses, so no state is colour alone.
        const texture = App.statusPatternUrl(bucket.status);
        if (texture) {
          svg.appendChild(App.svgNode('rect', {
            x: x0, y: L.status.y, width: bw, height: L.status.h, fill: texture,
          }));
        }
        if (bucket.path_changed) {
          svg.appendChild(App.svgNode('rect', {
            x: x0, y: 2, width: Math.max(bw, 2), height: TICKS_H - 3, fill: 'var(--accent)',
          }));
        }

      }
    }

    // The hatch and the bars this file defined by hand now live in app.js
    // beside the three the other states need, so the two timelines cannot
    // drift apart.
    App.statusPatternDefs(svg);

    const span = t1 - t0;
    const step = niceStep(span);
    for (let ts = Math.ceil(t0 / step) * step; ts <= t1; ts += step) {
      const x = xFor(ts);
      svg.appendChild(App.svgNode('text', {
        x, y: height - 6, 'text-anchor': 'middle', fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, App.stamp(ts, span)));
    }

    if (view.pinned) {
      const x = xFor(view.pinned);
      if (x >= PAD_X && x <= width - PAD_X) {
        svg.appendChild(App.svgNode('line', {
          x1: x, y1: L.rtt.y - 6, x2: x, y2: L.status.y + L.status.h,
          stroke: 'var(--text)', 'stroke-width': 1.5,
        }));
      }
    }
    if (view.drag) {
      const a = xFor(Math.min(view.drag.from, view.drag.to));
      const b = xFor(Math.max(view.drag.from, view.drag.to));
      svg.appendChild(App.svgNode('rect', {
        x: a, y: L.rtt.y - 4, width: Math.max(b - a, 2),
        height: L.status.y + L.status.h - L.rtt.y + 8,
        fill: 'var(--accent)', 'fill-opacity': 0.14,
        stroke: 'var(--accent)',
      }));
    }

    svg.onpointerdown = (event) => {
      if (event.button !== 0 || !event.isPrimary) return;
      event.preventDefault();
      svg.setPointerCapture(event.pointerId);
      const x = event.offsetX * (width / svg.clientWidth);
      view.drag = { from: timeAt(x), to: timeAt(x), moved: false };
    };
    const crosshair = App.svgNode('line', {
      y1: L.rtt.y, y2: L.status.y + L.status.h,
      stroke: 'var(--muted)', 'stroke-dasharray': '2 3', visibility: 'hidden',
    });
    svg.appendChild(crosshair);

    svg.onpointermove = (event) => {
      const x = event.offsetX * (width / svg.clientWidth);
      if (view.drag) {
        view.drag.to = timeAt(x);
        view.drag.moved = Math.abs(xFor(view.drag.to) - xFor(view.drag.from)) > 5;
        drawTimeline();
        return;
      }
      crosshair.setAttribute('x1', x);
      crosshair.setAttribute('x2', x);
      crosshair.setAttribute('visibility', 'visible');
      App.tooltip(bucketTip(timeAt(x)), event);
    };
    svg.onpointerleave = () => {
      crosshair.setAttribute('visibility', 'hidden');
      App.hideTooltip();
    };
    svg.onpointerup = () => {
      if (!view.drag) return;
      const { from, to, moved } = view.drag;
      view.drag = null;
      if (moved) { view.pinned = null; setWindow(Math.min(from, to), Math.max(from, to), false); }
      else { view.pinned = from; App.refreshNow('netpath'); }
    };
    // A cancelled gesture selects nothing and pins nothing.
    svg.onpointercancel = () => { view.drag = null; drawTimeline(); };
    svg.oncontextmenu = (event) => {
      event.preventDefault();
      view.pinned = null;
      App.refreshNow('netpath');
    };
    svg.onwheel = (event) => {
      event.preventDefault();
      const x = event.offsetX * (width / svg.clientWidth);
      const [start, end] = App.wheelWindow(event, t0, t1, timeAt(x));
      setWindow(start, end, false);
    };
  }

  /* The overrun note is a sentence, and the panel does not wrap. */
  function wrapNote(note, width = 56) {
    const out = [];
    let line = '';
    for (const word of String(note).split(/\s+/)) {
      if (line && (line + ' ' + word).length > width) { out.push(line); line = word; }
      else line = line ? `${line} ${word}` : word;
    }
    if (line) out.push(line);
    return out;
  }

  function threshold(svg, lane, y, text) {
    svg.appendChild(App.svgNode('line', {
      x1: lane.x, y1: y, x2: lane.x + lane.w, y2: y,
      stroke: 'var(--warn)', 'stroke-width': 1,
      'stroke-dasharray': '5 4', 'stroke-opacity': 0.75,
    }));
    // On the left, where the lane is emptiest: the right-hand end already
    // carries the scale figure, and the newest bars are drawn there too.
    const width = text.length * 5.6 + 8;
    svg.appendChild(App.svgNode('rect', {
      x: lane.x + 2, y: y - 11, width, height: 11, rx: 2,
      fill: 'var(--panel)', 'fill-opacity': 0.85,
    }));
    svg.appendChild(App.svgNode('text', {
      x: lane.x + 6, y: y - 3, fill: 'var(--warn)',
      'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
    }, text));
  }

  function bucketTip(ts) {
    const data = view.timeline;
    if (!data) return '';
    const bucket = data.buckets.find((b) => ts >= b.t0 && ts <= b.t1);
    if (!bucket) return '';
    const lines = [App.stamp(bucket.t0, view.t1 - view.t0),
                   STATUS_LABEL[bucket.status] || bucket.status];
    if (!bucket.total) {
      lines.push(`${data.polls_per_block} poll(s) expected, none recorded`);
      return lines.join('\n');
    }
    if (bucket.note) lines.push(...wrapNote(bucket.note));
    lines.push(`${bucket.total} trace(s)`);
    const counts = Object.entries(bucket.counts || {})
      .map(([key, value]) => `${key}: ${value}`).join(', ');
    if (counts) lines.push(counts);
    if (bucket.avg_rtt !== null && bucket.avg_rtt !== undefined) {
      lines.push(bucket.icmp_from
        ? `RTT ${bucket.avg_rtt.toFixed(1)} ms (to ${bucket.icmp_from}, which refused)`
        : `RTT ${bucket.avg_rtt.toFixed(1)} ms avg`);
    }
    lines.push(`Loss ${Math.round(bucket.avg_loss)}% avg, ` +
               `${Math.round(bucket.max_loss)}% worst`);
    if (bucket.icmp_code) {
      lines.push(`${bucket.icmp_code} ${bucket.icmp_text} from ${bucket.icmp_from}`);
    }
    if (bucket.path_changed) lines.push('route changed in this window');
    return lines.join('\n');
  }

  const STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200,
    10800, 21600, 43200, 86400, 172800, 604800, 1209600, 2592000];
  function niceStep(span) {
    const want = span / 7;
    return STEPS.find((s) => s >= want) || STEPS[STEPS.length - 1];
  }

  /* ----------------------------------------------------------- refresh */

  async function refresh() {
    if (App.state.tab !== 'netpath') return;
    const payload = await App.get('/api/netpath/targets');
    view.targets = payload.targets;
    pruneWindows();
    if (view.targetId === null && view.targets.length) view.targetId = view.targets[0].id;
    if (view.windowFor !== view.targetId) applyWindow(view.targetId);
    renderTargets();
    renderTerms();

    if (view.targetId === null) {
      view.timeline = null;
      view.topology = null;
      drawTimeline();
      drawRoute();
      return;
    }

    if (view.follow) {
      const span = view.t1 - view.t0;
      view.t1 = Date.now() / 1000;
      view.t0 = view.t1 - span;
    }

    const width = App.el('timeline').getBoundingClientRect().width || 1200;
    view.timeline = await App.get('/api/netpath/timeline', {
      target: view.targetId, t0: view.t0, t1: view.t1, width,
    });
    App.el('block-label').textContent = view.timeline.bucket_s
      ? (view.timeline.polls_per_block === 1
        ? `1 block = 1 poll (${App.span(view.timeline.bucket_s)})`
        : `1 block = ${view.timeline.polls_per_block} polls (${App.span(view.timeline.bucket_s)})`)
      : '';

    const summary = view.timeline.summary || {};
    App.el('stat-healthy').textContent =
      `Healthy   ${(summary.healthy_pct ?? 0).toFixed(1)}%`;
    App.el('stat-rtt').textContent = summary.avg_rtt
      ? `Avg RTT   ${summary.avg_rtt.toFixed(1)} ms` : 'Avg RTT      —';
    App.el('stat-traces').textContent = `Traces    ${summary.traces ?? 0}`;

    const params = { target: view.targetId, t0: view.t0, t1: view.t1 };
    if (view.pinned) params.at = view.pinned;
    view.topology = await App.get('/api/netpath/topology', params);
    if (view.expandAll) {
      for (const [a, b] of silentRuns(view.topology)) view.expanded.add(`${a}-${b}`);
    }
    App.el('stat-routes').textContent = `Routes    ${view.topology.distinct_paths ?? 0}`;

    const snapshot = view.topology.snapshot || {};
    App.el('route-live').hidden = !view.pinned;
    if (view.pinned && snapshot.found) {
      const parts = [`Snapshot of the trace at ${App.stamp(snapshot.at, 0)}`,
        STATUS_LABEL[snapshot.status] || snapshot.status];
      if (snapshot.rtt_ms !== null && snapshot.rtt_ms !== undefined) {
        parts.push(snapshot.icmp_from
          ? `${snapshot.rtt_ms.toFixed(1)} ms to ${snapshot.icmp_from}`
          : `${snapshot.rtt_ms.toFixed(1)} ms`);
      }
      if (snapshot.icmp_code) {
        parts.push(`${snapshot.icmp_code} from ${snapshot.icmp_from}`);
      }
      App.el('route-summary').textContent = parts.join(' · ');
    } else if (view.pinned) {
      App.el('route-summary').textContent =
        `Snapshot at ${App.stamp(view.pinned, 0)} · no trace in range`;
    } else {
      App.el('route-summary').textContent =
        `${view.topology.total_traces} traces · ` +
        `${view.topology.distinct_paths} distinct route(s) · ` +
        `${App.span(view.t1 - view.t0)} window ending ${App.stamp(view.t1, 0)}`;
    }

    drawTimeline();
    drawRoute();
  }

  /* Entry point for other tabs (NetFlow's "view route" jump): select a
     target and, optionally, a time window, without waiting for the user to
     click it in the target list. Safe to call with no args — App.selectTab
     already calls this with none on every ordinary tab switch. */
  function activate(opts) {
    // A hash route (#/netpath/<targetId>) names the destination in its path;
    // NetFlow's "view route" jump passes it as targetId directly. Both end
    // up in the same place.
    if (opts && opts.parts && opts.parts[0] !== undefined && !opts.targetId) {
      const fromRoute = Number(opts.parts[0]);
      if (Number.isFinite(fromRoute)) opts = { ...opts, targetId: fromRoute };
    }
    if (!opts || !opts.targetId) return;
    view.targetId = opts.targetId;
    view.pinned = null;
    view.expanded.clear();
    view.expandAll = false;
    view.userZoom = false;
    view.pan = { x: 0, y: 0 };
    if (opts.t0 !== undefined && opts.t1 !== undefined) {
      setWindow(opts.t0, opts.t1, false);
    }
  }

  function init() {
    App.fillRanges(App.el('range-select'), 'Last hour');
    view.windows = loadWindows();
    App.el('range-select').onchange = resetWindow;
    App.el('tl-follow').onchange = (event) => {
      view.follow = event.target.checked;
      if (view.follow) {
        const span = view.t1 - view.t0;
        setWindow(Date.now() / 1000 - span, Date.now() / 1000);
      } else rememberWindow();
    };
    App.el('tl-reset').onclick = resetWindow;
    App.el('tl-in').onclick = () => zoom(0.5);
    App.el('tl-out').onclick = () => zoom(2);
    App.el('tl-back').onclick = () => pan(-0.25);
    App.el('tl-fwd').onclick = () => pan(0.25);

    App.el('route-zoom-in').onclick = () => zoomGraph(1.25);
    App.el('route-zoom-out').onclick = () => zoomGraph(1 / 1.25);
    App.el('route-fit').onclick = () => {
      view.userZoom = false;
      view.pan = { x: 0, y: 0 };
      drawRoute();
    };

    const routeSvg = App.el('route-svg');
    routeSvg.addEventListener('wheel', wheelZoom, { passive: false });
    routeSvg.addEventListener('pointerdown', beginPan);
    // beginPan captures the pointer, so these fire on the svg for the whole
    // gesture wherever it wanders; cancel (a touch turned into a scroll,
    // a pen lifted out of range) ends it like a release.
    routeSvg.addEventListener('pointermove', movePan);
    routeSvg.addEventListener('pointerup', endPan);
    routeSvg.addEventListener('pointercancel', endPan);
    App.el('route-live').onclick = () => {
      view.pinned = null;
      App.refreshNow('netpath');
    };
    App.el('route-expand').onclick = () => {
      view.expandAll = !view.expandAll;
      // A toggle names its other half: this read "Expand silent hops" in
      // both states, while the graph's own affordance said "click to
      // collapse".
      const btn = App.el('route-expand');
      btn.textContent = view.expandAll ? 'Collapse silent hops' : 'Expand silent hops';
      btn.setAttribute('aria-pressed', String(view.expandAll));
      if (!view.expandAll) view.expanded.clear();
      else for (const [a, b] of silentRuns(view.topology || {})) view.expanded.add(`${a}-${b}`);
      drawRoute();
    };
    App.el('netpath-settings').onclick = netpathSettings;

    App.el('target-add').onclick = addTarget;
    App.el('target-edit').onclick = editTarget;
    App.el('target-remove').onclick = removeTarget;
    App.el('target-trace').onclick = async () => {
      if (view.targetId) await App.post(`/api/netpath/targets/${view.targetId}/trace`, {});
    };

    // Dragging a divider changes the drawing area, so the SVG has to be
    // rebuilt for the new size, not just stretched.
    for (const event of ['resize', 'panes-resized']) {
      window.addEventListener(event, () => {
        if (App.state.tab === 'netpath') { drawTimeline(); drawRoute(); }
      });
    }
    resetWindow();
  }

  App.pages.netpath = { init, refresh, activate };
})();

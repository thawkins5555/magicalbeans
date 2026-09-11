/* The MAPPER page: a manually-built L2 map, one SVG canvas per named map.
   Maps start BLANK — nothing here ever adds a device or a link on its
   own; the operator places a device (or an unmanaged CDP/LLDP peer) by
   hand and drags it where they want. The server (netpath/mapper.py)
   computes every link's render plan — mode, width, strand offsets,
   colours — once, so this file never re-derives them; it only draws what
   `plan` says and reacts to what the operator does with the mouse, the
   touchscreen or the keyboard.

   Modeled on netpath.js's route canvas for the pan/zoom/fit idiom
   (App.svgNode, the --canvas-* tokens, pointer-captured drag) and on
   wireless.js for the page shape (view object, init/refresh/activate/
   fastTick, a settings dialog matching Settings' own Apply feedback). The
   pan/zoom math is copied rather than shared: NetPath's canvas is a
   diagram laid out fresh every poll, MAPPER's is a *place* — a node's
   x/y is data the operator set, read back and drawn, never recomputed. */
(() => {
  const escape = App.escapeHtml;

  /* ------------------------------------------------------------ geometry
     Node position (map_nodes.x/y) is taken to mean the box's CENTRE, not
     its top-left corner — chosen once, here, because nothing about the
     schema or the API says either way and every piece of math below (drag,
     rubber-band hit-testing, link endpoints, align/distribute) is simpler
     around a centre than a corner. Every read and write of x/y in this
     file agrees, so the convention only has to be right once. */
  const NODE_W = 132, NODE_H = 54;
  const ICON = 16;   // the role glyph's own viewBox is 16x16
  // Position writes are debounced rather than sent on every pointermove —
  // a drag across a big map would otherwise queue one PUT per animation
  // frame. 500ms after the last move (or the last align/distribute) is
  // long enough that a released drag has visibly "settled" before the
  // network round-trip starts.
  const WRITE_DEBOUNCE_MS = 500;
  // A failed write is retried rather than dropped — see flushPositionWrites.
  const WRITE_RETRY_MS = 5000;
  // How far the pointer travels, in SCREEN pixels, before a press on a node
  // counts as a drag rather than a click.
  const MOVE_THRESHOLD_PX = 3;

  // mapperdb.MAP_STYLES, mirrored so the settings dialog's <select> and the
  // canvas's data-map-style attribute never drift from the server's own list.
  const MAP_STYLES = ['modern', 'classic', 'blueprint', 'minimal'];
  const MAP_STYLE_RADIUS = { modern: 10, classic: 3, blueprint: 0, minimal: 6 };

  // mapperdb.ROLES: the fixed list a node's role may take. A node carries
  // `role` (what to DRAW — the operator's override when they set one, else
  // mapper.detect_role's guess from vendor/sysDescr) and `role_auto`
  // (which of those two it was). The two have to stay separate in the
  // select: showing a detected role as though the operator had picked it
  // would leave them no way back to auto, since re-picking the same value
  // writes it as an override that then stops tracking the device.
  const ROLES = ['', 'switch', 'router', 'firewall', 'ap', 'server', 'unmanaged'];
  // '' is the "no override" option, so it reads Auto rather than Unknown —
  // roleSelectHtml appends what detection actually says when it says
  // anything, leaving a bare "Auto" only for a node nothing identified.
  const ROLE_LABEL = { '': 'Auto', switch: 'Switch', router: 'Router',
    firewall: 'Firewall', ap: 'Access point', server: 'Server', unmanaged: 'Unmanaged' };

  // nodes.js's own device-status vocabulary, copied rather than imported
  // (nodes.js is a lazy module too, and reaching into it is exactly what
  // test_frontend_contracts' "no lazy module reaches into another's
  // App.pages" rule exists to stop even for a plain data map like this one).
  const DEVICE_STATUS_TONE = { up: 'ok', down: 'fail', unsupported: 'warn', auth: 'warn', unknown: 'none' };
  const DEVICE_STATUS_LABEL = { up: 'Up', down: 'Down', unsupported: 'Unsupported',
    auth: 'Auth failed', unknown: 'Unknown' };

  const view = {
    maps: [],
    mapId: null,
    map: null,
    nodes: [],           // map_nodes rows, x/y possibly overridden by an in-flight drag
    nodeByDevice: new Map(),   // device_id -> map_nodes row, for joining a link's endpoints to this map
    nodeByPeer: new Map(),     // peer_key -> map_nodes row, same join for an unmanaged far end
    links: [],
    peersByKey: new Map(),
    vlans: [],
    // Rebuilt with the payload in loadMapData; replaces an Array.find()
    // per lookup that made a 60-node/200-link map quadratic.
    nodeMap: new Map(),        // map_nodes id -> row
    linkMap: new Map(),        // link id -> link
    vlanNameById: new Map(),   // vlan id -> its name on this map ('' when unnamed)
    linksByNode: new Map(),    // map_nodes id -> the links touching it

    // The drawn SVG, kept so pan/zoom/drag can move it instead of
    // rebuilding (applyTransform, redrawDragged, drawRubber).
    sceneGroup: null,
    rubberEl: null,
    nodeEls: new Map(),        // map_nodes id -> its <g>
    linkEls: new Map(),        // link id -> the <g> holding that link's own elements
    settings: {},        // mapperdb.DEFAULTS shape, refreshed with every maps/settings fetch
    candidates: { devices: [], neighbours: [] },

    selection: new Set(),    // selected node ids
    selectedLinkId: null,
    selectedVlan: null,      // vlan id highlighted from the VLAN table
    detailShowAllVlans: false,   // the open link's VLAN list, past VLAN_DETAIL_CAP

    // needsFit: a map is fitted once, when opened or when Fit is pressed,
    // never again under an operator who has since arranged it.
    zoom: 1, needsFit: true, pan: { x: 0, y: 0 }, frame: null,
    panDrag: null, spaceHeld: false,
    nodeDrag: null,          // {ids, from:Map(id->{x,y}), dx, dy, moved}
    rubber: null,            // {x0,y0,x1,y1, additive}

    pendingPositions: new Map(),   // node id -> {x,y}, awaiting the debounced PUT
    writeTimer: null,
    writeRetryTimer: null,

    // Bumped per loadMapData() and checked after its await, the same
    // guard netpath.js's refreshGen and configrx.js's searchGen use: a map
    // switch fired while a slower fetch for the PREVIOUS map is still in
    // flight must not let that stale response paint over the new map.
    loadGen: 0,
  };

  /* ------------------------------------------------------ role glyphs
     Inline SVG paths, no icon font and no external asset (the spec is
     explicit on this). Each returns plain {tag,attrs} descriptors for a
     16x16 box; drawNode positions the group and applies .mp-node-icon,
     which owns the stroke colour and weight so no glyph below names one. */
  function roleGlyph(role) {
    switch (role) {
      case 'switch':
        // A rack-mount switch: a body with four front ports along the base.
        return [
          { tag: 'rect', attrs: { x: 1, y: 2, width: 14, height: 8, rx: 1 } },
          { tag: 'line', attrs: { x1: 3, y1: 10, x2: 3, y2: 13 } },
          { tag: 'line', attrs: { x1: 6, y1: 10, x2: 6, y2: 13 } },
          { tag: 'line', attrs: { x1: 9, y1: 10, x2: 9, y2: 13 } },
          { tag: 'line', attrs: { x1: 12, y1: 10, x2: 12, y2: 13 } },
        ];
      case 'router':
        // A circle with a crosshair — paths routed through a hub, not a
        // single flat segment the way the switch's ports read.
        return [
          { tag: 'circle', attrs: { cx: 8, cy: 8, r: 6 } },
          { tag: 'line', attrs: { x1: 8, y1: 3, x2: 8, y2: 13 } },
          { tag: 'line', attrs: { x1: 3, y1: 8, x2: 13, y2: 8 } },
        ];
      case 'firewall':
        // Brick coursing: a wall, the shape this role has meant since the
        // term was coined.
        return [
          { tag: 'rect', attrs: { x: 1, y: 2, width: 6, height: 4 } },
          { tag: 'rect', attrs: { x: 8, y: 2, width: 6, height: 4 } },
          { tag: 'rect', attrs: { x: 1, y: 7, width: 3, height: 4 } },
          { tag: 'rect', attrs: { x: 5, y: 7, width: 6, height: 4 } },
          { tag: 'rect', attrs: { x: 12, y: 7, width: 3, height: 4 } },
          { tag: 'rect', attrs: { x: 1, y: 12, width: 6, height: 3 } },
          { tag: 'rect', attrs: { x: 8, y: 12, width: 6, height: 3 } },
        ];
      case 'ap':
        // A client dot under two signal arcs — the shape every access
        // point icon in every wireless controller UI already uses.
        return [
          { tag: 'circle', attrs: { cx: 8, cy: 13, r: 1.3, fill: 'var(--canvas-muted)', stroke: 'none' } },
          { tag: 'path', attrs: { d: 'M6 11 A2.6 2.6 0 0 1 10 11' } },
          { tag: 'path', attrs: { d: 'M4 9 A6 6 0 0 1 12 9' } },
        ];
      case 'server':
        // A rack unit body with three bands, each carrying its own status
        // LED — distinct from the switch's front-port row.
        return [
          { tag: 'rect', attrs: { x: 2, y: 1, width: 12, height: 14, rx: 1 } },
          { tag: 'line', attrs: { x1: 2, y1: 6, x2: 14, y2: 6 } },
          { tag: 'line', attrs: { x1: 2, y1: 10, x2: 14, y2: 10 } },
          { tag: 'circle', attrs: { cx: 11.5, cy: 3.5, r: 0.8, fill: 'var(--canvas-muted)', stroke: 'none' } },
          { tag: 'circle', attrs: { cx: 11.5, cy: 8, r: 0.8, fill: 'var(--canvas-muted)', stroke: 'none' } },
          { tag: 'circle', attrs: { cx: 11.5, cy: 12.5, r: 0.8, fill: 'var(--canvas-muted)', stroke: 'none' } },
        ];
      default:
        // '' (unknown) and 'unmanaged' share this: a dashed box around a
        // single dot — "something is here", nothing more claimed than that.
        return [
          { tag: 'rect', attrs: { x: 2, y: 2, width: 12, height: 12, rx: 2, 'stroke-dasharray': '2 2' } },
          { tag: 'circle', attrs: { cx: 8, cy: 8, r: 1.3, fill: 'var(--canvas-muted)', stroke: 'none' } },
        ];
    }
  }

  function drawRoleIcon(role, x, y) {
    const g = App.svgNode('g', { class: 'mp-node-icon', transform: `translate(${x},${y})` });
    for (const part of roleGlyph(role)) g.appendChild(App.svgNode(part.tag, part.attrs));
    return g;
  }

  /* -------------------------------------------------------------- helpers */

  function currentMap() { return view.maps.find((m) => m.id === view.mapId) || null; }
  function nodeById(id) { return view.nodeMap.get(id) || null; }
  function linkById(id) { return view.linkMap.get(id) || null; }

  /* A link (netpath/mapper.py's assemble_links) names its endpoints by
     DEVICE identity — a_device_id always (the reporting device), and
     b_device_id or b_peer_key for the far end — never by a map_nodes row
     id, because the same link is a fact about the network regardless of
     which map happens to place it. view.nodeByDevice/nodeByPeer (rebuilt
     alongside view.nodes in loadMapData) are the join back from that
     identity to THIS map's own placement, which is what drawing needs. */
  function linkNodeA(link) { return view.nodeByDevice.get(link.a_device_id) || null; }
  function linkNodeB(link) {
    if (link.b_device_id !== null && link.b_device_id !== undefined) {
      return view.nodeByDevice.get(link.b_device_id) || null;
    }
    return view.nodeByPeer.get(link.b_peer_key) || null;
  }

  // The position a node is drawn at RIGHT NOW: an in-flight drag (or a
  // pending write not yet acknowledged) wins over the last value the
  // server sent, so the box does not snap backward mid-gesture.
  function livePos(node) {
    if (view.nodeDrag && view.nodeDrag.from.has(node.id)) {
      const base = view.nodeDrag.from.get(node.id);
      return { x: base.x + view.nodeDrag.dx, y: base.y + view.nodeDrag.dy };
    }
    const pending = view.pendingPositions.get(node.id);
    if (pending) return { x: pending.x, y: pending.y };
    return { x: node.x, y: node.y };
  }

  // A node drag, a rubber band or a pan is a gesture the operator is in the
  // middle of; anything that would redraw the scene under it (a refresh, a
  // pane resize) waits, which is the promise FEATURES.md makes for MAPPER's
  // auto-refresh.
  function gestureActive() {
    return !!(view.nodeDrag || view.rubber || view.panDrag);
  }

  function snapValue(v) {
    const size = Number(view.settings.grid_size) || 20;
    return Math.round(v / size) * size;
  }

  /* ------------------------------------------------------------ resolving
     What a node draws as: name, status tone, whether it is unmanaged or
     gone, and a plain-text tooltip. GET .../maps/<id> already resolves
     name/status/ip/unmanaged/missing/temp_c/cpu_pct/port_count server side
     (nodesdb is the source of truth for all of it) — this reads those
     fields rather than re-deriving them from a second fetch of
     /api/nodes/devices, which is also what keeps this off
     test_frontend_contracts' "no module keeps a second device cache" rule.

     `name` is already the operator's own `label` wherever they set one,
     folded in server-side by get_mapper_map's _mapper_node_name so the map,
     the detail pane and the CSV export can never disagree about what a
     renamed node is called; `resolved_name` carries the underlying identity
     alongside it for anywhere that wants to say what the rename replaced. */
  function resolveNode(node) {
    // Defensive only: drawLink already skips a link whose endpoint cannot
    // be found on this map, so a null here would mean map data changed
    // out from under an already-open detail pane rather than a real state.
    if (!node) {
      return { node: null, name: '(removed)', sub: '', tone: 'none', unmanaged: false,
        gone: true, role: '', badges: {}, tooltip: 'This node is no longer on the map.' };
    }
    const name = node.name;
    const badges = { temp_c: node.temp_c, cpu_pct: node.cpu_pct, port_count: node.port_count };
    if (node.missing) {
      return {
        node, name, sub: 'removed from Nodes', tone: 'none', unmanaged: false,
        gone: true, role: node.role || '', badges,
        tooltip: `${name}\nThis device has been removed from Nodes; its position is kept ` +
          'in case it comes back, but nothing here is live any more.',
      };
    }
    if (node.unmanaged) {
      const peer = view.peersByKey.get(node.peer_key) || null;
      const via = peer ? peer.seen_via.map((v) => {
        const seenBy = view.nodeByDevice.get(v.device_id);
        return `${seenBy ? seenBy.name : `#${v.device_id}`} (${v.port || '—'})`;
      }).join(', ') : '';
      return {
        node, name, sub: (peer && peer.platform) || 'unmanaged', tone: 'none',
        unmanaged: true, gone: false, role: node.role || 'unmanaged', badges,
        tooltip: `${name}\nUnmanaged peer — seen over LLDP/CDP, not polled directly.` +
          (node.ip ? `\nAddress   ${node.ip}` : '') + (via ? `\nSeen via  ${via}` : ''),
      };
    }
    const tone = DEVICE_STATUS_TONE[node.status] || 'none';
    const statusWord = DEVICE_STATUS_LABEL[node.status] || node.status || 'Unknown';
    return {
      node, name, sub: node.ip || '', tone, unmanaged: false, gone: false,
      role: node.role || '', badges,
      tooltip: `${name}\n${node.ip || ''}\nStatus    ${statusWord}`,
    };
  }

  /* ---------------------------------------------------------- maps: CRUD */

  function fillMapSelect() {
    const select = App.el('mp-map');
    const current = String(view.mapId ?? '');
    select.innerHTML = view.maps.map((m) =>
      `<option value="${m.id}">${escape(m.name)}</option>`).join('');
    if (view.maps.some((m) => String(m.id) === current)) select.value = current;
    else if (view.maps.length) select.value = String(view.maps[0].id);
  }

  async function loadMapsList() {
    const payload = await App.get('/api/mapper/maps');
    view.maps = payload.maps || [];
    view.settings = payload.settings || view.settings || {};
    fillMapSelect();
  }

  // Remembered per browser exactly like every other late-filled select in
  // the product (wireless.js's controller filter): the option list does
  // not exist until the first fetch lands, so restoreControls' own
  // "assign from markup at init()" contract cannot reach it — the value is
  // read and written directly through savedControl/rememberControl instead.
  function recallMapId() {
    const stored = App.savedControl('mapper', 'mp-map');
    return stored ? Number(stored) : null;
  }
  function rememberMapId(id) {
    App.rememberControl('mapper', 'mp-map', id === null ? '' : String(id));
  }

  // The map id the address bar names, or null; refresh() prefers it over
  // the remembered one so #/mapper/<id> loads that map once, not twice.
  function routedMapId() {
    const route = App.currentRoute();
    if (!route || route.tab !== 'mapper') return null;
    const id = Number(route.parts[0]);
    return Number.isFinite(id) ? id : null;
  }

  function drawStatus() {
    const map = currentMap();
    App.el('mp-status').textContent = map ? map.name : 'No map selected';
    if (!map) { App.el('mp-counters').textContent = ''; return; }
    const nodeCount = view.nodes.length;
    const linkCount = view.links.length;
    const vlanCount = view.vlans.length;
    App.el('mp-counters').textContent =
      `${nodeCount} device(s) · ${linkCount} link(s) · ${vlanCount} VLAN(s)`;
    App.el('mp-dot').style.background = nodeCount ? 'var(--ok)' : 'var(--line)';
  }

  function mapSummaryText() {
    const map = currentMap();
    if (!map) return 'No map selected';
    return `${map.name}: ${view.nodes.length} device(s), ${view.links.length} link(s)`;
  }

  async function selectMap(id, opts = {}) {
    view.mapId = id;
    rememberMapId(id);
    const select = App.el('mp-map');
    if (select.value !== String(id ?? '')) select.value = String(id ?? '');
    if (!opts.keepView) {
      view.needsFit = true;
      view.pan = { x: 0, y: 0 };
      view.selection.clear();
      view.selectedLinkId = null;
      view.selectedVlan = null;
    }
    if (!opts.noRoute) App.setRoute(id === null ? [] : [id]);
    await loadMapData();
  }

  function mapForm(map) {
    return `
      <label>Name <input id="mpf-name" value="${escape(map ? map.name : '')}"></label>
      <label>Notes <input id="mpf-notes" value="${escape(map ? map.notes : '')}"></label>`;
  }

  function editMapDialog(map) {
    App.modal(map ? `Rename map: ${map.name}` : 'New map', mapForm(map), [
      { label: 'Cancel', onClick: App.closeModal },
      { label: map ? 'Save' : 'Create', primary: true, onClick: async (box) => {
        if (!App.requireFields(box, [['#mpf-name', 'Name']])) return;
        const name = box.querySelector('#mpf-name').value.trim();
        const notes = box.querySelector('#mpf-notes').value.trim();
        if (map) {
          await App.put(`/api/mapper/maps/${map.id}`, { name, notes });
        } else {
          const result = await App.post('/api/mapper/maps', { name, notes });
          view.mapId = result.id;
        }
        App.closeModal();
        await loadMapsList();
        await selectMap(view.mapId);
        mapsDialog();
      } },
    ]);
  }

  function confirmDeleteMap(map) {
    App.confirmDestructive('Delete map',
      `<p>Delete <b>${escape(map.name)}</b>? Every device and link placement on it is lost — ` +
      'the devices themselves, and their live neighbour data, are untouched.</p>',
      'Delete',
      () => App.del(`/api/mapper/maps/${map.id}`),
      async (confirmed) => {
        if (!confirmed) return;
        if (view.mapId === map.id) view.mapId = null;
        await loadMapsList();
        if (view.mapId === null && view.maps.length) view.mapId = view.maps[0].id;
        await selectMap(view.mapId);
        mapsDialog();
      });
  }

  function mapsDialog() {
    const rows = view.maps.map((m) => `
      <tr>
        <td>${escape(m.name)}</td>
        <td class="hint">${escape(m.notes || '—')}</td>
        <td class="num">${m.node_count}</td>
        <td>${App.agoCell(m.updated_ts)}</td>
        <td><button data-rename="${m.id}" data-requires-write="mapper" ${App.canWrite('mapper') ? '' : 'disabled'}>Rename</button>
          <button data-delete="${m.id}" class="danger" data-requires-write="mapper" ${App.canWrite('mapper') ? '' : 'disabled'}>Delete</button></td>
      </tr>`).join('');
    const box = App.modal('Maps', `
      <table class="table-wrap"><caption class="sr-only">Maps</caption><thead><tr>
        <th scope="col">Name</th><th scope="col">Notes</th><th scope="col">Devices</th>
        <th scope="col">Updated</th><th scope="col"></th>
      </tr></thead><tbody>${rows || '<tr><td colspan="5" class="empty">No maps yet</td></tr>'}</tbody></table>`,
      [
        { label: 'Close', onClick: App.closeModal },
        { label: 'New map', primary: true, onClick: () => editMapDialog(null) },
      ]);
    for (const btn of box.querySelectorAll('[data-rename]')) {
      btn.onclick = () => editMapDialog(view.maps.find((m) => m.id === Number(btn.dataset.rename)));
    }
    for (const btn of box.querySelectorAll('[data-delete]')) {
      btn.onclick = () => confirmDeleteMap(view.maps.find((m) => m.id === Number(btn.dataset.delete)));
    }
    return box;
  }

  /* ------------------------------------------------------------ map data */

  // Every by-id lookup, built once per payload instead of scanned per
  // call; linksByNode also feeds redrawDragged's per-pointermove lookup.
  function rebuildLookups() {
    view.nodeByDevice = new Map();
    view.nodeByPeer = new Map();
    view.nodeMap = new Map();
    for (const n of view.nodes) {
      view.nodeMap.set(n.id, n);
      if (n.device_id !== null && n.device_id !== undefined) view.nodeByDevice.set(n.device_id, n);
      else if (n.peer_key) view.nodeByPeer.set(n.peer_key, n);
    }
    view.linkMap = new Map(view.links.map((l) => [l.id, l]));
    view.vlanNameById = new Map(view.vlans.map((v) => [v.vlan, v.name || '']));
    view.linksByNode = new Map();
    for (const link of view.links) {
      const a = linkNodeA(link), b = linkNodeB(link);
      for (const node of (a && b && a.id === b.id) ? [a] : [a, b]) {
        if (!node) continue;
        const list = view.linksByNode.get(node.id);
        if (list) list.push(link); else view.linksByNode.set(node.id, [link]);
      }
    }
  }

  async function loadMapData() {
    const generation = ++view.loadGen;
    if (view.mapId === null) {
      view.map = null; view.nodes = []; view.links = []; view.peersByKey = new Map(); view.vlans = [];
      rebuildLookups();
      drawStatus(); draw(); drawDetail(); drawVlanTable(); drawLegend();
      return;
    }
    const payload = await App.get(`/api/mapper/maps/${view.mapId}`);
    if (view.loadGen !== generation) return;   // a newer selectMap/refresh already superseded this
    view.map = payload.map;
    view.nodes = payload.nodes || [];
    view.links = payload.links || [];
    view.peersByKey = new Map((payload.peers || []).map((p) => [p.peer_key, p]));
    view.vlans = payload.vlans || [];
    rebuildLookups();
    // A reload landing mid-drag (a settings save) ends the drag: the payload
    // replaces the ids and positions it holds.
    if (view.nodeDrag) view.nodeDrag = null;
    if (payload.settings) view.settings = payload.settings;
    // A selection or a highlighted link that no longer exists on the fresh
    // payload (removed elsewhere) is dropped rather than left pointing at
    // nothing — drawDetail below reads view.selection/selectedLinkId as
    // ground truth for what to show.
    for (const id of [...view.selection]) if (!nodeById(id)) view.selection.delete(id);
    if (view.selectedLinkId && !linkById(view.selectedLinkId)) view.selectedLinkId = null;
    App.el('mp-map-name').textContent = view.map ? view.map.name : '';
    App.el('mp-snap').checked = !!view.settings.snap_to_grid;
    drawStatus();
    draw();
    drawDetail();
    drawVlanTable();
    drawLegend();
  }

  /* ---------------------------------------------------------- candidates */

  async function loadCandidates() {
    if (view.mapId === null) { view.candidates = { devices: [], neighbours: [] }; return; }
    view.candidates = await App.get(`/api/mapper/maps/${view.mapId}/candidates`);
  }

  const DEVICE_PICK_COLUMNS = [
    { key: 'check', label: '', width: 34, sortable: false,
      cell: (r) => `<input type="checkbox" class="mp-pick" data-id="${r.id}">` },
    { key: 'name', label: 'Name', width: 200, value: (r) => (r.name || r.ip || '').toLowerCase(),
      cell: (r) => escape(r.name || r.ip) },
    { key: 'ip', label: 'IP', width: 130, cell: (r) => escape(r.ip || '—') },
    { key: 'vendor', label: 'Vendor', width: 140, cell: (r) => escape(r.vendor || '—') },
  ];

  // A brand-new node's x/y default to (0,0) server-side when the caller
  // omits them (post_mapper_map_nodes) — fine for the very first device
  // ever placed on a map, but adding several in one batch would stack every
  // one of them exactly on top of the last with nothing to drag apart from
  // a single point. Staggered in a loose grid beyond the map's current
  // right edge instead, so a batch add lands as N distinct, already-visible
  // boxes an operator can then arrange, not a pile they have to pull apart
  // one at a time first.
  // `bounds` is measured once by the caller before its loop, not re-walked
  // per node added.
  function nextPlacement(index, bounds) {
    const baseX = bounds ? bounds.x + bounds.width + 100 : 0;
    const baseY = bounds ? bounds.y : 0;
    const step = NODE_W + 20;
    return { x: baseX + (index % 4) * step, y: baseY + Math.floor(index / 4) * (NODE_H + 20) };
  }

  async function openAddDevice() {
    await loadCandidates();
    const box = App.modal('Add device', `
      <input id="mpad-q" placeholder="Search by name, IP or vendor…" style="width:100%;margin-bottom:var(--space-sm)">
      <div class="table-wrap tall"><table id="mpad-table"></table></div>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        const ids = [...b.querySelectorAll('.mp-pick:checked')].map((el) => Number(el.dataset.id));
        if (!ids.length) { App.closeModal(); return; }
        const bounds = contentBounds();
        for (let i = 0; i < ids.length; i += 1) {
          const pos = nextPlacement(i, bounds);
          await App.post(`/api/mapper/maps/${view.mapId}/nodes`, { device_id: ids[i], x: pos.x, y: pos.y });
        }
        App.closeModal();
        await loadMapData();
      } },
    ]);
    let sort = { key: 'name', descending: false };
    const draw2 = () => {
      const q = box.querySelector('#mpad-q').value.trim().toLowerCase();
      const rows = (view.candidates.devices || []).filter((r) =>
        !q || (r.name || '').toLowerCase().includes(q) || (r.ip || '').toLowerCase().includes(q)
        || (r.vendor || '').toLowerCase().includes(q));
      const table = App.grid(box.querySelector('#mpad-table'), {
        name: 'mapper-add-device', caption: 'Devices not yet on this map',
        columns: DEVICE_PICK_COLUMNS, sort, onSort: (key, descending) => { sort = { key, descending }; draw2(); },
      });
      const body = document.createElement('tbody');
      App.drawRows(body, App.sortRows(rows, sort.key, sort.descending, DEVICE_PICK_COLUMNS),
        DEVICE_PICK_COLUMNS, null, 'Every device is already on this map, or none matched the search.');
      table.appendChild(body);
    };
    box.querySelector('#mpad-q').oninput = draw2;
    draw2();
  }

  // netpath/web/api.py's get_mapper_map_candidates: each row is
  // {kind:'device', device_id, name, seen_from_device_id, seen_from_port}
  // or {kind:'peer', peer_key, name, platform, address, seen_from_device_id,
  // seen_from_port} — no protocol field travels with a candidate (only an
  // already-placed LINK's own `protocols` does), so there is no "Via"
  // column to draw here.
  const NEIGHBOUR_PICK_COLUMNS = [
    { key: 'check', label: '', width: 34, sortable: false,
      cell: (r) => `<input type="checkbox" class="mp-pick" data-key="${escape(r.key)}">` },
    { key: 'name', label: 'Name', width: 200, value: (r) => (r.name || '').toLowerCase(),
      cell: (r) => escape(r.name || r.peer_key || `#${r.device_id}`) },
    { key: 'seen_from', label: 'Seen from', width: 180, value: (r) => (r.seenFromName || '').toLowerCase(),
      cell: (r) => escape(r.seenFromName) },
    { key: 'seen_from_port', label: 'Port', width: 130, cell: (r) => escape(r.seen_from_port || '—') },
  ];

  async function openAddNeighbours() {
    await loadCandidates();
    // Each candidate is either a matched, addable device (kind:'device') or
    // an unmanaged peer (kind:'peer') — `key` disambiguates the two in the
    // checkbox's own dataset since a device_id and an unrelated peer_key
    // could otherwise collide as DOM attribute values. The device that SAW
    // this neighbour is necessarily already placed on this map (the server
    // only walks rows for on-map devices), so its name is resolved from
    // view.nodeByDevice rather than a second fetch of /api/nodes/devices.
    const rows = (view.candidates.neighbours || []).map((r) => {
      const seenFrom = view.nodeByDevice.get(r.seen_from_device_id);
      return {
        ...r, key: r.kind === 'device' ? `d:${r.device_id}` : `p:${r.peer_key}`,
        seenFromName: seenFrom ? seenFrom.name : `#${r.seen_from_device_id}`,
      };
    });
    const box = App.modal('Add neighbours', `
      <p class="hint">Neighbours seen by a device already on this map, one hop out. ` +
      'Nothing is added automatically — pick which ones belong here.</p>' +
      '<div class="table-wrap tall"><table id="mpan-table"></table></div>', [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        const keys = [...b.querySelectorAll('.mp-pick:checked')].map((el) => el.dataset.key);
        if (!keys.length) { App.closeModal(); return; }
        const bounds = contentBounds();
        for (let i = 0; i < keys.length; i += 1) {
          const row = rows.find((r) => r.key === keys[i]);
          if (!row) continue;
          const pos = nextPlacement(i, bounds);
          if (row.kind === 'device') {
            await App.post(`/api/mapper/maps/${view.mapId}/nodes`,
              { device_id: row.device_id, x: pos.x, y: pos.y });
          } else {
            await App.post(`/api/mapper/maps/${view.mapId}/nodes`,
              { peer_key: row.peer_key, label: row.name || '', x: pos.x, y: pos.y });
          }
        }
        App.closeModal();
        await loadMapData();
      } },
    ]);
    let sort = { key: 'name', descending: false };
    // App.grid re-run per redraw (as drawVlanTable does): called once
    // outside, re-sorting appended a second <tbody> and doubled every row.
    function redrawNeighbourRows() {
      const table = App.grid(box.querySelector('#mpan-table'), {
        name: 'mapper-add-neighbours', caption: 'Neighbours not yet on this map',
        columns: NEIGHBOUR_PICK_COLUMNS, sort, onSort: (key, descending) => {
          sort = { key, descending }; redrawNeighbourRows(); },
      });
      const body = document.createElement('tbody');
      App.drawRows(body, App.sortRows(rows, sort.key, sort.descending, NEIGHBOUR_PICK_COLUMNS),
        NEIGHBOUR_PICK_COLUMNS, null,
        'No neighbours to add — every one already on this map, or nothing placed here has reported any.');
      table.appendChild(body);
    }
    redrawNeighbourRows();
  }

  function removeSelected() {
    if (!view.selection.size) return;
    const names = [...view.selection].map((id) => resolveNode(nodeById(id)).name).filter(Boolean);
    App.confirmDestructive('Remove from map',
      `<p>Remove ${names.length === 1 ? `<b>${escape(names[0])}</b>` : `${names.length} device(s)`} ` +
      'from this map? The device itself (and its live data in Nodes) is untouched — ' +
      'only its placement here is removed, along with any links drawn to it.</p>',
      'Remove',
      async () => {
        for (const id of [...view.selection]) {
          await App.del(`/api/mapper/maps/${view.mapId}/nodes/${id}`);
        }
      },
      async (confirmed) => {
        if (!confirmed) return;
        view.selection.clear();
        await loadMapData();
      });
  }

  /* ------------------------------------------------------------- geometry
     Where a link's drawn line actually touches a node: clipped to the
     node's own ellipse (a cheap, corner-free approximation of the
     rounded box) rather than running center-to-center through the label,
     the way a hand-drawn network diagram would. */
  function edgePoint(cx, cy, hw, hh, dx, dy) {
    if (!dx && !dy) return { x: cx, y: cy };
    const scale = 1 / Math.sqrt((dx / hw) ** 2 + (dy / hh) ** 2);
    return { x: cx + dx * scale, y: cy + dy * scale };
  }

  /* ------------------------------------------------------------- drawing */

  function shouldDrawGrid() {
    return !!view.settings.snap_to_grid || view.settings.map_style === 'blueprint'
      || view.settings.map_style === 'classic';
  }

  function currentMapStyle() {
    return MAP_STYLES.includes(view.settings.map_style) ? view.settings.map_style : 'modern';
  }

  // One <pattern>+<rect>, not one <line> per step: a 6,000-unit map at the
  // default 20-unit grid drew 600 hit-testable line elements, re-laid-out
  // every redraw. .mp-grid-line still names the stroke for app.css.
  const GRID_PATTERN_ID = 'mp-grid-pattern';

  function drawGrid(layer, bounds) {
    const size = Math.max(Number(view.settings.grid_size) || 20, 4);
    const x0 = Math.floor((bounds.x - size) / size) * size;
    const y0 = Math.floor((bounds.y - size) / size) * size;
    const x1 = Math.ceil((bounds.x + bounds.width + size) / size) * size;
    const y1 = Math.ceil((bounds.y + bounds.height + size) / size) * size;
    const defs = App.svgNode('defs');
    const pattern = App.svgNode('pattern', {
      id: GRID_PATTERN_ID, x: x0, y: y0, width: size, height: size,
      patternUnits: 'userSpaceOnUse',
    });
    pattern.appendChild(App.svgNode('path', {
      class: 'mp-grid-line', fill: 'none', d: `M ${size} 0 L 0 0 L 0 ${size}`,
    }));
    defs.appendChild(pattern);
    layer.appendChild(defs);
    layer.appendChild(App.svgNode('rect', {
      class: 'mp-grid', x: x0, y: y0, width: x1 - x0, height: y1 - y0,
      fill: `url(#${GRID_PATTERN_ID})`,
    }));
  }

  // A VLAN id, named: "20 (Engineering)" when this map's own VLAN summary
  // (view.vlans, from the VLANs table) has a name for it, else just "20" —
  // shared by the link-level text (linkAriaLabel/linkTooltip, both of which
  // already listed the bare ids) and the per-strand text below (which did
  // not exist before: see the strands-mode comment in drawLink).
  function vlanDisplay(vlanId) {
    const name = view.vlanNameById.get(vlanId);
    return name ? `${vlanId} (${name})` : `${vlanId}`;
  }

  function drawLink(layer, link) {
    const a = linkNodeA(link), b = linkNodeB(link);
    if (!a || !b) return;   // an end not placed on THIS map: server already filters this out, belt-and-braces
    const pa = livePos(a), pb = livePos(b);
    const dx = pb.x - pa.x, dy = pb.y - pa.y;
    const from = edgePoint(pa.x, pa.y, NODE_W / 2, NODE_H / 2, dx, dy);
    const to = edgePoint(pb.x, pb.y, NODE_W / 2, NODE_H / 2, -dx, -dy);
    const len = Math.max(Math.hypot(dx, dy), 1e-6);
    const nx = -dy / len, ny = dx / len;
    const plan = link.plan || { mode: 'plain', width: 1.5, known: false, strands: [], vlans: [] };
    const selected = view.selectedLinkId === link.id;
    const dimmed = view.selectedVlan !== null
      && !(plan.vlans || []).includes(view.selectedVlan);
    // opts.focusable (default true) and opts.ariaLabel/opts.tooltip (default
    // the whole-link text) let the strands branch below give every strand
    // its OWN name and tooltip while keeping only one of them in the Tab
    // order — see that branch's own comment for why.
    const wireOne = (path, extraClass, opts = {}) => {
      const focusable = opts.focusable !== false;
      // Built lazily on first hover/focus, not while drawing: a 30-strand
      // link built 30 tooltip strings nobody may ever look at.
      let tooltipText = null;
      const tipText = () => {
        if (tooltipText === null) {
          tooltipText = opts.tooltip ? opts.tooltip() : linkTooltip(link);
        }
        return tooltipText;
      };
      path.classList.add('mp-link');
      if (extraClass) path.classList.add(extraClass);
      if (selected) path.classList.add('selected');
      if (dimmed) path.classList.add('dimmed');
      path.dataset.linkId = link.id;
      // A non-focusable strand still gets role="img" + aria-label, not no
      // role at all — a screen reader's browse/scan cursor (unlike Tab) can
      // land on any named node regardless of focusability, so a strand this
      // Tab skips is still discoverable by name that way. 'button' only for
      // the one stop that is actually reachable by keyboard.
      path.setAttribute('role', focusable ? 'button' : 'img');
      path.setAttribute('aria-label', opts.ariaLabel || linkAriaLabel(link));
      path.addEventListener('click', () => selectLink(link.id));
      path.addEventListener('mousemove', (event) => App.tooltip(tipText(), event));
      path.addEventListener('mouseleave', App.hideTooltip);
      if (focusable) {
        path.tabIndex = 0;
        path.addEventListener('keydown', (event) => {
          if (event.key !== 'Enter' && event.key !== ' ') return;
          event.preventDefault();
          selectLink(link.id);
        });
        path.addEventListener('focus', () => {
          const box = path.getBoundingClientRect();
          App.tooltip(tipText(), { clientX: box.left + box.width / 2, clientY: box.top });
        });
        path.addEventListener('blur', App.hideTooltip);
      }
      layer.appendChild(path);
      return path;
    };
    if (view.settings.show_port_labels) drawPortLabels(layer, link, from, to, nx, ny);
    if (plan.mode === 'strands' && plan.strands.length) {
      // Finding 9: every strand used to get the identical aria-label/tooltip
      // (the link's own, naming no VLAN at all), so colour was the ONLY way
      // to tell strand N from strand N+1 — invisible to a colour-blind or
      // screen-reader user, and a keyboard user got to Tab through up to
      // max_strand_vlans (30) indistinguishable stops for one link.
      // Considered making every strand its own Tab stop with its own label:
      // rejected, because thirty identically-shaped Tab stops for one link
      // is worse UX than one, whatever their labels say, and it would make a
      // "strands" link behave nothing like a "collapsed" one (already a
      // single stop) for no reason a keyboard user would understand. So only
      // the FIRST strand is focusable — the same single Tab stop a collapsed
      // link gets, carrying the whole link's aria-label (now listing every
      // VLAN by id/name, not just a count: see linkAriaLabel). Every strand,
      // focusable or not, still gets its own per-VLAN aria-label (role="img",
      // discoverable by a screen reader's browse cursor even off the Tab
      // order) and its own mouse tooltip, so hovering a specific coloured
      // line — not just Tabbing to the link — names that one VLAN.
      plan.strands.forEach((strand, i) => {
        const ox = nx * strand.offset, oy = ny * strand.offset;
        const path = App.svgNode('path', {
          d: `M ${from.x + ox} ${from.y + oy} L ${to.x + ox} ${to.y + oy}`,
          // --canvas-vlan-*, not --vlan-* — this strand is drawn on
          // #mp-canvas (background: var(--canvas)), and --vlan-1..16 is
          // tuned against --panel, the VLAN table's swatch background, not
          // this one. See tokens.css's --canvas-vlan-* comment.
          stroke: `var(--canvas-vlan-${strand.color_index + 1})`, 'stroke-width': plan.width,
        });
        wireOne(path, null, i === 0
          ? { focusable: true, ariaLabel: linkAriaLabel(link), tooltip: () => linkTooltip(link) }
          : {
            focusable: false,
            ariaLabel: `VLAN ${vlanDisplay(strand.vlan)} strand on the link.`,
            tooltip: () => strandTooltip(link, strand),
          });
        if (view.settings.show_vlan_labels) {
          layer.appendChild(App.svgNode('text', {
            class: 'mp-link-label', x: (from.x + to.x) / 2 + ox, y: (from.y + to.y) / 2 + oy - 3,
            'text-anchor': 'middle',
          }, `${strand.vlan}`));
        }
      });
      return;
    }
    const neutral = 'var(--canvas-muted)';
    const path = App.svgNode('path', {
      d: `M ${from.x} ${from.y} L ${to.x} ${to.y}`, stroke: neutral, 'stroke-width': plan.width,
    });
    wireOne(path, plan.known === false ? 'unknown' : null);
    if (plan.mode === 'collapsed' && view.settings.show_vlan_labels) {
      const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
      layer.appendChild(App.svgNode('text', {
        class: 'mp-link-label', x: mx, y: my - 4, 'text-anchor': 'middle',
      }, `${plan.vlan_count} VLANs`));
    }
  }

  // show_port_labels: a small label at each end of the line naming that
  // end's own port — link.a_port/b_port, already resolved server side by
  // _neighbor_local_port_labeler. Drawn regardless of plan.mode (a "plain",
  // unknown-VLAN link still has two real ports), inset along the link so the
  // text clears the node box, and offset to one side of the line (the same
  // normal `nx,ny` the strand offsets use) so it never sits on top of the
  // stroke itself.
  function drawPortLabels(layer, link, from, to, nx, ny) {
    if (!link.a_port && !link.b_port) return;
    const dx = to.x - from.x, dy = to.y - from.y;
    const len = Math.max(Math.hypot(dx, dy), 1e-6);
    const ux = dx / len, uy = dy / len;
    const inset = 18, aside = 8;
    if (link.a_port) {
      layer.appendChild(App.svgNode('text', {
        class: 'mp-link-label', x: from.x + ux * inset + nx * aside, y: from.y + uy * inset + ny * aside,
        'text-anchor': 'start',
      }, link.a_port));
    }
    if (link.b_port) {
      layer.appendChild(App.svgNode('text', {
        class: 'mp-link-label', x: to.x - ux * inset + nx * aside, y: to.y - uy * inset + ny * aside,
        'text-anchor': 'end',
      }, link.b_port));
    }
  }

  // The one stop a "strands" or "collapsed" link gets (see drawLink's own
  // comment on that decision): the full VLAN list, not just a count, so a
  // keyboard/screen-reader user gets everything a sighted user reading every
  // strand's colour would — capped at 16 named entries (a full 16-VLAN
  // strand bundle, the point at which vlan_collapse_threshold's own default
  // would already have collapsed a wider trunk) before falling back to a
  // count, since an aria-label is read aloud in full and a 200-VLAN
  // collapsed trunk should not turn into a paragraph — the detail pane
  // (linkDetailHtml), reachable from that same one stop, always has the
  // complete list regardless.
  function linkAriaLabel(link) {
    const a = resolveNode(linkNodeA(link)).name;
    const b = resolveNode(linkNodeB(link)).name;
    const plan = link.plan || {};
    let vlanText;
    if (plan.known === false) {
      vlanText = 'no VLAN data';
    } else {
      const vlans = plan.vlans || [];
      if (!vlans.length) vlanText = '0 VLANs';
      else if (vlans.length <= 16) vlanText = `${vlans.length} VLAN(s): ${vlans.map(vlanDisplay).join(', ')}`;
      else vlanText = `${vlans.length} VLANs — open the link for the full list`;
    }
    return `Link, ${a} to ${b}, ${vlanText}.`;
  }

  // '' for a port whose mode nothing reported — an unmanaged peer has no
  // VLAN MIB of its own, and a sysName-only match has no resolvable far-end
  // port to ask about, so this is blank far more often than it is wrong.
  function portMode(mode) {
    return mode === 'trunk' || mode === 'access' ? ` · ${mode}` : '';
  }

  // How many VLANs a hover/detail-pane screen names before "N more".
  const VLAN_TOOLTIP_CAP = 10;
  const VLAN_DETAIL_CAP = 10;

  function linkTooltip(link) {
    const a = resolveNode(linkNodeA(link)).name;
    const b = resolveNode(linkNodeB(link)).name;
    const plan = link.plan || {};
    const lines = [`${a} (${link.a_port || '—'})${portMode(link.a_port_mode)}`,
      `↕ ${(link.protocols || []).join(', ').toUpperCase()}`,
      `${b} (${link.b_port || '—'})${portMode(link.b_port_mode)}`, ''];
    if (plan.known === false) {
      lines.push('No VLAN data known for this link.');
    } else {
      // A 200-VLAN trunk listing every id grew the tooltip past the window
      // with no scroll, hiding the native-VLAN line below it. Cap it and
      // point to the detail pane for the rest.
      const vlans = plan.vlans || [];
      const shown = vlans.slice(0, VLAN_TOOLTIP_CAP).map(vlanDisplay).join(', ');
      lines.push(`VLANs (${vlans.length}): ${shown}`
        + (vlans.length > VLAN_TOOLTIP_CAP
          ? `, +${vlans.length - VLAN_TOOLTIP_CAP} more (open the link for the full list)` : ''));
    }
    // Each end's own native VLAN, as the device itself reported it
    // (vlan_ports.native_vlan), falling back on the a side to the value
    // inferred from which VLAN crosses the port untagged. The two ends can
    // genuinely disagree, and a native-VLAN mismatch across a trunk is a
    // real misconfiguration worth seeing rather than averaging away.
    const natA = link.a_native_vlan ?? link.native_vlan;
    const natB = link.b_native_vlan;
    const hasA = natA !== null && natA !== undefined;
    const hasB = natB !== null && natB !== undefined;
    if (hasA && hasB && natA !== natB) {
      lines.push(`Native VLAN ${natA} on ${a}, ${natB} on ${b} — mismatched`);
    } else if (hasA) {
      lines.push(`Native VLAN ${natA}`);
    } else if (hasB) {
      lines.push(`Native VLAN ${natB}`);
    }
    return lines.join('\n');
  }

  // Finding 9's per-strand tooltip: what THIS strand is, not the whole link
  // — the link-level linkTooltip above still lists every VLAN for whichever
  // strand ends up carrying the focusable stop.
  function strandTooltip(link, strand) {
    const a = resolveNode(linkNodeA(link)).name;
    const b = resolveNode(linkNodeB(link)).name;
    const native = link.native_vlan === strand.vlan ? ' (native)' : '';
    return `${a} ↔ ${b}\nVLAN ${vlanDisplay(strand.vlan)}${native}`;
  }

  function drawNode(layer, node) {
    const info = resolveNode(node);
    const pos = livePos(node);
    const g = App.svgNode('g', {
      class: `mp-node${view.selection.has(node.id) ? ' selected' : ''}` +
        `${info.unmanaged ? ' unmanaged' : ''}${info.gone ? ' gone' : ''}`,
      transform: `translate(${pos.x - NODE_W / 2},${pos.y - NODE_H / 2})`,
    });
    g.dataset.nodeId = node.id;
    const rx = MAP_STYLE_RADIUS[currentMapStyle()];
    g.appendChild(App.svgNode('rect', {
      class: 'mp-node-box', x: 0.5, y: 0.5, width: NODE_W - 1, height: NODE_H - 1, rx,
    }));
    g.appendChild(drawRoleIcon(info.role, 8, (NODE_H - ICON) / 2));
    // Status is never colour alone: the same shape App.statusMark uses
    // elsewhere is drawn here too, sized for the canvas rather than the
    // <i> glyph the table version renders as text.
    if (!info.unmanaged && !info.gone) {
      g.appendChild(statusGlyph(info.tone, NODE_W - 14, 12));
    }
    const nameNode = App.svgNode('text', {
      class: 'mp-node-label', x: 30, y: 22,
    }, truncate(info.name, 16));
    g.appendChild(nameNode);
    if (info.sub) {
      g.appendChild(App.svgNode('text', { class: 'mp-node-sub', x: 30, y: 36 }, truncate(info.sub, 20)));
    }
    // Badges: only ever present when the matching setting is on (the
    // server nulls each one out otherwise, see get_mapper_map), so no
    // client-side check of view.settings.badge_* is needed here — a badge
    // renders exactly when there is a reading to show.
    const badgeParts = [];
    if (info.badges.temp_c !== null && info.badges.temp_c !== undefined) {
      badgeParts.push(`${Math.round(info.badges.temp_c)}°C`);
    }
    if (info.badges.cpu_pct !== null && info.badges.cpu_pct !== undefined) {
      badgeParts.push(`${Math.round(info.badges.cpu_pct)}%`);
    }
    if (info.badges.port_count !== null && info.badges.port_count !== undefined) {
      badgeParts.push(`${info.badges.port_count}p`);
    }
    if (badgeParts.length) {
      g.appendChild(App.svgNode('text', {
        class: 'mp-node-sub', x: NODE_W - 8, y: NODE_H - 8, 'text-anchor': 'end',
      }, badgeParts.join(' · ')));
    }
    g.tabIndex = 0;
    g.setAttribute('role', 'button');
    g.setAttribute('aria-label', `${info.name}${info.unmanaged ? ', unmanaged peer' : ''}` +
      `${info.gone ? ', removed from Nodes' : ''}.`);
    g.addEventListener('mousemove', (event) => { if (!view.nodeDrag) App.tooltip(info.tooltip, event); });
    g.addEventListener('mouseleave', () => { if (!view.nodeDrag) App.hideTooltip(); });
    g.addEventListener('focus', () => {
      const box = g.getBoundingClientRect();
      App.tooltip(info.tooltip, { clientX: box.left + box.width / 2, clientY: box.top });
    });
    g.addEventListener('blur', App.hideTooltip);
    g.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        setSelection(new Set([node.id]));
      }
    });
    g.addEventListener('pointerdown', (event) => onNodePointerDown(event, node));
    layer.appendChild(g);
    return g;
  }

  // A minimal stand-in for App.statusMark inside SVG: statusMark's own
  // output is HTML (a styled <span>/<i>), which cannot be dropped into an
  // SVG tree, so the same three shapes (dot/triangle/square, plus a
  // hollow ring for "none") are drawn here as small paths carrying the
  // same tones, so a node's health is never colour alone on the canvas either.
  function statusGlyph(tone, x, y) {
    const color = { ok: 'var(--canvas-ok)', warn: 'var(--canvas-warn)',
      fail: 'var(--canvas-fail)', none: 'var(--canvas-faint)' }[tone] || 'var(--canvas-faint)';
    if (tone === 'ok') return App.svgNode('circle', { cx: x, cy: y, r: 3.5, fill: color });
    if (tone === 'warn') {
      return App.svgNode('path', { d: `M ${x} ${y - 4} L ${x + 4} ${y + 3} L ${x - 4} ${y + 3} Z`, fill: color });
    }
    if (tone === 'fail') return App.svgNode('rect', { x: x - 3.5, y: y - 3.5, width: 7, height: 7, fill: color });
    return App.svgNode('circle', { cx: x, cy: y, r: 3.5, fill: 'none', stroke: color, 'stroke-width': 1.4 });
  }

  function truncate(text, max) {
    const s = String(text || '');
    return s.length > max ? `${s.slice(0, max - 1)}…` : s;
  }

  function contentBounds() {
    if (!view.nodes.length) return null;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const node of view.nodes) {
      const p = livePos(node);
      minX = Math.min(minX, p.x - NODE_W / 2); maxX = Math.max(maxX, p.x + NODE_W / 2);
      minY = Math.min(minY, p.y - NODE_H / 2); maxY = Math.max(maxY, p.y + NODE_H / 2);
    }
    return { x: minX, y: minY, width: maxX - minX, height: maxY - minY };
  }

  // `bounds`/size come from draw(), which already measured both — redoing
  // it here would force a second layout for answers it already holds.
  function fitView(bounds, width, height) {
    if (bounds && bounds.width) {
      view.zoom = Math.min(width / (bounds.width + 120), height / (bounds.height + 120), 2);
      view.pan = { x: 0, y: 0 };
      view.frame = { width, height, cx: bounds.x + bounds.width / 2, cy: bounds.y + bounds.height / 2 };
    } else {
      view.zoom = 1; view.pan = { x: 0, y: 0 };
      view.frame = { width, height, cx: 0, cy: 0 };
    }
    view.needsFit = false;
  }

  function translation(scale) {
    const f = view.frame;
    return { tx: f.width / 2 - f.cx * scale + view.pan.x, ty: f.height / 2 - f.cy * scale + view.pan.y };
  }

  // One full redraw per animation frame, however many times below ask for
  // one — a pointermove fires faster than 60Hz and used to rebuild the
  // whole scene synchronously, inside the event.
  let drawPending = 0;

  function requestDraw() {
    if (drawPending) return;
    drawPending = window.requestAnimationFrame(() => { drawPending = 0; draw(); });
  }

  // Pan/zoom/Fit only move the scene, so they transform the one group
  // instead of rebuilding it; falls back to a full draw with no scene yet.
  function applyTransform() {
    if (!view.sceneGroup || !view.frame) { requestDraw(); return; }
    const { tx, ty } = translation(view.zoom);
    view.sceneGroup.setAttribute('transform', `translate(${tx},${ty}) scale(${view.zoom})`);
  }

  // One drag redraw per animation frame, on its own handle: a pointermove
  // fires faster than 60Hz, and a queued full draw and a queued drag redraw
  // must not cancel each other out.
  let dragPending = 0;

  function requestDragDraw() {
    if (dragPending) return;
    dragPending = window.requestAnimationFrame(() => { dragPending = 0; redrawDragged(); });
  }

  // Redraws only the dragged nodes and the links touching them.
  function redrawDragged() {
    if (!view.nodeDrag || !view.nodeEls.size) { requestDraw(); return; }
    const touched = new Set();
    for (const id of view.nodeDrag.ids) {
      const node = nodeById(id);
      const el = view.nodeEls.get(id);
      if (!node || !el) { requestDraw(); return; }
      const pos = livePos(node);
      el.setAttribute('transform', `translate(${pos.x - NODE_W / 2},${pos.y - NODE_H / 2})`);
      for (const link of view.linksByNode.get(id) || []) touched.add(link);
    }
    for (const link of touched) {
      const holder = view.linkEls.get(link.id);
      if (!holder) continue;
      holder.textContent = '';
      drawLink(holder, link);
    }
  }

  // Toggles a class in place: a full redraw at drag-start would replace
  // the very <g> the pointer is captured on.
  function applySelectionClasses() {
    if (!view.nodeEls.size) { requestDraw(); return; }
    for (const [id, el] of view.nodeEls) el.classList.toggle('selected', view.selection.has(id));
    for (const [id, holder] of view.linkEls) {
      for (const path of holder.querySelectorAll('.mp-link')) {
        path.classList.toggle('selected', view.selectedLinkId === id);
      }
    }
  }

  // One persistent rect moved in place, not re-appended by draw() per
  // pointermove.
  function drawRubber() {
    const el = view.rubberEl;
    if (!el) { requestDraw(); return; }
    if (!view.rubber) { el.style.display = 'none'; return; }
    const { x0, y0, x1, y1 } = view.rubber;
    el.setAttribute('x', Math.min(x0, x1));
    el.setAttribute('y', Math.min(y0, y1));
    el.setAttribute('width', Math.abs(x1 - x0));
    el.setAttribute('height', Math.abs(y1 - y0));
    el.style.display = '';
  }

  function draw() {
    const svg = App.el('mp-svg');
    const canvas = App.el('mp-canvas');
    canvas.dataset.mapStyle = currentMapStyle();
    // Replacing the <g> a drag captured means its release never arrives.
    view.nodeDrag = null;
    svg.innerHTML = '';
    view.sceneGroup = null;
    view.rubberEl = null;
    view.nodeEls = new Map();
    view.linkEls = new Map();

    if (!view.mapId) {
      return emptyCanvas(svg, canvas, 'No map selected. Use Maps to create or pick one.');
    }
    if (!view.nodes.length) {
      return emptyCanvas(svg, canvas,
        `${view.map ? view.map.name : 'This map'} has no devices yet. Use Add device or Add neighbours.`);
    }
    showCanvas(svg, canvas);

    // The SVG, not its wrapper: scenePoint, the pan and the wheel zoom all
    // measure #mp-svg, and #mp-canvas's own border made the two boxes differ
    // by a pixel in each axis — enough for a press to land beside the point
    // it was aimed at. Measured after showCanvas, since a canvas coming back
    // from the empty state is display:none until then.
    const box = svg.getBoundingClientRect();
    const measured = box.width > 0 && box.height > 0;
    const width = Math.max(box.width, 200), height = Math.max(box.height, 200);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

    // Size is re-read every draw (the pane is resizable); centre and zoom are
    // the operator's own arrangement, so only opening a map (selectMap) or
    // Fit itself re-fits — a refresh, a resize or a badge change must not
    // throw away where they put things.
    const bounds = contentBounds();
    if (!view.frame || view.needsFit) {
      fitView(bounds, width, height);
      // A fit into the 200x200 fallback is not the fit the operator gets to keep.
      if (!measured) view.needsFit = true;
    } else { view.frame.width = width; view.frame.height = height; }
    const group = App.svgNode('g');
    const gridLayer = App.svgNode('g');
    const linkLayer = App.svgNode('g');
    const nodeLayer = App.svgNode('g');
    group.append(gridLayer, linkLayer, nodeLayer);
    svg.appendChild(group);
    if (shouldDrawGrid() && bounds) drawGrid(gridLayer, bounds);
    // Own <g> per link: redrawDragged refills just the ones that moved.
    for (const link of view.links) {
      const holder = App.svgNode('g');
      linkLayer.appendChild(holder);
      view.linkEls.set(link.id, holder);
      drawLink(holder, link);
    }
    for (const node of view.nodes) view.nodeEls.set(node.id, drawNode(nodeLayer, node));

    view.rubberEl = App.svgNode('rect', { class: 'mp-rubber' });
    group.appendChild(view.rubberEl);
    view.sceneGroup = group;
    drawRubber();
    applyTransform();
    canvas.tabIndex = 0;
    // 'img', not 'application': the same role netpath.js's own route canvas
    // carries, for the same reason — 'application' turns off the screen
    // reader's normal navigation entirely, which nothing here needs, since
    // every interactive part (a node, a link) is its own separately
    // focusable, separately labelled stop a Tab already reaches.
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label',
      `Map canvas. ${mapSummaryText()}. Arrow keys pan, +/- zoom, Tab into a device or link.`);
  }

  // The bare-<svg>-doesn't-reflect-`hidden` trap the deleted L2 topology
  // view documented (nodes.js, before 4.53.0): svg.style.display is set
  // directly rather than through the `hidden` property, since [hidden]'s
  // display:none never reliably applied to a root <svg> in every engine.
  function emptyCanvas(svg, canvas, message) {
    svg.style.display = 'none';
    let empty = canvas.querySelector(':scope > .empty');
    if (!empty) { empty = document.createElement('div'); empty.className = 'empty'; canvas.appendChild(empty); }
    empty.textContent = message;
    canvas.removeAttribute('tabindex');
    canvas.removeAttribute('role');
    canvas.removeAttribute('aria-label');
  }
  function showCanvas(svg, canvas) {
    svg.style.display = '';
    const empty = canvas.querySelector(':scope > .empty');
    if (empty) empty.remove();
  }

  /* -------------------------------------------------------------- legend */

  function drawLegend() {
    const threshold = Number(view.settings.vlan_collapse_threshold) || 8;
    const hasUnknown = view.links.some((l) => l.plan && l.plan.known === false);
    const hasLinks = view.links.length > 0;
    let text = `Trunks of ${threshold}+ VLANs draw as one thick line, scaled by count; ` +
      'fewer draw as one coloured strand per VLAN.';
    if (hasUnknown) text += ' A dashed line means no VLAN data at all, not "one VLAN".';
    if (view.nodes.length && !hasLinks) {
      text = 'No CDP/LLDP adjacency was found between the devices placed here — ' +
        'that is information, not an error; add neighbours once they report one.';
    }
    App.el('mp-legend').textContent = text;
  }

  /* ------------------------------------------------------------ selection */

  function setSelection(ids) {
    view.selection = ids;
    view.selectedLinkId = null;
    requestDraw();
    drawDetail();
  }

  function selectLink(id) {
    view.selectedLinkId = id;
    view.selection.clear();
    // Each link opens on its capped VLAN list; "Show all" is a decision
    // about the link being read, not a mode the pane stays in.
    view.detailShowAllVlans = false;
    requestDraw();
    drawDetail();
  }

  /* The pane is rebuilt from innerHTML on every draw, and auto-refresh
     draws on its own clock: a field the operator is typing in is put back
     (text, caret, focus) around the rebuild, or a tick empties it mid-word. */
  function drawDetail() {
    const detail = App.el('mp-detail');
    const active = document.activeElement;
    const editing = active && active.id && detail.contains(active)
      && typeof active.selectionStart === 'number'
      ? { id: active.id, value: active.value, start: active.selectionStart, end: active.selectionEnd }
      : null;
    renderDetail();
    if (!editing) return;
    const again = detail.querySelector(`#${CSS.escape(editing.id)}`);
    if (!again || again.disabled) return;
    again.value = editing.value;
    again.focus({ preventScroll: true });
    again.setSelectionRange(editing.start, editing.end);
  }

  function renderDetail() {
    const nameEl = App.el('mp-detail-name');
    const detail = App.el('mp-detail');
    if (view.selectedLinkId) {
      const link = linkById(view.selectedLinkId);
      if (!link) { view.selectedLinkId = null; return renderDetail(); }
      nameEl.textContent = 'LINK';
      detail.innerHTML = linkDetailHtml(link);
      const showAll = detail.querySelector('[data-show-all-vlans]');
      if (showAll) showAll.onclick = () => { view.detailShowAllVlans = true; drawDetail(); };
      return;
    }
    if (view.selection.size === 1) {
      const node = nodeById([...view.selection][0]);
      if (!node) { view.selection.clear(); return renderDetail(); }
      nameEl.textContent = 'DEVICE';
      detail.innerHTML = nodeDetailHtml(node);
      const removeBtn = detail.querySelector('[data-remove-node]');
      if (removeBtn) removeBtn.onclick = () => { view.selection = new Set([node.id]); removeSelected(); };
      const renameBtn = detail.querySelector('#mpd-rename-save');
      if (renameBtn) renameBtn.onclick = async () => {
        const label = detail.querySelector('#mpd-rename').value.trim();
        try {
          await App.put(`/api/mapper/maps/${view.mapId}/nodes`, { updates: [{ id: node.id, label }] });
          // Same local-patch shape the role select below uses: `name` is
          // recomputed the way _mapper_node_name computes it server side
          // (label if any, else resolved_name) so the canvas and this same
          // pane redraw with the new name on THIS response, not only after
          // the next full loadMapData().
          node.label = label;
          node.name = label || node.resolved_name;
          requestDraw();
          drawDetail();
        } catch (error) {
          App.toast(`Could not rename: ${error.message}`, 'fail');
        }
      };
      const renameInput = detail.querySelector('#mpd-rename');
      if (renameInput) renameInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && renameBtn) { event.preventDefault(); renameBtn.click(); }
      });
      const roleSelect = detail.querySelector('#mpd-role');
      if (roleSelect) roleSelect.onchange = async () => {
        const role = roleSelect.value;
        try {
          await App.put(`/api/mapper/maps/${view.mapId}/nodes`, { updates: [{ id: node.id, role }] });
          node.role = role;
          requestDraw();
        } catch (error) {
          App.toast(`Could not change role: ${error.message}`, 'fail');
          roleSelect.value = node.role || '';
        }
      };
      return;
    }
    if (view.selection.size > 1) {
      nameEl.textContent = 'SELECTION';
      detail.textContent = `${view.selection.size} devices selected. Drag to move them together, ` +
        'or use Align to line them up.';
      return;
    }
    nameEl.textContent = 'SELECTION';
    detail.innerHTML = '';   // .detail:empty::before shows the data-empty prompt
  }

  // The "manual override" half of role auto-detection: whatever the
  // server sent (auto-detected or previously overridden), an operator can
  // always pick a different role from the same fixed list mapperdb.ROLES
  // enforces server side. Wired in renderDetail(), which is the one place
  // that owns this pane's innerHTML and so the one place that can safely
  // attach a listener to whatever it just wrote.
  function roleSelectHtml(node) {
    // The selected value is the OVERRIDE, not the drawn role: '' whenever
    // role_auto, so a detected "switch" sits on the Auto option rather than
    // on Switch. The Auto option names what detection currently says, so
    // the operator can see the guess they are accepting instead of being
    // asked to trust a bare word.
    const auto = node.role_auto !== false;
    const chosen = auto ? '' : node.role;
    const options = ROLES.map((r) => {
      const label = r === '' && auto && node.role
        ? `Auto (${ROLE_LABEL[node.role] || node.role})` : ROLE_LABEL[r];
      return `<option value="${r}" ${chosen === r ? 'selected' : ''}>${escape(label)}</option>`;
    }).join('');
    return `<select id="mpd-role" data-requires-write="mapper"` +
      `${App.canWrite('mapper') ? '' : ' disabled'}>${options}</select>`;
  }

  // Finding 10b: map_nodes.label has had a full server path (PUT
  // .../nodes accepts it, get_mapper_map resolves it into `name`, the CSV
  // export reads that same `name`) since renaming shipped, but nothing in
  // this file ever let an operator type one in — the only way to rename a
  // node was a direct API call. Wired in renderDetail() alongside the role
  // select, the one place that owns this pane's innerHTML. A blank box
  // clears the override and falls back to `resolved_name` (its placeholder,
  // so the box shows what it will read as even while empty) — server-side
  // _mapper_node_name already treats an empty label exactly that way.
  function renameFieldHtml(node) {
    const canWrite = App.canWrite('mapper');
    return `<input id="mpd-rename" type="text" maxlength="200" value="${escape(node.label || '')}" ` +
      `placeholder="${escape(node.resolved_name || '')}" data-requires-write="mapper"` +
      `${canWrite ? '' : ' disabled'}> ` +
      `<button id="mpd-rename-save" data-requires-write="mapper"${canWrite ? '' : ' disabled'}>Rename</button>`;
  }

  // "renamed from X": shown whenever the operator's own label differs from
  // what live data resolves to, so a rename never quietly hides the
  // underlying identity — resolved_name exists on the payload for exactly
  // this (see api.py's _mapper_node_name docstring).
  function renamedFromHtml(node) {
    if (!node.label || !node.resolved_name || node.label === node.resolved_name) return '';
    return `\n            <span class="hint">renamed from ${escape(node.resolved_name)}</span>`;
  }

  function nodeDetailHtml(node) {
    const info = resolveNode(node);
    const lines = [escape(info.name)];
    // Rename is offered for every node kind, "gone" included — a device
    // deleted from Nodes still keeps its map_nodes row (and its label)
    // until the operator removes the placement themselves, so its name
    // here is exactly as editable as a live device's.
    lines.push('', `Name        ${renameFieldHtml(node)}${renamedFromHtml(node)}`);
    if (info.gone) {
      lines.push('', 'This device has been removed from Nodes. Its placement is kept here ' +
        'in case it returns; nothing about it is live any more.');
      // data-requires-write is what applyPermissions() re-checks on every
      // loadState; the explicit `disabled` alongside it is what keeps a
      // read-only account from seeing the button briefly enabled between
      // this innerHTML write and that next periodic pass.
      lines.push('', `<button data-remove-node="${node.id}" data-requires-write="mapper"` +
        `${App.canWrite('mapper') ? '' : ' disabled'}>Remove from map</button>`);
      return lines.join('\n');
    }
    if (info.unmanaged) {
      const peer = view.peersByKey.get(node.peer_key);
      lines.push('', 'Unmanaged peer — seen over LLDP/CDP, not polled directly.');
      lines.push(`Role        ${roleSelectHtml(node)}`);
      if (peer && peer.platform) lines.push(`Platform    ${escape(peer.platform)}`);
      if (node.ip) lines.push(`Address     ${escape(node.ip)}`);
      if (peer) {
        lines.push('', `Seen via (${peer.seen_via.length})`, '-'.repeat(30));
        for (const via of peer.seen_via) {
          // The reporting device is necessarily placed on THIS map (assemble_links
          // only walks rows for on_map devices), so view.nodeByDevice resolves it
          // without a second fetch of /api/nodes/devices.
          const seenBy = view.nodeByDevice.get(via.device_id);
          lines.push(`${escape(seenBy ? seenBy.name : `#${via.device_id}`)}` +
            ` — ${escape(via.port || '—')}`);
        }
      }
      return lines.join('\n');
    }
    lines.push('', `IP          ${escape(node.ip || '—')}`);
    lines.push(`Status      ${escape(DEVICE_STATUS_LABEL[node.status] || node.status || 'Unknown')}`);
    lines.push(`Role        ${roleSelectHtml(node)}`);
    if (info.badges.temp_c !== null && info.badges.temp_c !== undefined) {
      lines.push(`Chassis temp ${info.badges.temp_c.toFixed ? info.badges.temp_c.toFixed(1) : info.badges.temp_c}°C`);
    }
    if (info.badges.cpu_pct !== null && info.badges.cpu_pct !== undefined) {
      lines.push(`CPU         ${info.badges.cpu_pct}%`);
    }
    if (info.badges.port_count !== null && info.badges.port_count !== undefined) {
      lines.push(`Ports       ${info.badges.port_count}`);
    }
    lines.push('', `<a class="linkish inline" href="${App.buildRoute('nodes', ['device', node.device_id])}">Open in Nodes</a>`);
    return lines.join('\n');
  }

  function linkDetailHtml(link) {
    const a = resolveNode(linkNodeA(link));
    const b = resolveNode(linkNodeB(link));
    const plan = link.plan || {};
    const lines = [`${escape(a.name)} (${escape(link.a_port || '—')})`,
      `  ↕  ${escape((link.protocols || []).join(', ').toUpperCase())}`,
      `${escape(b.name)} (${escape(link.b_port || '—')})`, ''];
    if (plan.known === false) {
      lines.push('No VLAN data known for this link — neither end answered a VLAN MIB.');
    } else {
      const vlans = plan.vlans || [];
      const all = view.detailShowAllVlans || vlans.length <= VLAN_DETAIL_CAP;
      lines.push(`VLANs (${vlans.length})`, '-'.repeat(30));
      for (const vlan of all ? vlans : vlans.slice(0, VLAN_DETAIL_CAP)) {
        const name = view.vlanNameById.get(vlan);
        lines.push(`${vlan}${name ? `  ${escape(name)}` : ''}` +
          `${link.native_vlan === vlan ? '  (native)' : ''}`);
      }
      if (!all) {
        // Behind a button, not truncated outright: a 200-VLAN trunk pushed
        // Last seen off the bottom of a pane the operator can't resize.
        lines.push(`<button data-show-all-vlans>Show all ${vlans.length}</button>`);
      }
    }
    lines.push('', `Last seen   ${escape(App.ago(link.seen_ts))}`);
    return lines.join('\n');
  }

  /* -------------------------------------------------------- pointer input */

  // null until draw() sets a frame — an empty map or a pre-paint pointer
  // event has no scene to point at.
  function scenePoint(event) {
    if (!view.frame) return null;
    const svg = App.el('mp-svg');
    const rect = svg.getBoundingClientRect();
    const px = (event.clientX - rect.left) * (view.frame.width / Math.max(rect.width, 1));
    const py = (event.clientY - rect.top) * (view.frame.height / Math.max(rect.height, 1));
    const { tx, ty } = translation(view.zoom);
    return { x: (px - tx) / view.zoom, y: (py - ty) / view.zoom };
  }

  /* Every press on the map calls preventDefault, which also suppresses the
     focus the browser would have moved here; without this the arrow-key pan
     and +/- zoom the canvas advertises do nothing after a click. */
  function focusCanvas() {
    const canvas = App.el('mp-canvas');
    // preventScroll: the canvas is already the thing under the pointer, and
    // scrolling the page to it would move the map out from under the gesture.
    if (canvas && document.activeElement !== canvas) canvas.focus({ preventScroll: true });
  }

  function onNodePointerDown(event, node) {
    if (event.button !== 0 || !event.isPrimary || view.spaceHeld) return;
    event.preventDefault();
    event.stopPropagation();
    focusCanvas();
    // Captured once: currentTarget is null once this dispatch ends, and the
    // closures below run on later events.
    const target = event.currentTarget;
    if (event.shiftKey) {
      const next = new Set(view.selection);
      if (next.has(node.id)) next.delete(node.id); else next.add(node.id);
      if (!next.has(node.id)) { setSelection(next); return; }
      view.selection = next;
    } else if (!view.selection.has(node.id)) {
      view.selection = new Set([node.id]);
    }
    view.selectedLinkId = null;
    // No frame yet (a press landing before the first paint) means no scene to
    // move within: this press selects and starts nothing.
    if (!scenePoint(event)) { applySelectionClasses(); drawDetail(); return; }
    target.setPointerCapture(event.pointerId);
    const from = new Map();
    for (const id of view.selection) { const n = nodeById(id); if (n) from.set(id, { x: n.x, y: n.y }); }
    // Scene units per screen pixel, read once at the press: a wheel zoom
    // mid-drag is the one thing the drag then does not follow.
    const rect = App.el('mp-svg').getBoundingClientRect();
    const perPixelX = (view.frame.width / Math.max(rect.width, 1)) / view.zoom;
    const perPixelY = (view.frame.height / Math.max(rect.height, 1)) / view.zoom;
    const startClient = { x: event.clientX, y: event.clientY };
    view.nodeDrag = { ids: [...view.selection], from, dx: 0, dy: 0, moved: false };
    App.hideTooltip();
    const move = (moveEvent) => {
      if (!view.nodeDrag) return;
      const cdx = moveEvent.clientX - startClient.x, cdy = moveEvent.clientY - startClient.y;
      // Screen pixels, not scene units: MOVE_THRESHOLD_PX of pointer travel
      // means the same thing to a hand at every zoom, where a scene-unit
      // threshold was a third of a pixel zoomed out and a centimetre zoomed in.
      if (!view.nodeDrag.moved) {
        if (Math.hypot(cdx, cdy) <= MOVE_THRESHOLD_PX) return;
        view.nodeDrag.moved = true;
      }
      view.nodeDrag.dx = cdx * perPixelX;
      view.nodeDrag.dy = cdy * perPixelY;
      requestDragDraw();
    };
    const detach = () => {
      target.removeEventListener('pointermove', move);
      target.removeEventListener('pointerup', up);
      target.removeEventListener('pointercancel', cancel);
    };
    const up = () => {
      try {
        if (view.nodeDrag && view.nodeDrag.moved) {
          const snap = !!view.settings.snap_to_grid;
          for (const [id, base] of view.nodeDrag.from) {
            let x = base.x + view.nodeDrag.dx, y = base.y + view.nodeDrag.dy;
            if (snap) { x = snapValue(x); y = snapValue(y); }
            const n = nodeById(id);
            if (n) { n.x = x; n.y = y; }
            queuePositionWrite(id, { x, y });
          }
        }
      } finally {
        detach();
        view.nodeDrag = null;
        requestDraw();
        drawDetail();
      }
    };
    const cancel = () => { detach(); view.nodeDrag = null; requestDraw(); };
    target.addEventListener('pointermove', move);
    target.addEventListener('pointerup', up);
    target.addEventListener('pointercancel', cancel);
    applySelectionClasses();
    drawDetail();
  }

  function queuePositionWrite(id, patch) {
    view.pendingPositions.set(id, { ...view.pendingPositions.get(id), ...patch });
    if (view.writeTimer) clearTimeout(view.writeTimer);
    view.writeTimer = setTimeout(flushPositionWrites, WRITE_DEBOUNCE_MS);
  }

  async function flushPositionWrites() {
    view.writeTimer = null;
    if (!view.pendingPositions.size || !view.mapId) return;
    const updates = [...view.pendingPositions].map(([id, pos]) => ({ id, x: pos.x, y: pos.y }));
    const mapId = view.mapId;
    try {
      await App.put(`/api/mapper/maps/${mapId}/nodes`, { updates });
      // Only clear the entries this flush actually sent — a drag that
      // queued a NEWER position for the same node while this request was
      // in flight must not have that newer value thrown away underneath it.
      for (const { id, x, y } of updates) {
        const still = view.pendingPositions.get(id);
        if (still && still.x === x && still.y === y) view.pendingPositions.delete(id);
      }
    } catch (error) {
      // A failed write must say so and must not silently lose the layout:
      // the pending positions stay queued (the boxes are still drawn where
      // the operator left them, from view.pendingPositions/livePos) and a
      // retry is scheduled rather than the edit quietly vanishing on the
      // next reload.
      App.toast(`Could not save the layout: ${error.message}. Will retry.`, 'fail');
      if (view.writeRetryTimer) clearTimeout(view.writeRetryTimer);
      view.writeRetryTimer = setTimeout(flushPositionWrites, WRITE_RETRY_MS);
    }
  }

  function onSvgPointerDown(event) {
    if (!event.isPrimary) return;
    if (event.button === 1 || (event.button === 0 && view.spaceHeld)) {
      // Pan: middle button, or left button with space held.
      event.preventDefault();
      focusCanvas();
      event.currentTarget.setPointerCapture(event.pointerId);
      view.panDrag = { x: event.clientX, y: event.clientY, pan: { ...view.pan } };
      App.el('mp-svg').classList.add('dragging');
      return;
    }
    if (event.button !== 0) return;
    // A node's own pointerdown handler stops propagation before this ever
    // runs; a link path has no drag handler of its own, so it is excluded
    // here instead, or pressing down on one and moving a couple of pixels
    // before release would start a rubber-band from under a click.
    if (event.target.closest('.mp-node') || event.target.closest('.mp-link')) return;
    // Empty canvas: start a rubber-band multi-select.
    const p = scenePoint(event);
    if (!p) return;
    event.preventDefault();
    focusCanvas();
    event.currentTarget.setPointerCapture(event.pointerId);
    view.rubber = { x0: p.x, y0: p.y, x1: p.x, y1: p.y, additive: event.shiftKey };
  }

  function onSvgPointerMove(event) {
    if (!view.frame) return;
    if (view.panDrag) {
      const svg = App.el('mp-svg');
      const rect = svg.getBoundingClientRect();
      const scaleX = view.frame.width / Math.max(rect.width, 1), scaleY = view.frame.height / Math.max(rect.height, 1);
      const dx = (event.clientX - view.panDrag.x) * scaleX, dy = (event.clientY - view.panDrag.y) * scaleY;
      App.hideTooltip();
      view.pan = { x: view.panDrag.pan.x + dx, y: view.panDrag.pan.y + dy };
      applyTransform();
      return;
    }
    if (view.rubber) {
      const p = scenePoint(event);
      if (!p) return;
      view.rubber.x1 = p.x; view.rubber.y1 = p.y;
      drawRubber();
    }
  }

  function onSvgPointerUp() {
    if (view.panDrag) { view.panDrag = null; App.el('mp-svg').classList.remove('dragging'); return; }
    if (view.rubber) {
      const { x0, y0, x1, y1, additive } = view.rubber;
      const left = Math.min(x0, x1), right = Math.max(x0, x1), top = Math.min(y0, y1), bottom = Math.max(y0, y1);
      const hit = view.nodes.filter((n) => {
        const p = livePos(n);
        return p.x >= left && p.x <= right && p.y >= top && p.y <= bottom;
      }).map((n) => n.id);
      view.rubber = null;
      if (hit.length || !additive) {
        const next = additive ? new Set(view.selection) : new Set();
        for (const id of hit) next.add(id);
        setSelection(next);
      } else drawRubber();
    }
  }

  function onSvgWheel(event) {
    if (!view.frame) return;
    event.preventDefault();
    const factor = event.deltaY < 0 ? 1.15 : 1 / 1.15;
    const from = view.zoom, to = Math.min(Math.max(from * factor, 0.1), 5);
    const svg = App.el('mp-svg');
    const rect = svg.getBoundingClientRect();
    const px = (event.clientX - rect.left) * (view.frame.width / Math.max(rect.width, 1));
    const py = (event.clientY - rect.top) * (view.frame.height / Math.max(rect.height, 1));
    const before = translation(from);
    const sceneX = (px - before.tx) / from, sceneY = (py - before.ty) / from;
    const f = view.frame;
    view.pan.x = px - sceneX * to - (f.width / 2 - f.cx * to);
    view.pan.y = py - sceneY * to - (f.height / 2 - f.cy * to);
    view.zoom = to;
    applyTransform();
  }

  function zoomBy(factor) {
    view.zoom = Math.min(Math.max(view.zoom * factor, 0.1), 5);
    applyTransform();
  }

  function onCanvasKeyDown(event) {
    if (event.target !== App.el('mp-canvas')) return;   // a node/link handles its own Enter/Space
    const panStep = 40 / view.zoom;
    const pan = (dx, dy) => {
      view.pan.x += dx; view.pan.y += dy;
      event.preventDefault();
      applyTransform();
    };
    if (event.key === 'ArrowLeft') pan(panStep, 0);
    else if (event.key === 'ArrowRight') pan(-panStep, 0);
    else if (event.key === 'ArrowUp') pan(0, panStep);
    else if (event.key === 'ArrowDown') pan(0, -panStep);
    else if (event.key === '+' || event.key === '=') { event.preventDefault(); zoomBy(1.2); }
    else if (event.key === '-') { event.preventDefault(); zoomBy(1 / 1.2); }
  }

  // What Space activates when one of these has focus. A browser fires that
  // activation on the key UP — after a whole pan gesture has been drawn — so
  // panning with a toolbar button still focused pressed it again on release:
  // Fit threw away the pan just made, Remove re-opened its confirm dialog.
  // Space belongs to whatever has focus; it pans only when nothing that Space
  // would press does.
  const SPACE_ACTIVATES = 'button, summary, [role="button"], [contenteditable]';

  // Space held down pans on a left-button drag, the same modifier a paint
  // program uses — scoped to when MAPPER is the visible tab and no dialog,
  // no text field and nothing Space would press has the keyboard, so it never
  // eats a space typed into a search box on another page or inside this one's
  // own dialogs, nor a keyboard user's press of the button they focused.
  function wireSpaceModifier() {
    window.addEventListener('keydown', (event) => {
      if (event.code !== 'Space' || App.state.tab !== 'mapper') return;
      const target = event.target;
      const tag = (target && target.tagName) || '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (target && target.closest && target.closest(SPACE_ACTIVATES)) return;
      if (!App.el('modal').hidden) return;
      view.spaceHeld = true;
    });
    window.addEventListener('keyup', (event) => {
      if (event.code === 'Space') view.spaceHeld = false;
    });
  }

  /* --------------------------------------------------------- align tools */

  function alignDialog() {
    if (view.selection.size < 2) return;
    const canWrite = App.canWrite('mapper');
    const gate = canWrite ? '' : ' disabled';
    App.modal('Align / distribute', `
      <div class="row wrap">
        <button data-align="left" data-requires-write="mapper"${gate}>Align left</button>
        <button data-align="centerH" data-requires-write="mapper"${gate}>Align centre</button>
        <button data-align="right" data-requires-write="mapper"${gate}>Align right</button>
        <button data-align="top" data-requires-write="mapper"${gate}>Align top</button>
        <button data-align="middleV" data-requires-write="mapper"${gate}>Align middle</button>
        <button data-align="bottom" data-requires-write="mapper"${gate}>Align bottom</button>
        <button data-align="distH" data-requires-write="mapper"${(!canWrite || view.selection.size < 3) ? ' disabled' : ''}>Distribute horizontally</button>
        <button data-align="distV" data-requires-write="mapper"${(!canWrite || view.selection.size < 3) ? ' disabled' : ''}>Distribute vertically</button>
      </div>`, [{ label: 'Close', onClick: App.closeModal }])
      .querySelectorAll('[data-align]').forEach((btn) => {
        btn.onclick = () => { applyAlign(btn.dataset.align); };
      });
  }

  function applyAlign(kind) {
    const nodes = [...view.selection].map(nodeById).filter(Boolean);
    if (nodes.length < 2) return;
    const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
    const min = (a) => Math.min(...a), max = (a) => Math.max(...a), avg = (a) => a.reduce((s, v) => s + v, 0) / a.length;
    const updates = [];
    if (kind === 'left') { const v = min(xs); for (const n of nodes) updates.push([n, v, n.y]); }
    else if (kind === 'right') { const v = max(xs); for (const n of nodes) updates.push([n, v, n.y]); }
    else if (kind === 'centerH') { const v = avg(xs); for (const n of nodes) updates.push([n, v, n.y]); }
    else if (kind === 'top') { const v = min(ys); for (const n of nodes) updates.push([n, n.x, v]); }
    else if (kind === 'bottom') { const v = max(ys); for (const n of nodes) updates.push([n, n.x, v]); }
    else if (kind === 'middleV') { const v = avg(ys); for (const n of nodes) updates.push([n, n.x, v]); }
    else if (kind === 'distH' && nodes.length >= 3) {
      const sorted = [...nodes].sort((a, b) => a.x - b.x);
      const lo = sorted[0].x, hi = sorted[sorted.length - 1].x, step = (hi - lo) / (sorted.length - 1);
      sorted.forEach((n, i) => updates.push([n, lo + step * i, n.y]));
    } else if (kind === 'distV' && nodes.length >= 3) {
      const sorted = [...nodes].sort((a, b) => a.y - b.y);
      const lo = sorted[0].y, hi = sorted[sorted.length - 1].y, step = (hi - lo) / (sorted.length - 1);
      sorted.forEach((n, i) => updates.push([n, n.x, lo + step * i]));
    } else return;
    for (const [n, x, y] of updates) { n.x = x; n.y = y; queuePositionWrite(n.id, { x, y }); }
    if (view.writeTimer) clearTimeout(view.writeTimer);
    flushPositionWrites();
    requestDraw();
  }

  /* --------------------------------------------------------- toolbar state */

  function drawToolbarState() {
    const canWrite = App.canWrite('mapper');
    const hasMap = view.mapId !== null;
    // Compared before assigning, for the reason App.setText/setHidden exist:
    // fastTick runs this ten times a second and an unconditional write
    // queues a real mutation even when the value is already there. There is
    // no App.setDisabled to borrow.
    const states = [
      ['mp-remove-node', !canWrite || view.selection.size === 0],
      ['mp-align', !canWrite || view.selection.size < 2],
      ['mp-add-device', !canWrite || !hasMap],
      ['mp-add-neighbours', !canWrite || !hasMap],
      ['mp-snap', !canWrite || !hasMap],
    ];
    for (const [id, disabled] of states) {
      const button = App.el(id);
      if (button && button.disabled !== disabled) button.disabled = disabled;
    }
  }

  /* -------------------------------------------------------------- VLANs */

  const VLAN_COLUMNS = [
    // --canvas-vlan-*, not --vlan-* -- Finding 3: this swatch is what an operator
    // picks a VLAN's colour FROM, so it has to show the colour that is actually
    // stroked on #mp-canvas (drawLink uses --canvas-vlan-N), not the --panel-tuned
    // --vlan-N rotation that used to live here and could be a completely different
    // lightness (Dark's --vlan-1 is a pastel #DA6C6C; the strand it named was the
    // maroon #862727 --canvas-vlan-1). The swatch itself still sits on --panel, and
    // --canvas-vlan-* was never tuned against it -- worst case (Nord) is ~1.03:1,
    // functionally invisible -- so .mp-swatch's own border (app.css) carries the
    // shape at the --line/--panel floor (>=3.38:1 in every theme) regardless of
    // how the fill lands; see that rule's own comment.
    { key: 'swatch', label: '', width: 40, sortable: false,
      cell: (v) => `<button class="mp-swatch" data-vlan-swatch="${v.vlan}" data-requires-write="mapper"` +
        `${App.canWrite('mapper') ? '' : ' disabled'} ` +
        `style="background:var(--canvas-vlan-${(v.color_index || 0) + 1})" ` +
        `title="Change colour" aria-label="Change colour for VLAN ${v.vlan}"></button>` },
    { key: 'vlan', label: 'VLAN', width: 70, numeric: true },
    { key: 'name', label: 'Name', width: 160, value: (v) => (v.name || '').toLowerCase(),
      cell: (v) => escape(v.name || '—') },
    { key: 'link_count', label: 'Links', width: 70, numeric: true },
  ];

  let vlanSort = App.recallSort('mapper-vlan-table', { key: 'vlan', descending: false });

  function drawVlanTable() {
    const table = App.grid(App.el('mapper-vlan-table'), {
      name: 'mapper-vlan-table', caption: 'VLANs on this map', columns: VLAN_COLUMNS,
      sort: vlanSort, onSort: (key, descending) => { vlanSort = { key, descending }; drawVlanTable(); },
    });
    const body = document.createElement('tbody');
    const rows = App.sortRows(view.vlans, vlanSort.key, vlanSort.descending, VLAN_COLUMNS);
    App.drawRows(body, rows, VLAN_COLUMNS, (tr, row) => {
      tr.className = 'clickable' + (view.selectedVlan === row.vlan ? ' selected' : '');
      tr.onclick = (event) => {
        if (event.target.closest('[data-vlan-swatch]')) return;
        view.selectedVlan = view.selectedVlan === row.vlan ? null : row.vlan;
        requestDraw();
        drawVlanTable();
      };
    }, 'No VLAN data has been seen on this map yet.');
    table.appendChild(body);
    App.wireRowKeyboard(body);
    for (const btn of body.querySelectorAll('[data-vlan-swatch]')) {
      btn.onclick = (event) => { event.stopPropagation(); openVlanColorPicker(Number(btn.dataset.vlanSwatch)); };
    }
  }

  function openVlanColorPicker(vlan) {
    const current = view.vlans.find((v) => v.vlan === vlan);
    // --canvas-vlan-*, same reason as the table swatch above: this dialog is
    // choosing the colour a strand will actually be drawn in, so it has to show
    // that colour, not the --panel-tuned --vlan-N one.
    const canWrite = App.canWrite('mapper');
    const swatches = Array.from({ length: 16 }, (_, i) => {
      const selected = current && current.color_index === i;
      return `<button class="mp-swatch${selected ? ' selected' : ''}" data-color-index="${i}" ` +
        `data-requires-write="mapper"${canWrite ? '' : ' disabled'} ` +
        `style="background:var(--canvas-vlan-${i + 1})" aria-label="Colour ${i + 1}"></button>`;
    }).join('');
    const box = App.modal(`VLAN ${vlan} colour`,
      `<div class="mp-swatch-grid">${swatches}</div>` +
      '<p class="hint gap-t-sm">Automatic assigns a colour from the VLAN id and stays the ' +
      'same everywhere this VLAN is drawn.</p>', [
      { label: 'Automatic', onClick: async () => {
        await App.post('/api/mapper/vlan-color', { vlan, color_index: null });
        App.closeModal();
        await loadMapData();
      } },
      { label: 'Close', onClick: App.closeModal },
    ]);
    for (const btn of box.querySelectorAll('[data-color-index]')) {
      btn.onclick = async () => {
        await App.post('/api/mapper/vlan-color', { vlan, color_index: Number(btn.dataset.colorIndex) });
        App.closeModal();
        await loadMapData();
      };
    }
  }

  /* ----------------------------------------------------------- settings */

  function settingsDialog() {
    const s = view.settings;
    const box = App.modal('Mapper settings', `
      <fieldset><legend>LINKS</legend>
        <label>Collapse trunks at <input id="mps-threshold" type="number" min="1" max="30"
          value="${s.vlan_collapse_threshold}"> VLANs</label>
        <p class="hint">At or above this many VLANs, a trunk stops drawing one strand per VLAN
          and draws as a single line instead, its width scaling with how many it carries.</p>
        <label>Never draw more than <input id="mps-maxstrands" type="number" min="1" max="200"
          value="${s.max_strand_vlans}"> strands</label>
        <p class="hint">Two jobs, not one: a real ceiling on strands (checked independently of
          the threshold above, so a trunk collapses at this count even if the threshold would
          otherwise still draw it as strands), AND the VLAN count a collapsed trunk reaches its
          full Collapsed trunk width at — the line gets no wider carrying more VLANs than this.</p>
        <label>Strand width <input id="mps-widthmin" type="number" min="0.5" step="0.5"
          value="${s.link_width_min}"></label>
        <label>Collapsed trunk width, at the cap <input id="mps-widthmax" type="number" min="1" step="0.5"
          value="${s.link_width_max}"></label>
        <label class="check"><input type="checkbox" id="mps-portlabels" ${s.show_port_labels ? 'checked' : ''}>
          Show port labels</label>
        <p class="hint">A small label at each end of a link naming that end's own port.</p>
        <label class="check"><input type="checkbox" id="mps-vlanlabels" ${s.show_vlan_labels ? 'checked' : ''}>
          Show VLAN labels</label>
        <p class="hint">The VLAN id on each drawn strand, or the VLAN count on a collapsed trunk.
          Turn off on a busy map where the numbers themselves start to crowd the lines.</p>
        <label>A link is stale after <input id="mps-stale" type="number" min="0" step="1"
          value="${s.stale_link_hours}"> hours</label>
      </fieldset>
      <fieldset><legend>LAYOUT</legend>
        <label>Map style <select id="mps-style">
          ${MAP_STYLES.map((m) => `<option value="${m}" ${s.map_style === m ? 'selected' : ''}>` +
            `${m[0].toUpperCase()}${m.slice(1)}</option>`).join('')}
        </select></label>
        <label>Grid size <input id="mps-grid" type="number" min="4" value="${s.grid_size}"></label>
      </fieldset>
      <fieldset><legend>BADGES</legend>
        <label class="check"><input type="checkbox" id="mps-temp" ${s.badge_temp ? 'checked' : ''}>
          Chassis temperature</label>
        <label class="check"><input type="checkbox" id="mps-cpu" ${s.badge_cpu ? 'checked' : ''}>
          CPU</label>
        <label class="check"><input type="checkbox" id="mps-ports" ${s.badge_ports ? 'checked' : ''}>
          Port count</label>
      </fieldset>
      <fieldset><legend>REFRESH</legend>
        <label>Refresh every <input id="mps-refresh" type="number" min="0" value="${s.refresh_interval_s}"> s</label>
        <p class="hint">0 turns off automatic refresh; the Refresh button always works.</p>
      </fieldset>
      <p id="mps-apply-status" class="hint" aria-live="polite"></p>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: async (b, button) => {
        const status = b.querySelector('#mps-apply-status');
        status.textContent = 'Applying…';
        const n = (id) => Number(b.querySelector(id).value);
        try {
          await App.post('/api/settings', { scope: 'mapper', values: {
            vlan_collapse_threshold: n('#mps-threshold'), max_strand_vlans: n('#mps-maxstrands'),
            link_width_min: n('#mps-widthmin'), link_width_max: n('#mps-widthmax'),
            show_port_labels: b.querySelector('#mps-portlabels').checked,
            show_vlan_labels: b.querySelector('#mps-vlanlabels').checked,
            stale_link_hours: n('#mps-stale'), map_style: b.querySelector('#mps-style').value,
            grid_size: n('#mps-grid'), badge_temp: b.querySelector('#mps-temp').checked,
            badge_cpu: b.querySelector('#mps-cpu').checked, badge_ports: b.querySelector('#mps-ports').checked,
            refresh_interval_s: n('#mps-refresh'),
          } });
          status.textContent = 'Applied';
          await loadMapsList();
          await loadMapData();
          App.closeModal();
        } catch (error) {
          status.textContent = `Could not apply: ${error.message}`;
          throw error;
        }
      } },
    ]);
    return box;
  }

  /* ------------------------------------------------------------- export */

  // A detached copy of the live SVG has no access to the page's CSS custom
  // properties (var(--token) resolves against the DOCUMENT it is attached
  // to; a canvas-drawn <img> built from a serialised copy is not attached
  // to anything) — every computed colour has to be inlined into the COPY
  // before it is serialised, or the PNG comes back all black/transparent
  // strokes. getComputedStyle on the LIVE element (still in the real
  // document, so its var()s resolve) is read once per element and written
  // back onto the clone as literal colours.
  function inlineComputedColors(liveRoot, cloneRoot) {
    const liveEls = liveRoot.querySelectorAll('*');
    const cloneEls = cloneRoot.querySelectorAll('*');
    const props = ['fill', 'stroke', 'color', 'stop-color'];
    // Only the CLONE is touched — the live, on-screen canvas must come out
    // of an export exactly as it went in, background included.
    cloneRoot.style.background = getComputedStyle(App.el('mp-canvas')).backgroundColor;
    for (let i = 0; i < liveEls.length; i += 1) {
      const computed = getComputedStyle(liveEls[i]);
      for (const prop of props) {
        const value = computed.getPropertyValue(prop);
        // Skip a paint-server url(...) (the grid's fill): the browser
        // reports it absolutised against this page, which resolves to
        // nothing in a detached clone. The clone's own "#id" form already
        // works since the pattern is in the serialised tree.
        if (!value || value.startsWith('url(')) continue;
        cloneEls[i].style.setProperty(prop, value);
      }
    }
  }

  function exportPng() {
    const svg = App.el('mp-svg');
    const clone = svg.cloneNode(true);
    inlineComputedColors(svg, clone);
    const box = svg.getBoundingClientRect();
    const width = Math.max(box.width, 200), height = Math.max(box.height, 200);
    clone.setAttribute('width', width);
    clone.setAttribute('height', height);
    const xml = new XMLSerializer().serializeToString(clone);
    const svgBlob = new Blob([xml], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = width; canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);
      URL.revokeObjectURL(url);
      canvas.toBlob((blob) => {
        if (!blob) { App.toast('Could not render the map to PNG.', 'fail'); return; }
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${(view.map && view.map.name) || 'map'}.png`;
        link.click();
        URL.revokeObjectURL(link.href);
        App.toast('Map exported to PNG', 'ok');
      }, 'image/png');
    };
    img.onerror = () => { URL.revokeObjectURL(url); App.toast('Could not render the map to PNG.', 'fail'); };
    img.src = url;
  }

  function exportCsvClick() {
    if (!view.mapId) return;
    App.exportCsv(`/api/mapper/maps/${view.mapId}/export.csv`, {});
  }

  /* --------------------------------------------------------------- init */

  async function refresh() {
    if (App.state.tab !== 'mapper') return;
    if (gestureActive()) return;
    if (!view.maps.length) await loadMapsList();
    if (view.mapId === null) {
      // First time this browser has opened MAPPER (or nothing remembered
      // is still a valid map): fall back to the recalled map, else the
      // first one — the same "pick something sensible" default every
      // late-filled select in the product uses. Done here, in refresh(),
      // rather than in activate(): for a PLAIN tab click, app.js's
      // activateTab calls activate() before refreshNow() ever runs (this
      // module's maps list would still be empty), whereas for a real
      // #/mapper/<id> route deliverRoute calls refreshNow() FIRST and
      // activate(opts) only once that has landed — so refresh() is the
      // one path guaranteed to run before any data is needed either way,
      // and activate() (below) only ever has to act on an id a route
      // actually named.
      const routed = routedMapId();
      const recalled = recallMapId();
      const known = (id) => id !== null && view.maps.some((m) => m.id === id);
      const initial = known(routed) ? routed
        : (known(recalled) ? recalled : (view.maps.length ? view.maps[0].id : null));
      if (initial !== null) {
        // Stamped before the await: a poll tick during this load would
        // otherwise see no stamp, decide a refresh is due, and double-load.
        view.lastAutoTs = Date.now();
        await selectMap(initial, { noRoute: true });
        return;
      }
    }
    // No key exists for 'mapper' in app.js's rateFor() map (it has no
    // global <module>_refresh_s setting the way every other tab does —
    // MAPPER's own refresh_interval_s lives in mapperdb's own settings
    // scope instead), so master() calls this at whatever the missing-key
    // fallback gives it (2s). Self-gated here against the module's own
    // setting instead of trusting that cadence: 0 means manual-only, and
    // anything else is honoured against a wall clock this function keeps,
    // not against how often master() happens to call it.
    const intervalS = Number(view.settings.refresh_interval_s);
    const now = Date.now();
    if (!(intervalS > 0)) return;
    if (now - (view.lastAutoTs || 0) < intervalS * 1000) return;
    view.lastAutoTs = now;
    if (view.mapId !== null) await loadMapData();
  }

  function forceRefresh() {
    view.lastAutoTs = Date.now();
    return (async () => {
      await loadMapsList();
      await loadMapData();
    })();
  }

  function fastTick() {
    if (App.state.tab === 'mapper') drawToolbarState();
  }

  function init() {
    const svg = App.el('mp-svg');
    const canvas = App.el('mp-canvas');
    svg.addEventListener('pointerdown', onSvgPointerDown);
    svg.addEventListener('pointermove', onSvgPointerMove);
    svg.addEventListener('pointerup', onSvgPointerUp);
    svg.addEventListener('pointercancel', onSvgPointerUp);
    svg.addEventListener('wheel', onSvgWheel, { passive: false });
    canvas.addEventListener('keydown', onCanvasKeyDown);
    canvas.oncontextmenu = (event) => event.preventDefault();   // the middle/space pan owns the gesture
    wireSpaceModifier();

    App.el('mp-refresh').onclick = () => App.runJob(App.el('mp-refresh'),
      { queued: 'Refreshing…', done: 'Refreshed' }, forceRefresh());
    App.el('mp-maps').onclick = mapsDialog;
    App.el('mp-upstream-suggestions').onclick = () => upstreamSuggestionsDialog().catch((error) =>
      App.toast(`Could not open upstream suggestions: ${error.message}`, 'fail'));
    App.el('mp-settings').onclick = settingsDialog;
    App.el('mp-map').onchange = (event) => selectMap(Number(event.target.value));
    App.el('mp-add-device').onclick = openAddDevice;
    App.el('mp-add-neighbours').onclick = openAddNeighbours;
    App.el('mp-remove-node').onclick = removeSelected;
    App.el('mp-align').onclick = alignDialog;
    // Recomputes the frame from what's on screen, then moves the scene —
    // nothing about the drawing itself changes.
    App.el('mp-fit').onclick = () => {
      const box = App.el('mp-svg').getBoundingClientRect();
      fitView(contentBounds(), Math.max(box.width, 200), Math.max(box.height, 200));
      applyTransform();
    };
    App.el('mp-zoom-in').onclick = () => zoomBy(1.25);
    App.el('mp-zoom-out').onclick = () => zoomBy(1 / 1.25);
    App.el('mp-export-png').onclick = exportPng;
    App.el('mp-export-csv').onclick = exportCsvClick;
    App.el('mp-snap').onchange = async (event) => {
      await App.post('/api/settings', { scope: 'mapper', values: { snap_to_grid: event.target.checked } });
      view.settings.snap_to_grid = event.target.checked;
      requestDraw();
    };

    // A release the page never sees (Alt-Tab mid-pan) would otherwise leave
    // a gesture flag set and refresh skipped for good.
    window.addEventListener('blur', () => {
      if (!gestureActive() && !view.spaceHeld) return;
      view.nodeDrag = null; view.panDrag = null; view.rubber = null; view.spaceHeld = false;
      const svg = App.el('mp-svg');
      if (svg) svg.classList.remove('dragging');
      drawRubber();
      requestDraw();
    });
    for (const eventName of ['resize', 'panes-resized']) {
      window.addEventListener(eventName, () => {
        if (App.state.tab === 'mapper' && !gestureActive()) requestDraw();
      });
    }
  }

  /* #/mapper/<mapId>: deliverRoute (app.js) awaits refreshNow('mapper')
     BEFORE calling this, so view.maps is already loaded and view.mapId
     already holds a sensible default by the time this runs — this only
     ever has to act on an id the ROUTE itself named. A plain tab click
     carries no opts at all (activateTab calls activate() before
     refreshNow(), the opposite order), so this is a deliberate no-op in
     that case: refresh() already did the only work there is to do. */
  function activate(opts) {
    const routed = opts && opts.parts && opts.parts[0] !== undefined ? Number(opts.parts[0]) : null;
    if (!Number.isFinite(routed)) return;
    if (routed === view.mapId && view.map) { drawLegend(); return; }
    if (!view.maps.find((m) => m.id === routed)) return;   // an id nothing on this account can see
    selectMap(routed).then(drawLegend, (error) => {
      App.toast(`Could not open that map: ${error.message}`, 'fail');
    });
  }

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

  App.pages.mapper = {
    // The legend only changes with the map's data, so loadMapData()/
    // activate() draw it, not fastTick (which ran every beat before).
    init, refresh, activate, fastTick,
  };
})();

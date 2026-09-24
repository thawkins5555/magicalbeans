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
  const NODE_W = 176, NODE_H = 54;
  const ICON = 16;   // the role glyph's own viewBox is 16x16
  // Matches mapper.py's STRAND_LABEL_GAP_PX — the minimum on-screen gap a
  // staggered VLAN label needs from its neighbour before it's worth
  // staggering at all.
  const STRAND_LABEL_MIN_GAP_PX = 22;
  // A port label's margin past the node box, on top of boxExit()'s own
  // geometry; the old fixed 65px corner allowance left a short vertical
  // link no room for the stagger below.
  const PORT_LABEL_INSET = 18;
  // The fan separates parallel cables by less than a port name is wide, so
  // each steps its labels this much further along its own line.
  const PORT_LABEL_STEP = 16;
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
  // A frame's minimum drawn size in scene units, both ways: a drag that
  // draws one smaller is ignored, and a resize never shrinks one further —
  // matches post_mapper_map_frames' own server-side floor.
  const FRAME_MIN = 40;
  const FRAME_HANDLE = 10;   // the resize-handle square, in scene units
  const FIND_SUGGEST_CAP = 12;  // rows the #mp-find-list dropdown ever shows at once

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
    frames: [],           // map_frames rows, x/y/width/height possibly overridden by an in-flight drag/resize
    notes: [],            // map_notes rows, same shape of override as frames
    // Rebuilt with the payload in loadMapData; replaces an Array.find()
    // per lookup that made a 60-node/200-link map quadratic.
    nodeMap: new Map(),        // map_nodes id -> row
    linkMap: new Map(),        // link id -> link
    vlanNameById: new Map(),   // vlan id -> its name on this map ('' when unnamed)
    linksByNode: new Map(),    // map_nodes id -> the links touching it
    frameMap: new Map(),       // frame id -> row
    noteMap: new Map(),        // note id -> row
    notesByNode: new Map(),    // map_nodes id -> notes anchored to it (their tail follows a drag)

    // The drawn SVG, kept so pan/zoom/drag can move it instead of
    // rebuilding (applyTransform, redrawDragged, drawRubber).
    sceneGroup: null,
    rubberEl: null,
    nodeEls: new Map(),        // map_nodes id -> its <g>
    linkEls: new Map(),        // link id -> the <g> holding that link's own elements
    linkLabelEls: new Map(),   // link id -> its port/VLAN labels, drawn above every link
    frameEls: new Map(),       // frame id -> its <g>
    noteEls: new Map(),        // note id -> its <g>
    dragPans: false,           // the Drag pans checkbox: left-drag on empty canvas pans
    fiberView: false,          // the FiberView checkbox: glow every link.fiber link
    linkFan: new Map(),        // link id -> px offset, draw()'s fanOffsets() (parallel cables)
    linkFanIndex: new Map(),   // link id -> its place in that fan, for drawPortLabels' stagger
    settings: {},        // mapperdb.DEFAULTS shape, refreshed with every maps/settings fetch
    candidates: { devices: [], neighbours: [] },

    selection: new Set(),    // selected node ids
    selectedLinkId: null,
    selectedFrameId: null,
    selectedNoteId: null,
    selectedVlan: null,      // vlan id highlighted from the VLAN table
    detailShowAllVlans: false,   // the open link's VLAN list, past VLAN_DETAIL_CAP

    // needsFit: a map is fitted once, when opened or when Fit is pressed,
    // never again under an operator who has since arranged it.
    zoom: 1, needsFit: true, pan: { x: 0, y: 0 }, frame: null,
    panDrag: null, spaceHeld: false,
    nodeDrag: null,          // {ids, from:Map(id->{x,y}), dx, dy, moved}
    rubber: null,            // {x0,y0,x1,y1, additive} or {..., drawFrame:true}/{..., drawNote:true} while arming one
    framing: false,          // Frame button armed: the next empty-canvas drag draws one
    frameDrag: null,         // {id, mode:'move'|'resize', startRect, dx, dy, moved}
    noting: false,           // Note button armed: the next empty-canvas drag draws one
    notingAnchorId: null,    // the one node selected when Note was armed, or null
    noteDrag: null,          // {id, mode:'move'|'resize', startRect, dx, dy, moved}

    pendingPositions: new Map(),   // node id -> {x,y}, awaiting the debounced PUT
    writeTimer: null,
    writeRetryTimer: null,
    pendingFramePatches: new Map(),   // frame id -> merged {x,y,width,height,label,color} patch
    frameWriteTimers: new Map(),      // frame id -> debounce timeout handle
    frameWriteRetryTimers: new Map(), // frame id -> retry timeout handle
    pendingNotePatches: new Map(),    // note id -> merged {x,y,width,height,text,color} patch
    noteWriteTimers: new Map(),       // note id -> debounce timeout handle
    noteWriteRetryTimers: new Map(),  // note id -> retry timeout handle

    // findNode's own "same text, next hit" cycling state.
    findQuery: '', findIndex: -1,

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
  function linkNodeA(link) {
    // Every discovered link's A end is the reporting device, so
    // a_device_id is always set -- but a manual line (D2) can join two
    // unmanaged peers or one of each, so it needs the same peer_key
    // fallback linkNodeB already has.
    if (link.a_device_id !== null && link.a_device_id !== undefined) {
      return view.nodeByDevice.get(link.a_device_id) || null;
    }
    return view.nodeByPeer.get(link.a_peer_key) || null;
  }
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
    return !!(view.nodeDrag || view.rubber || view.panDrag || view.frameDrag || view.noteDrag);
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
  const NAME_SOURCES = {
    manual: 'manual name', sysName: 'SNMP sysName', dns: 'reverse DNS', ip: 'address only',
  };

  function resolveNode(node) {
    // Defensive only: drawLink already skips a link whose endpoint cannot
    // be found on this map, so a null here would mean map data changed
    // out from under an already-open detail pane rather than a real state.
    if (!node) {
      return { node: null, name: '(removed)', sub: '', tone: 'none', unmanaged: false,
        gone: true, role: '', badges: {}, placeholder: false,
        tooltip: 'This node is no longer on the map.' };
    }
    const name = node.name;
    const badges = { temp_c: node.temp_c, cpu_pct: node.cpu_pct, port_count: node.port_count };
    if (node.missing) {
      return {
        node, name, sub: 'removed from Nodes', tone: 'none', unmanaged: false,
        gone: true, role: node.role || '', badges, placeholder: false,
        tooltip: `${name}\nThis device has been removed from Nodes; its position is kept ` +
          'in case it comes back, but nothing here is live any more.',
      };
    }
    if (node.placeholder) {
      return {
        node, name, sub: 'placeholder', tone: 'none', unmanaged: false,
        gone: false, placeholder: true, role: node.role || '', badges,
        tooltip: `${name}\nPlaceholder — not a device, drawn for the diagram only.`,
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
        unmanaged: true, gone: false, role: node.role || 'unmanaged', badges, placeholder: false,
        tooltip: `${name}\nUnmanaged peer — seen over LLDP/CDP, not polled directly.` +
          (node.ip ? `\nAddress   ${node.ip}` : '') + (via ? `\nSeen via  ${via}` : ''),
      };
    }
    const tone = DEVICE_STATUS_TONE[node.status] || 'none';
    const statusWord = DEVICE_STATUS_LABEL[node.status] || node.status || 'Unknown';
    return {
      node, name, sub: (node.name_source === 'ip' || node.ip === name) ? '' : (node.ip || ''),
      tone, unmanaged: false, gone: false, placeholder: false,
      role: node.role || '', badges,
      tooltip: `${name}\n${node.ip || ''}\nStatus    ${statusWord}` +
        (node.name_source ? `\nName      ${NAME_SOURCES[node.name_source] || node.name_source}` : ''),
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
      // The reset below changes what draw() would paint even when the payload
      // is identical, so the skip must not apply to this load.
      lastMapPayloadJson = null;
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
    view.frameMap = new Map(view.frames.map((f) => [f.id, f]));
    view.noteMap = new Map(view.notes.map((n) => [n.id, n]));
    view.linksByNode = new Map();
    for (const link of view.links) {
      const a = linkNodeA(link), b = linkNodeB(link);
      for (const node of (a && b && a.id === b.id) ? [a] : [a, b]) {
        if (!node) continue;
        const list = view.linksByNode.get(node.id);
        if (list) list.push(link); else view.linksByNode.set(node.id, [link]);
      }
    }
    view.notesByNode = new Map();
    for (const note of view.notes) {
      if (note.node_id === null || note.node_id === undefined) continue;
      const list = view.notesByNode.get(note.node_id);
      if (list) list.push(note); else view.notesByNode.set(note.node_id, [note]);
    }
  }

  // Fingerprint of the last drawn payload's body: a poll that comes back
  // byte-for-byte the same has nothing to redraw, so draw()/drawDetail()/
  // drawVlanTable()/drawLegend() are skipped and the in-flight drag (if any)
  // that draw() would otherwise cancel survives the poll.
  let lastMapPayloadJson = null;

  async function loadMapData() {
    const generation = ++view.loadGen;
    if (view.mapId === null) {
      lastMapPayloadJson = null;
      view.map = null; view.nodes = []; view.links = []; view.peersByKey = new Map(); view.vlans = [];
      view.frames = []; view.notes = [];
      rebuildLookups();
      rebuildFindList();
      drawStatus(); draw(); drawDetail(); drawVlanTable(); drawLegend();
      return;
    }
    const payload = await App.get(`/api/mapper/maps/${view.mapId}`);
    if (view.loadGen !== generation) return;   // a newer selectMap/refresh already superseded this
    const payloadJson = JSON.stringify(payload);
    const unchanged = payloadJson === lastMapPayloadJson;
    lastMapPayloadJson = payloadJson;
    view.map = payload.map;
    view.nodes = payload.nodes || [];
    view.links = payload.links || [];
    view.peersByKey = new Map((payload.peers || []).map((p) => [p.peer_key, p]));
    view.vlans = payload.vlans || [];
    view.frames = payload.frames || [];
    view.notes = payload.notes || [];
    rebuildLookups();
    rebuildFindList();
    // A reload landing mid-drag (a settings save) ends the drag: the payload
    // replaces the ids and positions it holds.
    if (view.nodeDrag) view.nodeDrag = null;
    if (view.frameDrag) view.frameDrag = null;
    if (view.noteDrag) view.noteDrag = null;
    if (payload.settings) view.settings = payload.settings;
    // A selection or a highlighted link/frame/note that no longer exists on
    // the fresh payload (removed elsewhere) is dropped rather than left
    // pointing at nothing — drawDetail below reads view.selection/
    // selectedLinkId/selectedFrameId/selectedNoteId as ground truth for
    // what to show.
    for (const id of [...view.selection]) if (!nodeById(id)) view.selection.delete(id);
    if (view.selectedLinkId && !linkById(view.selectedLinkId)) view.selectedLinkId = null;
    if (view.selectedFrameId && !view.frameMap.has(view.selectedFrameId)) view.selectedFrameId = null;
    if (view.selectedNoteId && !view.noteMap.has(view.selectedNoteId)) view.selectedNoteId = null;
    App.el('mp-map-name').textContent = view.map ? view.map.name : '';
    App.el('mp-snap').checked = !!view.settings.snap_to_grid;
    drawStatus();
    if (unchanged) return;
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

  // ---- find: #mp-find-list suggestion dropdown, matched via findMatches below
  let findOpen = false;
  let findItems = [];   // nodes currently listed in the dropdown, ranked
  let findActive = -1;  // index into findItems, -1 = none highlighted

  // Case-insensitive, over label/name/resolved_name/ip: a node ranks by its
  // BEST field (an exact match on any field beats a prefix match on every
  // field, a prefix beats a plain substring), and view.nodes' own order
  // breaks ties, so results are stable call to call.
  function findMatches(text) {
    const q = String(text || '').trim().toLowerCase();
    if (!q) return [];
    const ranked = [];
    for (const node of view.nodes) {
      let rank = 4;
      for (const value of [node.label, node.name, node.resolved_name, node.ip]) {
        if (!value) continue;
        const field = String(value).toLowerCase();
        const r = field === q ? 0 : field.startsWith(q) ? 1 : field.includes(q) ? 2 : 4;
        if (r < rank) rank = r;
      }
      if (rank < 4) ranked.push({ node, rank });
    }
    ranked.sort((a, b) => a.rank - b.rank);
    return ranked.map((r) => r.node);
  }

  // Re-runs the current query against fresh view.nodes on a poll/refresh; no-op if closed.
  function rebuildFindList() {
    if (!findOpen) return;
    const input = App.el('mp-find');
    showFindSuggestions(input ? input.value : '');
  }

  function positionFindList(input, list) {
    const rect = input.getBoundingClientRect();
    list.style.left = `${rect.left}px`;
    list.style.top = `${rect.bottom + 2}px`;
    list.style.width = `${Math.max(rect.width, 220)}px`;
  }

  function renderFindList() {
    const list = App.el('mp-find-list');
    const input = App.el('mp-find');
    if (!list || !input) return;
    list.innerHTML = findItems.map((node, i) => {
      const ip = node.ip ? `<span class="mp-suggest-ip">${escape(node.ip)}</span>` : '';
      return `<div class="mp-suggest-item${i === findActive ? ' active' : ''}" role="option" ` +
        `id="mp-find-opt-${i}" aria-selected="${i === findActive}" data-index="${i}">` +
        `<span class="mp-suggest-name">${escape(node.name || node.ip || '')}</span>${ip}</div>`;
    }).join('');
    positionFindList(input, list);
    list.hidden = false;
    const active = list.querySelector('.mp-suggest-item.active');
    if (active) input.setAttribute('aria-activedescendant', active.id);
    else input.removeAttribute('aria-activedescendant');
  }

  function showFindSuggestions(text) {
    const q = String(text || '').trim();
    findItems = q ? findMatches(q).slice(0, FIND_SUGGEST_CAP) : [];
    findActive = findItems.length ? 0 : -1;
    if (!findItems.length) { hideFindSuggestions(); return; }
    findOpen = true;
    renderFindList();
  }

  function hideFindSuggestions() {
    const list = App.el('mp-find-list');
    if (list) { list.hidden = true; list.innerHTML = ''; }
    const input = App.el('mp-find');
    if (input) input.removeAttribute('aria-activedescendant');
    findOpen = false;
    findItems = [];
    findActive = -1;
  }

  // Shared by Enter and a dropdown click: fills the box, then calls findNode.
  function pickFindSuggestion(index) {
    const node = findItems[index];
    if (!node) return;
    const text = node.name || node.ip || '';
    const input = App.el('mp-find');
    if (input) input.value = text;
    hideFindSuggestions();
    findNode(text);
  }

  // The pan/zoom half of a Find: put the node dead centre at no less than
  // 1x zoom (a Find should never leave the operator squinting at a map
  // that was zoomed out), select it and hand the canvas keyboard focus.
  function centerOn(node) {
    if (!view.frame) return;   // no scene painted yet to point at
    const pos = livePos(node);
    view.frame.cx = pos.x;
    view.frame.cy = pos.y;
    view.pan = { x: 0, y: 0 };
    view.zoom = Math.max(view.zoom, 1);
    applyTransform();
    setSelection(new Set([node.id]));
    focusCanvas();
  }

  // Enter on #mp-find: the first hit, or — typing the SAME text again — the
  // next one, so repeated Enter cycles a name that matches several nodes.
  function findNode(text) {
    const q = String(text || '').trim();
    if (!q) return;
    const hits = findMatches(q);
    if (!hits.length) {
      App.toast(`No device on this map matches "${q}".`, 'fail');
      view.findQuery = ''; view.findIndex = -1;
      return;
    }
    view.findIndex = (view.findQuery.toLowerCase() === q.toLowerCase() && view.findIndex >= 0)
      ? (view.findIndex + 1) % hits.length : 0;
    view.findQuery = q;
    centerOn(hits[view.findIndex]);
  }

  function onFindKeydown(event) {
    if (findOpen && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
      event.preventDefault();
      if (!findItems.length) return;
      const delta = event.key === 'ArrowDown' ? 1 : -1;
      findActive = (findActive + delta + findItems.length) % findItems.length;
      renderFindList();
      return;
    }
    if (event.key === 'Escape') {
      if (!findOpen) return;
      event.preventDefault();
      hideFindSuggestions();
      return;
    }
    if (event.key !== 'Enter') return;
    event.preventDefault();
    if (findOpen && findActive >= 0) { pickFindSuggestion(findActive); return; }
    hideFindSuggestions();
    findNode(event.currentTarget.value);
  }

  function onFindInput(event) {
    showFindSuggestions(event.target.value);
  }

  // Prevents pointerdown from blurring #mp-find before the click fires.
  function onFindListPointerdown(event) {
    event.preventDefault();
  }

  function onFindListClick(event) {
    const item = event.target.closest('.mp-suggest-item');
    if (!item) return;
    pickFindSuggestion(Number(item.dataset.index));
  }

  // Only fires for a genuine move away from #mp-find (see onFindListPointerdown).
  function onFindBlur() {
    hideFindSuggestions();
  }

  function onFindOutsideClick(event) {
    if (!findOpen) return;
    const input = App.el('mp-find');
    const list = App.el('mp-find-list');
    if (event.target === input || (list && list.contains(event.target))) return;
    hideFindSuggestions();
  }

  // Reassigned (not mutated in place) at the top of each openAddDevice()
  // call, so the DEVICE_PICK_COLUMNS cell below — a module-level constant,
  // reused across every open of the dialog — always renders the CURRENT
  // dialog's own picks rather than a stale one left over from the last.
  let devicePicked = new Set();
  const DEVICE_PICK_COLUMNS = [
    { key: 'check', label: '', width: 34, sortable: false,
      cell: (r) => `<input type="checkbox" class="mp-pick" data-id="${r.id}"` +
        `${devicePicked.has(r.id) ? ' checked' : ''}>` },
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
    devicePicked = new Set();
    const box = App.modal('Add device', `
      <input id="mpad-q" placeholder="Search by name, IP or vendor…" style="width:100%;margin-bottom:var(--space-sm)">
      <div class="table-wrap tall"><table id="mpad-table"></table></div>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        const ids = [...devicePicked];
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
      // Recomputed from THIS redraw's filtered rows, not the full candidate
      // list — a header tick above a search that narrowed the table must
      // only ever mean "every row shown", never "every row that exists".
      const table = App.grid(box.querySelector('#mpad-table'), {
        name: 'mapper-add-device', caption: 'Devices not yet on this map',
        columns: DEVICE_PICK_COLUMNS, sort, onSort: (key, descending) => { sort = { key, descending }; draw2(); },
        selectAll: {
          key: 'check',
          checked: rows.length > 0 && rows.every((r) => devicePicked.has(r.id)),
          some: rows.some((r) => devicePicked.has(r.id)),
          label: 'Select all listed devices',
          onToggle: (on) => {
            for (const r of rows) { if (on) devicePicked.add(r.id); else devicePicked.delete(r.id); }
            draw2();
          },
        },
      });
      const body = document.createElement('tbody');
      App.drawRows(body, App.sortRows(rows, sort.key, sort.descending, DEVICE_PICK_COLUMNS),
        DEVICE_PICK_COLUMNS, null, 'Every device is already on this map, or none matched the search.');
      // Delegated on the tbody rather than per-checkbox: draw2/App.drawRows
      // rebuild every row (and so every checkbox) on each redraw, the same
      // reason redrawNeighbourRows' own listener below is wired this way.
      body.addEventListener('change', (event) => {
        const box2 = event.target.closest('.mp-pick');
        if (!box2) return;
        const id = Number(box2.dataset.id);
        if (box2.checked) devicePicked.add(id); else devicePicked.delete(id);
        draw2();
      });
      table.appendChild(body);
    };
    box.querySelector('#mpad-q').oninput = draw2;
    draw2();
  }

  // A placeholder is not a device: no candidate list, just a name. The
  // server rejects a blank label (400), so a blank/whitespace-only entry
  // is caught here too rather than round-tripping to find that out.
  function openAddPlaceholder() {
    const box = App.modal('Add placeholder', `
      <input id="mpph-name" maxlength="200" style="width:100%"
        placeholder="Name, e.g. Internet, Carrier MPLS, Site B">`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        const label = b.querySelector('#mpph-name').value.trim();
        if (!label) { App.closeModal(); return; }
        const pos = nextPlacement(0, contentBounds());
        await App.post(`/api/mapper/maps/${view.mapId}/nodes`,
          { placeholder: true, label, x: pos.x, y: pos.y });
        App.closeModal();
        await loadMapData();
      } },
    ]);
    if (box) { const input = box.querySelector('#mpph-name'); if (input) input.focus(); }
  }

  // netpath/web/api.py's get_mapper_map_candidates: each row is
  // {kind:'device', device_id, name, seen_from_device_id, seen_from_port}
  // or {kind:'peer', peer_key, name, platform, address, seen_from_device_id,
  // seen_from_port} — no protocol field travels with a candidate (only an
  // already-placed LINK's own `protocols` does), so there is no "Via"
  // column to draw here.
  // Same reassign-not-mutate reason as devicePicked above.
  let neighbourPicked = new Set();
  const NEIGHBOUR_PICK_COLUMNS = [
    { key: 'check', label: '', width: 34, sortable: false,
      cell: (r) => `<input type="checkbox" class="mp-pick" data-key="${escape(r.key)}"` +
        `${neighbourPicked.has(r.key) ? ' checked' : ''}>` },
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
    neighbourPicked = new Set();
    const box = App.modal('Add neighbours', `
      <p class="hint">Neighbours seen by a device already on this map, one hop out. ` +
      'Nothing is added automatically — pick which ones belong here.</p>' +
      '<div class="table-wrap tall"><table id="mpan-table"></table></div>', [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Add', primary: true, onClick: async (b) => {
        const keys = [...neighbourPicked];
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
    // Nothing here is filtered by a search box, so "rows" IS the currently
    // listed set — unlike Add device's draw2, there is no narrower subset
    // the select-all header would need to distinguish from the full list.
    function redrawNeighbourRows() {
      const table = App.grid(box.querySelector('#mpan-table'), {
        name: 'mapper-add-neighbours', caption: 'Neighbours not yet on this map',
        columns: NEIGHBOUR_PICK_COLUMNS, sort, onSort: (key, descending) => {
          sort = { key, descending }; redrawNeighbourRows(); },
        selectAll: {
          key: 'check',
          checked: rows.length > 0 && rows.every((r) => neighbourPicked.has(r.key)),
          some: rows.some((r) => neighbourPicked.has(r.key)),
          label: 'Select all listed devices',
          onToggle: (on) => {
            for (const r of rows) { if (on) neighbourPicked.add(r.key); else neighbourPicked.delete(r.key); }
            redrawNeighbourRows();
          },
        },
      });
      const body = document.createElement('tbody');
      App.drawRows(body, App.sortRows(rows, sort.key, sort.descending, NEIGHBOUR_PICK_COLUMNS),
        NEIGHBOUR_PICK_COLUMNS, null,
        'No neighbours to add — every one already on this map, or nothing placed here has reported any.');
      body.addEventListener('change', (event) => {
        const cb = event.target.closest('.mp-pick');
        if (!cb) return;
        const key = cb.dataset.key;
        if (cb.checked) neighbourPicked.add(key); else neighbourPicked.delete(key);
        redrawNeighbourRows();
      });
      table.appendChild(body);
    }
    redrawNeighbourRows();
  }

  function removeSelected() {
    // Whatever is selected: a frame and a note never join view.selection,
    // which holds device ids alone, so the button sat disabled for both.
    if (view.selectedFrameId) { removeFrame(view.selectedFrameId); return; }
    if (view.selectedNoteId) { removeNote(view.selectedNoteId); return; }
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

  // Same confirm idiom as removeSelected above — a frame's own Remove
  // button in the detail pane and Delete/Backspace on the canvas (with a
  // frame selected) both call this one function.
  function removeFrame(id) {
    if (!App.canWrite('mapper')) return;
    const frame = view.frameMap.get(id);
    if (!frame) return;
    App.confirmDestructive('Remove frame',
      `<p>Remove the frame${frame.label ? ` <b>${escape(frame.label)}</b>` : ''}? ` +
      'Nothing it encloses is moved or affected — only the frame itself is removed.</p>',
      'Remove',
      () => App.del(`/api/mapper/maps/${view.mapId}/frames/${id}`),
      async (confirmed) => {
        if (!confirmed) return;
        if (view.selectedFrameId === id) view.selectedFrameId = null;
        await loadMapData();
      });
  }

  // The note analogue of removeFrame above.
  function removeNote(id) {
    if (!App.canWrite('mapper')) return;
    const note = view.noteMap.get(id);
    if (!note) return;
    App.confirmDestructive('Remove note',
      '<p>Remove this note? Nothing it points at is moved or affected — ' +
      'only the note itself is removed.</p>',
      'Remove',
      () => App.del(`/api/mapper/maps/${view.mapId}/notes/${id}`),
      async (confirmed) => {
        if (!confirmed) return;
        if (view.selectedNoteId === id) view.selectedNoteId = null;
        await loadMapData();
      });
  }

  // D2: a manual line between two selected nodes -- discovery found nothing
  // there (or found it and drew it wrong), so the operator asserts it
  // instead. Enabled only when exactly two nodes are selected (drawToolbarState).
  function openConnect() {
    if (view.selection.size !== 2) return;
    const [aId, bId] = [...view.selection];
    App.modal('Connect', `
      <label>Label (optional) <input id="mpc-label" maxlength="60"></label>`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Connect', primary: true, onClick: async (box) => {
        const label = box.querySelector('#mpc-label').value.trim();
        try {
          await App.post(`/api/mapper/maps/${view.mapId}/links`,
            { a_node_id: aId, b_node_id: bId, label });
          App.closeModal();
          await loadMapData();
        } catch (error) {
          App.toast(`Could not connect: ${error.message}`, 'fail');
        }
      } },
    ]);
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

  // A rendering preference, not a map edit: toggling it never refetches.
  // It flips the attribute app.css keys off; the toggle handler also redraws,
  // since drawLink picks where a blocked link's dots live by view.fiberView.
  function applyFiberView() {
    App.el('mp-canvas').dataset.fiberview = view.fiberView ? '1' : '0';
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

  // The exact colour the VLAN table's own swatch uses (VLAN_COLUMNS below),
  // so a link's VlanView glow always matches the tile the operator picked it from.
  function vlanColorVar(vlan) {
    const v = view.vlans.find((x) => x.vlan === vlan);
    return `var(--canvas-vlan-${((v && v.color_index) || 0) + 1})`;
  }

  // An end with no VLAN data (null/empty) is skipped, so a blind peer never vetoes the known end.
  function vlanOnBothEnds(link, vlan) {
    const ends = [link.a_vlans, link.b_vlans].filter((v) => Array.isArray(v) && v.length);
    return ends.every((v) => v.includes(vlan));
  }

  function drawLink(layer, link, labelLayer = layer) {
    const a = linkNodeA(link), b = linkNodeB(link);
    if (!a || !b) return;   // an end not placed on THIS map: server already filters this out, belt-and-braces
    const pa = livePos(a), pb = livePos(b);
    const dx = pb.x - pa.x, dy = pb.y - pa.y;
    const from = edgePoint(pa.x, pa.y, NODE_W / 2, NODE_H / 2, dx, dy);
    const to = edgePoint(pb.x, pb.y, NODE_W / 2, NODE_H / 2, -dx, -dy);
    const len = Math.max(Math.hypot(dx, dy), 1e-6);
    const nx = -dy / len, ny = dx / len;
    // One line per cable between the same two nodes: draw() fills
    // view.linkFan before this runs, so every strand/label/underlay below
    // shifts together, off the pair's shared centre line.
    const fanOffset = (view.linkFan && view.linkFan.get(link.id)) || 0;
    if (fanOffset) {
      from.x += nx * fanOffset; from.y += ny * fanOffset;
      to.x += nx * fanOffset; to.y += ny * fanOffset;
    }
    const plan = link.plan || { mode: 'plain', width: 1.5, known: false, strands: [], vlans: [] };
    const selected = view.selectedLinkId === link.id;
    const dimmed = view.selectedVlan !== null
      && !(plan.vlans || []).includes(view.selectedVlan);
    // Halo only when BOTH ends carry the picked VLAN; one-sided draws plain, .dimmed fades the rest.
    const glow = view.selectedVlan !== null && !dimmed && vlanOnBothEnds(link, view.selectedVlan);
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
    // .mp-link's round caps lengthen every dash by the stroke width, so the
    // glow's own 5px-plus stroke closes .blocking's 2-on/6-off gaps and the
    // dots read solid. Below, a thin unglowed path carries them instead.
    const overlaidBlocking = link.blocking && link.fiber === true && view.fiberView;
    let bundleHalf = plan.width / 2;
    const isStrandBundle = plan.mode === 'strands' && plan.strands.length;
    if (isStrandBundle) {
      const offsets = plan.strands.map((strand) => strand.offset);
      bundleHalf = (Math.max(...offsets) - Math.min(...offsets) + plan.width) / 2;
    }
    const span = bundleHalf * 2; // shared by the strand-bundle underlays below and the VlanView glow
    if (glow) {
      const underlay = App.svgNode('path', {
        d: `M ${from.x} ${from.y} L ${to.x} ${to.y}`,
        class: 'mp-link mp-vlan-view', 'pointer-events': 'none', 'aria-hidden': 'true',
      });
      underlay.style.setProperty('--mp-vlan-glow', vlanColorVar(view.selectedVlan));
      underlay.style.setProperty('--mp-vlan-w',
        isStrandBundle ? `${span + 8}px` : `${Math.max(5, plan.width * 1.6) + 6}px`);
      layer.appendChild(underlay);
    }
    // How much of each end a port label takes, so the VLAN numbers below stay off it.
    let reserve = 0;
    if (view.settings.show_port_labels) {
      reserve = drawPortLabels(labelLayer, link, from, to, nx, ny, bundleHalf,
        (view.linkFanIndex && view.linkFanIndex.get(link.id)) || 0, fanOffset);
    }
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
      if (link.fiber === true) {
        // Underneath every strand, not one of them: the strands keep their
        // own VLAN colours, and this lone unfocusable path (no wireOne — no
        // tooltip/dataset of its own) just glows behind the whole ribbon.
        // No .blocking here: the strands above carry the dots themselves.
        const underlay = App.svgNode('path', {
          d: `M ${from.x} ${from.y} L ${to.x} ${to.y}`,
          class: 'mp-link fiber', 'pointer-events': 'none',
        });
        underlay.style.setProperty('--mp-fiber-w', `${span + 4}px`);
        if (dimmed) underlay.classList.add('dimmed');
        if (link.fiber_mode === 'sm') underlay.classList.add('fiber-sm');
        else if (link.fiber_mode === 'mismatch') underlay.classList.add('fiber-mismatch');
        layer.appendChild(underlay);
      }
      // Only the blocked VLANs' strands dot; no per-VLAN detail dots them all.
      const blocked = link.blocking ? stpBlockedVlans(link) : null;
      // Drawn BEFORE the strands, so a strand still wins its own per-VLAN
      // tooltip and this catches only the gaps and the margin around them.
      const hit = App.svgNode('path', {
        d: `M ${from.x} ${from.y} L ${to.x} ${to.y}`, fill: 'none',
        stroke: 'transparent', 'stroke-width': span + LINK_HIT_PAD,
        'pointer-events': 'stroke', class: 'mp-link-hit',
      });
      // No Tab stop or name: the first strand already carries the link's.
      hit.setAttribute('aria-hidden', 'true');
      let hitTip = null;
      hit.addEventListener('click', () => selectLink(link.id));
      hit.addEventListener('mousemove', (event) => {
        if (hitTip === null) hitTip = linkTooltip(link);
        App.tooltip(hitTip, event);
      });
      hit.addEventListener('mouseleave', App.hideTooltip);
      layer.appendChild(hit);
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
        if (link.blocking && (!blocked || blocked.has(strand.vlan))) {
          path.classList.add('blocking');
        }
        wireOne(path, null, i === 0
          ? { focusable: true, ariaLabel: linkAriaLabel(link), tooltip: () => linkTooltip(link) }
          : {
            focusable: false,
            ariaLabel: `VLAN ${vlanDisplay(strand.vlan)} strand on the link.`,
            tooltip: () => strandTooltip(link, strand),
          });
        if (view.settings.show_vlan_labels) {
          // label_step (server-computed, render_plan) staggers each
          // strand's number along the link instead of stacking every one
          // at the midpoint; a link too short to fit them 22px apart
          // falls back to the midpoint, same as before label_step existed.
          const n = plan.strands.length;
          const edgeLen = Math.hypot(to.x - from.x, to.y - from.y);
          let step = plan.label_step || 0;
          if (reserve && n > 1) {
            step = Math.min(step, Math.max(edgeLen - 2 * reserve, 0) / ((n - 1) * edgeLen));
          }
          const staggered = n > 1 && step * edgeLen >= STRAND_LABEL_MIN_GAP_PX;
          const frac = staggered ? 0.5 + (i - (n - 1) / 2) * step : 0.5;
          labelLayer.appendChild(App.svgNode('text', {
            class: 'mp-link-label',
            x: from.x + (to.x - from.x) * frac + ox,
            y: from.y + (to.y - from.y) * frac + oy - 3,
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
    wireOne(path, link.manual ? 'manual' : (plan.known === false ? 'unknown' : null));
    if (link.fiber === true) {
      path.classList.add('fiber');
      path.style.setProperty('--mp-fiber-w', `${Math.max(5, plan.width * 1.6)}px`);
      if (link.fiber_mode === 'sm') path.classList.add('fiber-sm');
      else if (link.fiber_mode === 'mismatch') path.classList.add('fiber-mismatch');
    }
    if (link.blocking && !overlaidBlocking) path.classList.add('blocking');
    if (overlaidBlocking) {
      const overlay = App.svgNode('path', {
        d: `M ${from.x} ${from.y} L ${to.x} ${to.y}`, fill: 'none',
        class: 'mp-link blocking mp-blocking-over', 'stroke-width': plan.width,
        'pointer-events': 'none',
      });
      if (dimmed) overlay.classList.add('dimmed');
      layer.appendChild(overlay);
    }
    if (plan.mode === 'collapsed' && view.settings.show_vlan_labels) {
      const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
      labelLayer.appendChild(App.svgNode('text', {
        class: 'mp-link-label', x: mx, y: my - 4, 'text-anchor': 'middle',
      }, `${plan.vlan_count} VLANs`));
    }
    if (link.manual && link.label) {
      const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
      labelLayer.appendChild(App.svgNode('text', {
        class: 'mp-link-label', x: mx, y: my - 4, 'text-anchor': 'middle',
      }, link.label));
    }
  }

  // show_port_labels: a small label at each end of the line naming that
  // end's own port — link.a_port/b_port, already resolved server side by
  // _neighbor_local_port_labeler. Drawn regardless of plan.mode (a "plain",
  // unknown-VLAN link still has two real ports), inset along the link so the
  // text clears the node box, and offset to one side of the line (the same
  // normal `nx,ny` the strand offsets use) so it never sits on top of the
  // stroke itself.
  function drawPortLabels(layer, link, from, to, nx, ny, bundleHalf, fanIndex = 0, fanOffset = 0) {
    if (!link.a_port && !link.b_port) return 0;
    const dx = to.x - from.x, dy = to.y - from.y;
    const len = Math.max(Math.hypot(dx, dy), 1e-6);
    const ux = dx / len, uy = dy / len;
    const aside = Math.max(8, bundleHalf + 5);
    // A start/end anchor along x only reads right beside a shallow line. On
    // a steep one both labels sit on the fan's outward side and read away
    // from it, so a cable's own label never crosses its line or its neighbour's.
    const steep = Math.abs(uy) > Math.abs(ux);
    const fanSide = Math.sign(fanOffset * nx) || 1;
    const ox = steep ? fanSide * aside : nx * aside, oy = steep ? 0 : ny * aside;
    // The box's reach is measured from where the label actually sits -- the
    // fan and the sideways offset both move it -- at whichever end reaches
    // further, so one inset serves both.
    const ex = nx * fanOffset + ox, ey = ny * fanOffset + oy;
    const clear = Math.max(boxExit(ux, uy, ex, ey), boxExit(-ux, -uy, ex, ey)) + PORT_LABEL_INSET;
    // Clamped at the midpoint: on a short link the two ends' labels would
    // otherwise step past each other and swap sides.
    const step = Math.min(fanIndex * PORT_LABEL_STEP, Math.max(len / 2 - clear, 0));
    const inset = clear + step;
    const label = (text, x, y, anchor) => layer.appendChild(App.svgNode('text', {
      class: 'mp-link-label', x, y, 'text-anchor': anchor,
    }, text));
    const ax = from.x + ux * inset + ox, ay = from.y + uy * inset + oy;
    const bx = to.x - ux * inset + ox, by = to.y - uy * inset + oy;
    if (steep) {
      const anchor = fanSide > 0 ? 'start' : 'end';
      if (link.a_port) label(link.a_port, ax, ay, anchor);
      if (link.b_port) label(link.b_port, bx, by, anchor);
      return inset + PORT_LABEL_STEP;
    }
    if (link.a_port) label(link.a_port, ax, ay, 'start');
    if (link.b_port) label(link.b_port, bx, by, 'end');
    return 0;
  }

  // How far along (ux, uy) the node box reaches past edgePoint()'s inscribed
  // ellipse, starting from a point (ox, oy) off that ellipse point: nothing
  // on an axis-aligned link, up to NODE_H / 2 toward a corner.
  function boxExit(ux, uy, ox, oy) {
    const hw = NODE_W / 2, hh = NODE_H / 2;
    const t = 1 / Math.sqrt((ux / hw) ** 2 + (uy / hh) ** 2);
    const px = ux * t + ox, py = uy * t + oy;
    const tx = ux ? (Math.sign(ux) * hw - px) / ux : Infinity;
    const ty = uy ? (Math.sign(uy) * hh - py) / uy : Infinity;
    return Math.max(0, Math.min(tx, ty));
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
    if (link.manual) {
      return `Manual line, ${a} to ${b}${link.label ? `, ${link.label}` : ''}.`;
    }
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
    let text = `Link, ${a} to ${b}, ${vlanText}.`;
    const fiberText = fiberModeText(link, a, b);
    if (fiberText) text += ` ${fiberText}.`;
    const stpText = stpBlockingText(link, a, b);
    if (stpText) text += ` ${stpText}.`;
    return text;
  }

  // '' for a port whose mode nothing reported — an unmanaged peer has no
  // VLAN MIB of its own, and a sysName-only match has no resolvable far-end
  // port to ask about, so this is blank far more often than it is wrong.
  function portMode(mode) {
    return mode === 'trunk' || mode === 'access' ? ` · ${mode}` : '';
  }

  // Fiber-mode (netpath.mapper.fiber_mode) and STP-blocking text, shared by
  // the tooltip, aria-label and detail pane -- `a`/`b` are already the
  // device names the caller wants shown (escaped, for the detail pane's
  // HTML); `esc` lets the detail pane escape the port text too, and
  // defaults to plain text for the tooltip/aria-label callers.
  function fiberModeText(link, a, b) {
    if (!link.fiber_mode) return null;
    const abbrev = (mode) => (mode === 'sm' ? 'SM' : 'MM');
    const full = (mode) => (mode === 'sm' ? 'single-mode' : 'multimode');
    if (link.fiber_mode === 'mismatch') {
      return `Fiber: ${abbrev(link.a_optic_mode)} on ${a}, ${abbrev(link.b_optic_mode)} on ${b} — mismatched`;
    }
    if (link.a_optic_mode && link.b_optic_mode) return `Fiber: ${full(link.fiber_mode)} both ends`;
    return `Fiber: ${full(link.fiber_mode)} (${link.a_optic_mode ? 'A' : 'B'} end known)`;
  }
  function stpVlanSuffix(vlans) {
    return vlans ? ` (VLANs ${vlans.split(',').join(', ')})` : '';
  }
  // withVlans: the tooltip and aria-label have no list to colour, so they
  // keep naming the ids. The pane passes false -- its list is red/green.
  function stpBlockingText(link, a, b, esc = (x) => x, withVlans = true) {
    if (!link.blocking) return null;
    const who = [];
    const suffix = (vlans) => (withVlans ? esc(stpVlanSuffix(vlans)) : '');
    const via = (v) => (v ? `, via ${esc(v)}` : '');
    if (link.a_stp === 'blocking') {
      who.push(`${a} (${esc(link.a_port || '—')}${via(link.a_stp_via)})${suffix(link.a_stp_vlans)}`);
    }
    if (link.b_stp === 'blocking') {
      who.push(`${b} (${esc(link.b_port || '—')}${via(link.b_stp_via)})${suffix(link.b_stp_vlans)}`);
    }
    return `STP: blocking on ${who.join(', ')}`;
  }

  // For a link not drawn blocking: both ends forward, or an end has no state.
  function stpIdleText(link, a, b, esc = (x) => x) {
    if (link.blocking) return null;
    const hasA = link.a_stp !== null && link.a_stp !== undefined;
    const hasB = link.b_stp !== null && link.b_stp !== undefined;
    if (hasA && hasB) return 'STP: forwarding on both ends';
    const who = [];
    if (!hasA) who.push(`${a} (${esc(link.a_port || '—')})`);
    if (!hasB) who.push(`${b} (${esc(link.b_port || '—')})`);
    return `STP: no state read on ${who.join(', ')}`;
  }

  // VlanView's pane line: callers only reach this once the VLAN is on at least one end.
  function vlanEndsText(link, vlan, esc = (x) => x) {
    const a = esc(resolveNode(linkNodeA(link)).name);
    const b = esc(resolveNode(linkNodeB(link)).name);
    const hasA = Array.isArray(link.a_vlans) && link.a_vlans.length > 0;
    const hasB = Array.isArray(link.b_vlans) && link.b_vlans.length > 0;
    const onA = hasA && link.a_vlans.includes(vlan);
    const onB = hasB && link.b_vlans.includes(vlan);
    const label = esc(vlanDisplay(vlan));
    if (onA && onB) return `VLAN ${label}: on both ends`;
    const [name, port, other, otherHas] = onA
      ? [a, link.a_port, b, hasB] : [b, link.b_port, a, hasA];
    const base = `VLAN ${label}: on ${name} (${esc(port || '—')})`;
    return otherHas ? `${base} only` : `${base}; ${other} reports no VLAN data`;
  }

  // null, not an empty Map: a link with nothing blocked leaves its list
  // neutral rather than painting every row green for no reason. Each end's
  // ids count only while that end itself blocks, the footer's own gate.
  function stpBlockedVlans(link) {
    if (!link.blocking) return null;
    const out = new Map();
    for (const end of ['a', 'b']) {
      const raw = link[`${end}_stp_vlans`];
      if (!raw || link[`${end}_stp`] !== 'blocking') continue;
      for (const part of String(raw).split(',')) {
        const vlan = Number(part.trim());
        if (!part.trim() || !Number.isFinite(vlan)) continue;
        out.set(vlan, out.has(vlan) && out.get(vlan) !== end ? 'both' : end);
      }
    }
    return out.size ? out : null;
  }

  // How far past the ribbon the invisible click target reaches: a strand is
  // 1.5px, and the operator was having to hit one exactly.
  const LINK_HIT_PAD = 14;

  // How many VLANs a hover/detail-pane screen names before "N more".
  const VLAN_TOOLTIP_CAP = 10;
  const VLAN_DETAIL_CAP = 10;

  function linkTooltip(link) {
    const a = resolveNode(linkNodeA(link)).name;
    const b = resolveNode(linkNodeB(link)).name;
    if (link.manual) {
      return [`Manual line`, `${a} — ${b}`, link.label || ''].filter(Boolean).join('\n');
    }
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
    const fiberText = fiberModeText(link, a, b);
    if (fiberText) lines.push(fiberText);
    const stpText = stpBlockingText(link, a, b) || stpIdleText(link, a, b);
    if (stpText) lines.push(stpText);
    if (view.selectedVlan !== null && (plan.vlans || []).includes(view.selectedVlan)) {
      lines.push(vlanEndsText(link, view.selectedVlan));
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

  // ---- label collision: pushes a colliding name label straight down in whole-line
  // steps until clear; measured off-document via canvas 2D, not getBBox(), to avoid
  // a reflow per node. Only the label's y moves — the node box itself never does.
  const LABEL_X = 30, LABEL_BASE_Y = 22, LABEL_SUB_GAP = 14, LABEL_GAP_PX = 3;
  const LABEL_STEP_CAP = 6;
  const labelMeasureCtx = document.createElement('canvas').getContext('2d');
  let labelFontCache = '';
  let subFontCache = '';
  function fontFor(familyToken, sizeToken = '--fs-2xs') {
    const root = getComputedStyle(document.documentElement);
    const remPx = parseFloat(root.fontSize) || 16;
    const sizeRem = parseFloat(root.getPropertyValue(sizeToken)) || 0.6875;
    const family = root.getPropertyValue(familyToken).trim() || 'sans-serif';
    return `${sizeRem * remPx}px ${family}`;
  }
  function labelFont() {
    if (!labelFontCache) labelFontCache = fontFor('--ui');
    return labelFontCache;
  }
  // .mp-node-sub's font (--mono); only its descent feeds the collision rect below.
  function subFont() {
    if (!subFontCache) subFontCache = fontFor('--mono');
    return subFontCache;
  }

  // A note's font at one of the three TEXT_SIZES; cleared with labelFontCache.
  const noteFontCache = new Map();
  function noteFont(sizeIdx) {
    if (!noteFontCache.has(sizeIdx)) noteFontCache.set(sizeIdx, fontFor('--ui', TEXT_SIZES[sizeIdx].fs));
    return noteFontCache.get(sizeIdx);
  }

  function measureLabel(text, font) {
    labelMeasureCtx.font = font || labelFont();
    const m = labelMeasureCtx.measureText(text);
    return {
      width: m.width,
      ascent: m.fontBoundingBoxAscent || m.actualBoundingBoxAscent || 8,
      descent: m.fontBoundingBoxDescent || m.actualBoundingBoxDescent || 3,
    };
  }

  // The one place a label's scene rect is computed; covers the sub-line too so a
  // collision push clears both, not just the name.
  function labelRect(node, info, steps) {
    const pos = livePos(node);
    const { width, ascent, descent } = measureLabel(truncate(info.name, 24));
    const lineStep = ascent + descent + LABEL_GAP_PX;
    const baseY = pos.y - NODE_H / 2 + LABEL_BASE_Y + steps * lineStep;
    const h = info.sub
      ? ascent + LABEL_SUB_GAP + measureLabel(truncate(info.sub, 26), subFont()).descent
      : ascent + descent;
    return { x: pos.x - NODE_W / 2 + LABEL_X, y: baseY - ascent, w: width, h };
  }

  function rectsOverlap(a, b) {
    if (a.y + a.h <= b.y || b.y + b.h <= a.y) return false;   // vertical early exit
    return a.x < b.x + b.w && a.x + a.w > b.x;
  }

  // node.id -> line-steps pushed down; processed by y then x for a stable result.
  function placeLabels(nodes) {
    const boxes = nodes.map((node) => {
      const pos = livePos(node);
      return { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2, w: NODE_W, h: NODE_H };
    });
    const order = nodes.map((node, index) => ({ node, index }))
      .sort((a, b) => livePos(a.node).y - livePos(b.node).y || livePos(a.node).x - livePos(b.node).x);
    const placed = [];
    const offsets = new Map();
    for (const { node, index } of order) {
      const info = resolveNode(node);
      let steps = 0;
      let rect = labelRect(node, info, steps);
      while (steps < LABEL_STEP_CAP && (placed.some((r) => rectsOverlap(rect, r))
        || boxes.some((box, j) => j !== index && rectsOverlap(rect, box)))) {
        steps += 1;
        rect = labelRect(node, info, steps);
      }
      offsets.set(node.id, steps);
      placed.push(rect);
    }
    return offsets;
  }

  function drawNode(layer, node, labelOffsets) {
    const info = resolveNode(node);
    const pos = livePos(node);
    const g = App.svgNode('g', {
      class: `mp-node${view.selection.has(node.id) ? ' selected' : ''}` +
        `${info.unmanaged ? ' unmanaged' : ''}${info.gone ? ' gone' : ''}` +
        `${info.placeholder ? ' placeholder' : ''}`,
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
    if (!info.unmanaged && !info.gone && !info.placeholder) {
      g.appendChild(statusGlyph(info.tone, NODE_W - 14, 12));
    }
    const steps = (labelOffsets && labelOffsets.get(node.id)) || 0;
    const { ascent, descent } = measureLabel(truncate(info.name, 24));
    const nameY = LABEL_BASE_Y + steps * (ascent + descent + LABEL_GAP_PX);
    const nameNode = App.svgNode('text', {
      class: 'mp-node-label', x: LABEL_X, y: nameY,
    }, truncate(info.name, 24));
    g.appendChild(nameNode);
    if (info.sub) {
      g.appendChild(App.svgNode('text',
        { class: 'mp-node-sub', x: LABEL_X, y: nameY + LABEL_SUB_GAP }, truncate(info.sub, 26)));
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
      `${info.gone ? ', removed from Nodes' : ''}${info.placeholder ? ', placeholder' : ''}.`);
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
    // Opens the same Device Details modal as a Nodes row dblclick, without leaving Mapper.
    g.addEventListener('dblclick', (event) => {
      if (info.unmanaged || info.gone || info.placeholder) return;
      event.preventDefault();
      event.stopPropagation();
      App.whenModuleReady('nodes').then((page) => page.openDeviceDialog(node.device_id))
        .catch(() => {});
    });
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

  // The rect a frame is drawn at RIGHT NOW — livePos's own logic, for a
  // frame's x/y/width/height instead of a node's x/y.
  function liveFrameRect(frame) {
    const drag = view.frameDrag;
    if (drag && drag.id === frame.id) {
      if (drag.mode === 'move') {
        return { x: drag.startRect.x + drag.dx, y: drag.startRect.y + drag.dy,
          width: drag.startRect.width, height: drag.startRect.height };
      }
      return { x: drag.startRect.x, y: drag.startRect.y,
        width: Math.max(FRAME_MIN, drag.startRect.width + drag.dx),
        height: Math.max(FRAME_MIN, drag.startRect.height + drag.dy) };
    }
    const pending = view.pendingFramePatches.get(frame.id);
    return {
      x: (pending && pending.x !== undefined) ? pending.x : frame.x,
      y: (pending && pending.y !== undefined) ? pending.y : frame.y,
      width: (pending && pending.width !== undefined) ? pending.width : frame.width,
      height: (pending && pending.height !== undefined) ? pending.height : frame.height,
    };
  }

  // The note analogue of liveFrameRect.
  function liveNoteRect(note) {
    const drag = view.noteDrag;
    if (drag && drag.id === note.id) {
      if (drag.mode === 'move') {
        return { x: drag.startRect.x + drag.dx, y: drag.startRect.y + drag.dy,
          width: drag.startRect.width, height: drag.startRect.height };
      }
      return { x: drag.startRect.x, y: drag.startRect.y,
        width: Math.max(FRAME_MIN, drag.startRect.width + drag.dx),
        height: Math.max(FRAME_MIN, drag.startRect.height + drag.dy) };
    }
    const pending = view.pendingNotePatches.get(note.id);
    return {
      x: (pending && pending.x !== undefined) ? pending.x : note.x,
      y: (pending && pending.y !== undefined) ? pending.y : note.y,
      width: (pending && pending.width !== undefined) ? pending.width : note.width,
      height: (pending && pending.height !== undefined) ? pending.height : note.height,
    };
  }

  function contentBounds() {
    if (!view.nodes.length && !view.frames.length && !view.notes.length) return null;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const node of view.nodes) {
      const p = livePos(node);
      minX = Math.min(minX, p.x - NODE_W / 2); maxX = Math.max(maxX, p.x + NODE_W / 2);
      minY = Math.min(minY, p.y - NODE_H / 2); maxY = Math.max(maxY, p.y + NODE_H / 2);
    }
    for (const frame of view.frames) {
      const r = liveFrameRect(frame);
      minX = Math.min(minX, r.x); maxX = Math.max(maxX, r.x + r.width);
      minY = Math.min(minY, r.y); maxY = Math.max(maxY, r.y + r.height);
    }
    for (const note of view.notes) {
      const r = liveNoteRect(note);
      minX = Math.min(minX, r.x); maxX = Math.max(maxX, r.x + r.width);
      minY = Math.min(minY, r.y); maxY = Math.max(maxY, r.y + r.height);
    }
    return { x: minX, y: minY, width: maxX - minX, height: maxY - minY };
  }

  /* ------------------------------------------------------------- frames
     Decoration only — see the file header comment: a frame's own x/y/
     width/height never touch a node, so nothing here reads or writes
     view.nodes. Each frame is a <g class="mp-frame"> of four children in a
     fixed order (fill, stroke, label, resize handle); updateFrameElement
     repositions all four in place, shared by the initial draw and every
     drag/resize redraw so the geometry is written in exactly one place. */
  function frameColorClass(frame) {
    const idx = Number.isInteger(frame.color) ? Math.max(0, Math.min(5, frame.color)) : 0;
    return `mp-frame-c${idx}`;
  }

  function updateFrameElement(g, frame) {
    const r = liveFrameRect(frame);
    const fill = g.querySelector('.mp-frame-fill');
    const stroke = g.querySelector('.mp-frame-stroke');
    const label = g.querySelector('.mp-frame-label');
    const handle = g.querySelector('.mp-frame-handle');
    for (const el of [fill, stroke]) {
      el.setAttribute('x', r.x); el.setAttribute('y', r.y);
      el.setAttribute('width', r.width); el.setAttribute('height', r.height);
    }
    const sizeIdx = textSizeIndex(frame);
    label.setAttribute('x', r.x + 6);
    label.setAttribute('y', r.y + TEXT_SIZES[sizeIdx].dy);
    for (let i = 0; i < TEXT_SIZES.length; i += 1) {
      label.classList.toggle(`mp-frame-t${i}`, i === sizeIdx);
    }
    handle.setAttribute('x', r.x + r.width - FRAME_HANDLE);
    handle.setAttribute('y', r.y + r.height - FRAME_HANDLE);
  }

  function drawFrame(layer, frame) {
    const selected = view.selectedFrameId === frame.id;
    const g = App.svgNode('g', { class: `mp-frame ${frameColorClass(frame)}${selected ? ' selected' : ''}` });
    g.dataset.frameId = frame.id;
    // (a) the fill: pointer-events none, so a rubber-band drag or a pan
    // started over the inside of a frame still reaches the canvas below it.
    const fill = App.svgNode('rect', { class: 'mp-frame-fill', 'pointer-events': 'none' });
    // (b) the stroke: pointer-events stroke, so only the dashed outline
    // itself — not the whole rect — is what a click/drag on the frame hits.
    const stroke = App.svgNode('rect', { class: 'mp-frame-stroke', 'pointer-events': 'stroke' });
    // (c) the label. Not escape()'d: this is an SVG text node's textContent
    // (App.svgNode's third argument), never parsed as markup, the same
    // reason no other label on this canvas (a port name, a VLAN id) is
    // either — escape() belongs where a name lands in an HTML string.
    const label = App.svgNode('text', { class: 'mp-frame-label' }, truncate(frame.label || 'Frame', 40));
    // (d) the resize handle, bottom-right.
    const handle = App.svgNode('rect', {
      class: 'mp-frame-handle', width: FRAME_HANDLE, height: FRAME_HANDLE,
    });
    g.append(fill, stroke, label, handle);
    stroke.addEventListener('pointerdown', (event) => onFramePointerDown(event, frame, 'move'));
    label.addEventListener('pointerdown', (event) => onFramePointerDown(event, frame, 'move'));
    handle.addEventListener('pointerdown', (event) => onFramePointerDown(event, frame, 'resize'));
    // The same Tab reach a node gets: tabindex/role/aria-label via
    // setAttribute (never innerHTML, so the label needs no escape() here
    // either), Enter/Space selects through the same path a pointer press
    // does, and Delete/Backspace removes — nodes have no keyboard delete of
    // their own to match, so none is added here beyond what was asked.
    g.tabIndex = 0;
    g.setAttribute('role', 'button');
    g.setAttribute('aria-label', frame.label ? `Frame ${frame.label}` : 'Frame');
    g.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectFrame(frame);
      } else if (event.key === 'Delete' || event.key === 'Backspace') {
        event.preventDefault();
        removeFrame(frame.id);
      }
    });
    updateFrameElement(g, frame);
    layer.appendChild(g);
    return g;
  }

  /* -------------------------------------------------------------- notes
     A thought-bubble annotation, the frame idiom applied to operator
     commentary instead of grouping: same debounced-drag/resize, same
     six-swatch palette, same keyboard reach. The one thing a frame never
     has is an anchor — note.node_id, set once at creation, points the
     bubble's tail at a placed node and keeps it there as that node is
     dragged (see redrawDragged's own notesByNode pass); with no anchor the
     tail just points down-left, a fixed offset off the bubble itself. */
  function noteColorClass(note) {
    const idx = Number.isInteger(note.color) ? Math.max(0, Math.min(5, note.color)) : 0;
    return `mp-note-c${idx}`;
  }

  function noteAnchorNode(note) {
    return (note.node_id === null || note.node_id === undefined) ? null : nodeById(note.node_id);
  }

  // Two circles trailing off the bubble's lower-left toward whatever it
  // points at — the anchor node's live position, or a fixed down-left
  // offset with no anchor. Guarded against a zero-length direction (an
  // anchor that lands exactly on the tail's own base point).
  function noteTail(note, r) {
    const base = { x: r.x + r.width * 0.22, y: r.y + r.height };
    const anchor = noteAnchorNode(note);
    const target = anchor ? livePos(anchor) : { x: base.x - 24, y: base.y + 24 };
    let dx = target.x - base.x, dy = target.y - base.y;
    const len = Math.hypot(dx, dy) || 1;
    dx /= len; dy /= len;
    return {
      c1: { x: base.x + dx * 10, y: base.y + dy * 10, r: 5 },
      c2: { x: base.x + dx * 20, y: base.y + dy * 20, r: 3 },
    };
  }

  const NOTE_PAD_X = 8, NOTE_PAD_TOP = 14;

  // Greedy word wrap against the bubble's own inner width, capped to
  // however many lines its inner height fits — a long word alone can still
  // overrun a line (no mid-word breaking), and text past the last line is
  // marked with a trailing ellipsis rather than silently dropped.
  function wrapNoteLines(text, innerWidth, maxLines, font) {
    const words = String(text || '').trim().split(/\s+/).filter(Boolean);
    if (!words.length) return [];
    const lines = [];
    let current = '';
    let truncated = false;
    for (const word of words) {
      const attempt = current ? `${current} ${word}` : word;
      if (!current || measureLabel(attempt, font).width <= innerWidth) {
        current = attempt;
        continue;
      }
      lines.push(current);
      current = word;
      if (lines.length >= maxLines) { truncated = true; current = ''; break; }
    }
    if (current) {
      if (lines.length >= maxLines) truncated = true;
      else lines.push(current);
    }
    if (truncated && lines.length) lines[lines.length - 1] += '…';
    return lines;
  }

  // The note analogue of updateFrameElement: one place that repositions
  // every child (and re-wraps the text, since the wrap depends on the
  // bubble's own current size), shared by the initial draw and every
  // drag/resize redraw.
  function updateNoteElement(g, note) {
    const r = liveNoteRect(note);
    const fill = g.querySelector('.mp-note-fill');
    const stroke = g.querySelector('.mp-note-stroke');
    const text = g.querySelector('.mp-note-text');
    const tail1 = g.querySelector('.mp-note-tail1');
    const tail2 = g.querySelector('.mp-note-tail2');
    const handle = g.querySelector('.mp-note-handle');
    for (const el of [fill, stroke]) {
      el.setAttribute('x', r.x); el.setAttribute('y', r.y);
      el.setAttribute('width', r.width); el.setAttribute('height', r.height);
    }
    const sizeIdx = textSizeIndex(note);
    const font = noteFont(sizeIdx);
    const metrics = measureLabel('M', font);
    const lineHeight = metrics.ascent + metrics.descent + 2;
    const padTop = Math.max(NOTE_PAD_TOP, metrics.ascent + 3);
    const innerWidth = Math.max(10, r.width - NOTE_PAD_X * 2);
    const innerHeight = Math.max(lineHeight, r.height - padTop - NOTE_PAD_X);
    const maxLines = Math.max(1, Math.floor(innerHeight / lineHeight));
    text.textContent = '';
    text.setAttribute('x', r.x + NOTE_PAD_X);
    text.setAttribute('y', r.y + padTop);
    for (let i = 0; i < TEXT_SIZES.length; i += 1) {
      text.classList.toggle(`mp-note-t${i}`, i === sizeIdx);
    }
    wrapNoteLines(note.text, innerWidth, maxLines, font).forEach((line, i) => {
      text.appendChild(App.svgNode('tspan', { x: r.x + NOTE_PAD_X, dy: i === 0 ? 0 : lineHeight }, line));
    });
    const tail = noteTail(note, r);
    tail1.setAttribute('cx', tail.c1.x); tail1.setAttribute('cy', tail.c1.y); tail1.setAttribute('r', tail.c1.r);
    tail2.setAttribute('cx', tail.c2.x); tail2.setAttribute('cy', tail.c2.y); tail2.setAttribute('r', tail.c2.r);
    handle.setAttribute('x', r.x + r.width - FRAME_HANDLE);
    handle.setAttribute('y', r.y + r.height - FRAME_HANDLE);
  }

  function drawNote(layer, note) {
    const selected = view.selectedNoteId === note.id;
    const g = App.svgNode('g', { class: `mp-note ${noteColorClass(note)}${selected ? ' selected' : ''}` });
    g.dataset.noteId = note.id;
    // Children in a fixed order, the same shape drawFrame's own comment
    // documents: fill, stroke, text, the two tail circles, resize handle.
    const fill = App.svgNode('rect', { class: 'mp-note-fill', rx: 10, ry: 10, 'pointer-events': 'none' });
    const stroke = App.svgNode('rect', { class: 'mp-note-stroke', rx: 10, ry: 10, 'pointer-events': 'stroke' });
    // textContent only (App.svgNode's third argument, set per-tspan in
    // updateNoteElement) — never innerHTML, so no escape() belongs here
    // either; see drawFrame's own comment on its label for why.
    const text = App.svgNode('text', { class: 'mp-note-text' });
    const tail1 = App.svgNode('circle', { class: 'mp-note-tail mp-note-tail1' });
    const tail2 = App.svgNode('circle', { class: 'mp-note-tail mp-note-tail2' });
    const handle = App.svgNode('rect', {
      class: 'mp-note-handle', width: FRAME_HANDLE, height: FRAME_HANDLE,
    });
    g.append(fill, stroke, text, tail1, tail2, handle);
    stroke.addEventListener('pointerdown', (event) => onNotePointerDown(event, note, 'move'));
    text.addEventListener('pointerdown', (event) => onNotePointerDown(event, note, 'move'));
    handle.addEventListener('pointerdown', (event) => onNotePointerDown(event, note, 'resize'));
    g.tabIndex = 0;
    g.setAttribute('role', 'button');
    g.setAttribute('aria-label', note.text ? `Note ${truncate(note.text, 60)}` : 'Note');
    g.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectNote(note);
      } else if (event.key === 'Delete' || event.key === 'Backspace') {
        event.preventDefault();
        removeNote(note.id);
      }
    });
    updateNoteElement(g, note);
    layer.appendChild(g);
    return g;
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

  // Redraws only the dragged nodes, the links touching them, and any
  // note anchored to one of them (its tail follows the node it points at).
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
      for (const note of view.notesByNode.get(id) || []) {
        const noteEl = view.noteEls.get(note.id);
        if (noteEl) updateNoteElement(noteEl, note);
      }
    }
    for (const link of touched) {
      const holder = view.linkEls.get(link.id);
      if (!holder) continue;
      holder.textContent = '';
      const labels = view.linkLabelEls.get(link.id);
      if (labels) labels.textContent = '';
      drawLink(holder, link, labels || holder);
    }
  }

  // The frame-drag analogue of requestDragDraw/redrawDragged: one redraw of
  // just the dragged frame per animation frame, not the whole scene.
  let frameDragPending = 0;

  function requestFrameDragDraw() {
    if (frameDragPending) return;
    frameDragPending = window.requestAnimationFrame(() => { frameDragPending = 0; redrawFrameDragged(); });
  }

  function redrawFrameDragged() {
    const drag = view.frameDrag;
    const frame = drag && view.frameMap.get(drag.id);
    const el = drag && view.frameEls.get(drag.id);
    if (!frame || !el) { requestDraw(); return; }
    updateFrameElement(el, frame);
  }

  // The note-drag analogue of requestFrameDragDraw/redrawFrameDragged.
  let noteDragPending = 0;

  function requestNoteDragDraw() {
    if (noteDragPending) return;
    noteDragPending = window.requestAnimationFrame(() => { noteDragPending = 0; redrawNoteDragged(); });
  }

  function redrawNoteDragged() {
    const drag = view.noteDrag;
    const note = drag && view.noteMap.get(drag.id);
    const el = drag && view.noteEls.get(drag.id);
    if (!note || !el) { requestDraw(); return; }
    updateNoteElement(el, note);
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

  // Every cable between the same two nodes its own line: parallel LLDP
  // links already fold onto distinct frozenset keys (mapper.py) but used to
  // land on identical coordinates. Groups view.links by the unordered pair
  // of node ids, spaces each group's members off the shared centre line,
  // and returns link.id -> offset (px, along the link's own normal) for
  // drawLink to apply. A pair with only one link needs no offset at all.
  function fanOffsets() {
    const groups = new Map();
    for (const link of view.links) {
      const a = linkNodeA(link), b = linkNodeB(link);
      if (!a || !b) continue;
      const key = a.id < b.id ? `${a.id}:${b.id}` : `${b.id}:${a.id}`;
      let group = groups.get(key);
      if (!group) { group = []; groups.set(key, group); }
      group.push(link);
    }
    const fan = new Map();
    const index = new Map();
    for (const group of groups.values()) {
      if (group.length < 2) continue;
      group.sort((x, y) => String(x.id).localeCompare(String(y.id)));
      let widest = 0;
      for (const link of group) {
        const plan = link.plan || {};
        let span = plan.width || 1.5;
        if (plan.mode === 'strands' && plan.strands.length) {
          const offsets = plan.strands.map((strand) => strand.offset);
          span = (Math.max(...offsets) - Math.min(...offsets)) + plan.width;
        }
        if (span > widest) widest = span;
      }
      const spacing = Math.max(30, widest + 16);
      const start = -spacing * (group.length - 1) / 2;
      group.forEach((link, i) => {
        const a = linkNodeA(link), b = linkNodeB(link);
        // Sign flipped when this link's own A node is the larger of the
        // pair, so both ends' drawLink calls (whichever one reported it)
        // shift the cable the same way in world space -- see drawLink's
        // (nx, ny), which itself flips with a link's a/b order.
        const flip = a.id > b.id ? -1 : 1;
        fan.set(link.id, flip * (start + i * spacing));
        index.set(link.id, i);
      });
    }
    return { fan, index };
  }

  function draw() {
    const svg = App.el('mp-svg');
    const canvas = App.el('mp-canvas');
    canvas.dataset.mapStyle = currentMapStyle();
    applyFiberView();
    // Replacing the <g> a drag captured means its release never arrives.
    view.nodeDrag = null;
    view.frameDrag = null;
    view.noteDrag = null;
    svg.innerHTML = '';
    view.sceneGroup = null;
    view.rubberEl = null;
    view.nodeEls = new Map();
    view.linkEls = new Map();
    view.linkLabelEls = new Map();
    view.frameEls = new Map();
    view.noteEls = new Map();

    if (!view.mapId) {
      return emptyCanvas(svg, canvas, 'No map selected. Use Maps to create or pick one.');
    }
    // The Frame/Note tools need the real canvas to draw the first one on,
    // so either armed button falls through here even with nothing on the
    // map yet — otherwise a brand-new map could never get its first frame
    // or note.
    if (!view.nodes.length && !view.frames.length && !view.notes.length && !view.framing && !view.noting) {
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
    const frameLayer = App.svgNode('g');
    const linkLayer = App.svgNode('g');
    const labelLayer = App.svgNode('g');
    const nodeLayer = App.svgNode('g');
    const noteLayer = App.svgNode('g');
    // frameLayer sits between the grid and the links: a frame is
    // decoration an operator draws to group boxes visually, and must never
    // sit over a link or a node it encloses. noteLayer sits on top of
    // everything else: a note is read over whatever it annotates, not
    // grouped under it the way a frame is.
    group.append(gridLayer, frameLayer, linkLayer, nodeLayer, labelLayer, noteLayer);
    if (shouldDrawGrid() && bounds) drawGrid(gridLayer, bounds);
    for (const frame of view.frames) view.frameEls.set(frame.id, drawFrame(frameLayer, frame));
    const fans = fanOffsets();
    view.linkFan = fans.fan;
    view.linkFanIndex = fans.index;
    // Own <g> per link: redrawDragged refills just the ones that moved.
    for (const link of view.links) {
      const holder = App.svgNode('g');
      linkLayer.appendChild(holder);
      view.linkEls.set(link.id, holder);
      const labels = App.svgNode('g');
      labelLayer.appendChild(labels);
      view.linkLabelEls.set(link.id, labels);
      drawLink(holder, link, labels);
    }
    // Refreshed every draw so a theme switch's font change is picked up on the next redraw.
    labelFontCache = fontFor('--ui');
    subFontCache = fontFor('--mono');
    noteFontCache.clear();
    const labelOffsets = placeLabels(view.nodes);
    for (const node of view.nodes) view.nodeEls.set(node.id, drawNode(nodeLayer, node, labelOffsets));
    for (const note of view.notes) view.noteEls.set(note.id, drawNote(noteLayer, note));

    view.rubberEl = App.svgNode('rect', { class: 'mp-rubber' });
    group.appendChild(view.rubberEl);
    // Built detached and appended once: every layer above filled while the
    // group was out of the document, so a map's worth of nodes and links is
    // one insertion rather than thousands into a live tree. Nothing above
    // measures layout (the two getBoundingClientRect calls in drawLink and
    // drawNode are inside focus handlers), so it is safe to attach here.
    svg.appendChild(group);
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
    const hasFiber = view.links.some((l) => l.fiber);
    const hasLinks = view.links.length > 0;
    let text = '';
    if (view.selectedVlan !== null) {
      text = `VlanView: links carrying VLAN ${vlanDisplay(view.selectedVlan)} on both ends glow in ` +
        'its colour; a link carrying it on one end only draws plain; the rest are dimmed. ';
    }
    if (view.fiberView && hasFiber) {
      text += 'FiberView: dark orange = multimode, bright yellow = single-mode, ' +
        'dotted red = single/multimode mismatch.';
    }
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
    view.selectedFrameId = null;
    view.selectedNoteId = null;
    requestDraw();
    drawDetail();
  }

  function selectLink(id) {
    view.selectedLinkId = id;
    view.selection.clear();
    view.selectedFrameId = null;
    view.selectedNoteId = null;
    // Each link opens on its capped VLAN list; "Show all" is a decision
    // about the link being read, not a mode the pane stays in.
    view.detailShowAllVlans = false;
    requestDraw();
    drawDetail();
  }

  // Keyboard path only (Enter/Space below); not a drag, so a full redraw is fine.
  function selectFrame(frame) {
    view.selectedFrameId = frame.id;
    view.selection = new Set();
    view.selectedLinkId = null;
    view.selectedNoteId = null;
    requestDraw();
    drawDetail();
  }

  // The frame analogue of applySelectionClasses: toggles .selected in place,
  // not requestDraw() (which would detach the <g> just captured below).
  function selectFrameInPlace(frame) {
    view.selectedFrameId = frame.id;
    view.selection = new Set();
    view.selectedLinkId = null;
    view.selectedNoteId = null;
    if (!view.frameEls.size) { requestDraw(); return; }
    for (const [id, el] of view.frameEls) el.classList.toggle('selected', id === frame.id);
    for (const [, el] of view.nodeEls) el.classList.remove('selected');
    for (const [, el] of view.noteEls) el.classList.remove('selected');
    for (const [, holder] of view.linkEls) {
      for (const path of holder.querySelectorAll('.mp-link')) path.classList.remove('selected');
    }
    drawDetail();
  }

  // The note analogue of selectFrame -- keyboard path only.
  function selectNote(note) {
    view.selectedNoteId = note.id;
    view.selection = new Set();
    view.selectedLinkId = null;
    view.selectedFrameId = null;
    requestDraw();
    drawDetail();
  }

  // The note analogue of selectFrameInPlace.
  function selectNoteInPlace(note) {
    view.selectedNoteId = note.id;
    view.selection = new Set();
    view.selectedLinkId = null;
    view.selectedFrameId = null;
    if (!view.noteEls.size) { requestDraw(); return; }
    for (const [id, el] of view.noteEls) el.classList.toggle('selected', id === note.id);
    for (const [, el] of view.nodeEls) el.classList.remove('selected');
    for (const [, el] of view.frameEls) el.classList.remove('selected');
    for (const [, holder] of view.linkEls) {
      for (const path of holder.querySelectorAll('.mp-link')) path.classList.remove('selected');
    }
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
    if (view.selectedFrameId) {
      const frame = view.frameMap.get(view.selectedFrameId);
      if (!frame) { view.selectedFrameId = null; return renderDetail(); }
      nameEl.textContent = 'FRAME';
      detail.innerHTML = frameDetailHtml(frame);
      const saveBtn = detail.querySelector('#mpf-label-save');
      if (saveBtn) saveBtn.onclick = async () => {
        const label = detail.querySelector('#mpf-label').value.trim();
        try {
          await App.put(`/api/mapper/maps/${view.mapId}/frames/${frame.id}`, { label });
          frame.label = label;
          requestDraw();
          drawDetail();
        } catch (error) {
          App.toast(`Could not rename the frame: ${error.message}`, 'fail');
        }
      };
      const labelInput = detail.querySelector('#mpf-label');
      if (labelInput) labelInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && saveBtn) { event.preventDefault(); saveBtn.click(); }
      });
      for (const swatch of detail.querySelectorAll('[data-frame-color]')) {
        swatch.onclick = async () => {
          const color = Number(swatch.dataset.frameColor);
          try {
            await App.put(`/api/mapper/maps/${view.mapId}/frames/${frame.id}`, { color });
            frame.color = color;
            requestDraw();
            drawDetail();
          } catch (error) {
            App.toast(`Could not change the frame's colour: ${error.message}`, 'fail');
          }
        };
      }
      for (const sizeBtn of detail.querySelectorAll('[data-frame-textsize]')) {
        sizeBtn.onclick = async () => {
          const textSize = Number(sizeBtn.dataset.frameTextsize);
          try {
            await App.put(`/api/mapper/maps/${view.mapId}/frames/${frame.id}`, { text_size: textSize });
            frame.text_size = textSize;
            requestDraw();
            drawDetail();
          } catch (error) {
            App.toast(`Could not change the frame's text size: ${error.message}`, 'fail');
          }
        };
      }
      const removeBtn = detail.querySelector('#mpf-remove');
      if (removeBtn) removeBtn.onclick = () => removeFrame(frame.id);
      return;
    }
    if (view.selectedNoteId) {
      const note = view.noteMap.get(view.selectedNoteId);
      if (!note) { view.selectedNoteId = null; return renderDetail(); }
      nameEl.textContent = 'NOTE';
      detail.innerHTML = noteDetailHtml(note);
      const saveBtn = detail.querySelector('#mpn-text-save');
      if (saveBtn) saveBtn.onclick = async () => {
        const text = detail.querySelector('#mpn-text').value.trim();
        try {
          await App.put(`/api/mapper/maps/${view.mapId}/notes/${note.id}`, { text });
          note.text = text;
          requestDraw();
          drawDetail();
        } catch (error) {
          App.toast(`Could not update the note: ${error.message}`, 'fail');
        }
      };
      for (const swatch of detail.querySelectorAll('[data-note-color]')) {
        swatch.onclick = async () => {
          const color = Number(swatch.dataset.noteColor);
          try {
            await App.put(`/api/mapper/maps/${view.mapId}/notes/${note.id}`, { color });
            note.color = color;
            requestDraw();
            drawDetail();
          } catch (error) {
            App.toast(`Could not change the note's colour: ${error.message}`, 'fail');
          }
        };
      }
      for (const sizeBtn of detail.querySelectorAll('[data-note-textsize]')) {
        sizeBtn.onclick = async () => {
          const textSize = Number(sizeBtn.dataset.noteTextsize);
          try {
            await App.put(`/api/mapper/maps/${view.mapId}/notes/${note.id}`, { text_size: textSize });
            note.text_size = textSize;
            requestDraw();
            drawDetail();
          } catch (error) {
            App.toast(`Could not change the note's text size: ${error.message}`, 'fail');
          }
        };
      }
      const removeBtn = detail.querySelector('#mpn-remove');
      if (removeBtn) removeBtn.onclick = () => removeNote(note.id);
      return;
    }
    if (view.selectedLinkId) {
      const link = linkById(view.selectedLinkId);
      if (!link) { view.selectedLinkId = null; return renderDetail(); }
      nameEl.textContent = 'LINK';
      detail.innerHTML = linkDetailHtml(link);
      const showAll = detail.querySelector('[data-show-all-vlans]');
      if (showAll) showAll.onclick = () => { view.detailShowAllVlans = true; drawDetail(); };
      const removeLink = detail.querySelector('[data-remove-link]');
      if (removeLink) removeLink.onclick = async () => {
        try {
          await App.del(`/api/mapper/maps/${view.mapId}/links/${link.link_id}`);
          view.selectedLinkId = null;
          await loadMapData();
        } catch (error) {
          App.toast(`Could not remove line: ${error.message}`, 'fail');
        }
      };
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
    if (info.placeholder) {
      lines.push('', 'Placeholder — not a device. Drawn for the diagram only; select it with a ' +
        'device and press Connect to join them.');
      lines.push(`Role        ${roleSelectHtml(node)}`);
      lines.push('', `<button data-remove-node="${node.id}" data-requires-write="mapper"` +
        `${App.canWrite('mapper') ? '' : ' disabled'}>Remove from map</button>`);
      return lines.join('\n');
    }
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
    if (link.manual) {
      const lines = ['Manual line', '', `${escape(a.name)}`, '  —', `${escape(b.name)}`, ''];
      if (link.label) lines.push(`Label       ${escape(link.label)}`, '');
      lines.push(`Added       ${escape(App.ago(link.seen_ts))}`, '',
        `<button data-remove-link="${link.link_id}" data-requires-write="mapper"` +
        `${App.canWrite('mapper') ? '' : ' disabled'}>Remove line</button>`);
      return lines.join('\n');
    }
    const plan = link.plan || {};
    const lines = [`${escape(a.name)} (${escape(link.a_port || '—')})`,
      `  ↕  ${escape((link.protocols || []).join(', ').toUpperCase())}`,
      `${escape(b.name)} (${escape(link.b_port || '—')})`, ''];
    if (plan.known === false) {
      lines.push('No VLAN data known for this link — neither end answered a VLAN MIB.');
    } else {
      const vlans = plan.vlans || [];
      const blocked = stpBlockedVlans(link);
      const all = view.detailShowAllVlans || vlans.length <= VLAN_DETAIL_CAP;
      lines.push(`VLANs (${vlans.length})`, '-'.repeat(30));
      for (const vlan of all ? vlans : vlans.slice(0, VLAN_DETAIL_CAP)) {
        const name = view.vlanNameById.get(vlan);
        const row = `${vlan}${name ? `  ${escape(name)}` : ''}` +
          `${link.native_vlan === vlan ? '  (native)' : ''}`;
        // Never colour alone, the same way (native) above carries words.
        if (blocked === null) lines.push(row);
        else if (blocked.has(vlan)) {
          const end = blocked.get(vlan);
          const where = end === 'both' ? `${escape(a.name)} and ${escape(b.name)}`
            : escape(end === 'a' ? a.name : b.name);
          lines.push(`<span class="mp-vlan-blocked">${row}  (${where})</span>`);
        } else lines.push(`<span class="mp-vlan-pass">${row}</span>`);
      }
      if (!all) {
        // Behind a button, not truncated outright: a 200-VLAN trunk pushed
        // Last seen off the bottom of a pane the operator can't resize.
        lines.push(`<button data-show-all-vlans>Show all ${vlans.length}</button>`);
      }
    }
    const fiberText = fiberModeText(link, escape(a.name), escape(b.name));
    const stpText = stpBlockingText(link, escape(a.name), escape(b.name), escape, false)
      || stpIdleText(link, escape(a.name), escape(b.name), escape);
    if (fiberText || stpText) lines.push('', ...[fiberText, stpText].filter(Boolean));
    if (view.selectedVlan !== null && (plan.vlans || []).includes(view.selectedVlan)) {
      lines.push('', vlanEndsText(link, view.selectedVlan, escape));
    }
    lines.push('', `Last seen   ${escape(App.ago(link.seen_ts))}`);
    return lines.join('\n');
  }

  // Six swatches, not the VLAN table's sixteen: a frame's colour is a
  // fixed palette index (mapperdb validates 0-5), not a VLAN's free-form
  // --canvas-vlan-N choice — --canvas-vlan-1..6 supplies the six hues so a
  // frame reads with the same canvas-tuned palette a VLAN strand does.
  // The three sizes mapperdb validates 0-2, shared by a frame's label and a
  // note's text. dy is a frame label's baseline: one fixed value would clip
  // Large. fs is the token app.css's mp-frame-t*/mp-note-t* rules use, so a
  // note wraps against the same font it is drawn in.
  const TEXT_SIZES = [
    { label: 'S', dy: 15, fs: '--fs-2xs' },
    { label: 'M', dy: 17, fs: '--fs-xs' },
    { label: 'L', dy: 22, fs: '--fs-xl' },
  ];

  function textSizeIndex(item) {
    const n = Number(item.text_size);
    return Number.isInteger(n) && n >= 0 && n < TEXT_SIZES.length ? n : 1;
  }

  // Same row, gate and shape as frameSwatchesHtml; letters, not colours.
  // `attr` is data-frame-textsize or data-note-textsize, whichever pane asks.
  function textSizesHtml(item, attr, canWrite) {
    const current = textSizeIndex(item);
    return TEXT_SIZES.map((size, i) =>
      `<button class="mp-textsize${current === i ? ' selected' : ''}" ${attr}="${i}" ` +
      `data-requires-write="mapper"${canWrite ? '' : ' disabled'} ` +
      `aria-label="Text size ${escape(size.label)}">${escape(size.label)}</button>`).join('');
  }

  function frameSwatchesHtml(frame, canWrite) {
    return Array.from({ length: 6 }, (_, i) => {
      const selected = Number(frame.color) === i;
      return `<button class="mp-swatch${selected ? ' selected' : ''}" data-frame-color="${i}" ` +
        `data-requires-write="mapper"${canWrite ? '' : ' disabled'} ` +
        `style="background:var(--canvas-vlan-${i + 1})" aria-label="Colour ${i + 1}"></button>`;
    }).join('');
  }

  function frameDetailHtml(frame) {
    const canWrite = App.canWrite('mapper');
    const gate = canWrite ? '' : ' disabled';
    const lines = [
      `Label       <input id="mpf-label" type="text" maxlength="60" value="${escape(frame.label || '')}" ` +
        `placeholder="Frame" data-requires-write="mapper"${gate}> ` +
        `<button id="mpf-label-save" data-requires-write="mapper"${gate}>Save</button>`,
      '',
      `Colour      ${frameSwatchesHtml(frame, canWrite)}`,
      '',
      `Text size   ${textSizesHtml(frame, 'data-frame-textsize', canWrite)}`,
      '',
      `Added       ${escape(App.ago(frame.added_ts))}`,
      '',
      `<button id="mpf-remove" class="danger" data-requires-write="mapper"${gate}>Remove</button>`,
    ];
    return lines.join('\n');
  }

  // The note analogue of frameSwatchesHtml -- same six swatches, same palette.
  function noteSwatchesHtml(note, canWrite) {
    return Array.from({ length: 6 }, (_, i) => {
      const selected = Number(note.color) === i;
      return `<button class="mp-swatch${selected ? ' selected' : ''}" data-note-color="${i}" ` +
        `data-requires-write="mapper"${canWrite ? '' : ' disabled'} ` +
        `style="background:var(--canvas-vlan-${i + 1})" aria-label="Colour ${i + 1}"></button>`;
    }).join('');
  }

  function noteDetailHtml(note) {
    const canWrite = App.canWrite('mapper');
    const gate = canWrite ? '' : ' disabled';
    const anchor = noteAnchorNode(note);
    const lines = [
      `Text        <textarea id="mpn-text" maxlength="500" rows="3" ` +
        `data-requires-write="mapper"${gate}>${escape(note.text || '')}</textarea> ` +
        `<button id="mpn-text-save" data-requires-write="mapper"${gate}>Save</button>`,
      '',
      `Colour      ${noteSwatchesHtml(note, canWrite)}`,
      '',
      `Text size   ${textSizesHtml(note, 'data-note-textsize', canWrite)}`,
      '',
    ];
    if (anchor) lines.push(`Anchored to ${escape(resolveNode(anchor).name)}`, '');
    lines.push(
      `Added       ${escape(App.ago(note.added_ts))}`,
      '',
      `<button id="mpn-remove" class="danger" data-requires-write="mapper"${gate}>Remove</button>`,
    );
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

  // The same debounce/retry idiom as queuePositionWrite/flushPositionWrites
  // above, one timer per FRAME rather than one shared timer for every
  // node: a frame write is its own PUT (no batched `updates` route exists
  // for frames), so two frames dragged one after another must not have the
  // second cancel the first's still-pending save.
  function queueFrameWrite(id, patch) {
    view.pendingFramePatches.set(id, { ...view.pendingFramePatches.get(id), ...patch });
    const existing = view.frameWriteTimers.get(id);
    if (existing) clearTimeout(existing);
    view.frameWriteTimers.set(id, setTimeout(() => flushFrameWrite(id), WRITE_DEBOUNCE_MS));
  }

  async function flushFrameWrite(id) {
    view.frameWriteTimers.delete(id);
    const patch = view.pendingFramePatches.get(id);
    if (!patch || !view.mapId) return;
    const mapId = view.mapId;
    try {
      await App.put(`/api/mapper/maps/${mapId}/frames/${id}`, patch);
      // Only clear it if nothing newer queued while this PUT was in flight.
      if (view.pendingFramePatches.get(id) === patch) view.pendingFramePatches.delete(id);
    } catch (error) {
      App.toast(`Could not save the frame: ${error.message}. Will retry.`, 'fail');
      const retrying = view.frameWriteRetryTimers.get(id);
      if (retrying) clearTimeout(retrying);
      view.frameWriteRetryTimers.set(id, setTimeout(() => flushFrameWrite(id), WRITE_RETRY_MS));
    }
  }

  // The same debounce/retry idiom, one timer per NOTE.
  function queueNoteWrite(id, patch) {
    view.pendingNotePatches.set(id, { ...view.pendingNotePatches.get(id), ...patch });
    const existing = view.noteWriteTimers.get(id);
    if (existing) clearTimeout(existing);
    view.noteWriteTimers.set(id, setTimeout(() => flushNoteWrite(id), WRITE_DEBOUNCE_MS));
  }

  async function flushNoteWrite(id) {
    view.noteWriteTimers.delete(id);
    const patch = view.pendingNotePatches.get(id);
    if (!patch || !view.mapId) return;
    const mapId = view.mapId;
    try {
      await App.put(`/api/mapper/maps/${mapId}/notes/${id}`, patch);
      if (view.pendingNotePatches.get(id) === patch) view.pendingNotePatches.delete(id);
    } catch (error) {
      App.toast(`Could not save the note: ${error.message}. Will retry.`, 'fail');
      const retrying = view.noteWriteRetryTimers.get(id);
      if (retrying) clearTimeout(retrying);
      view.noteWriteRetryTimers.set(id, setTimeout(() => flushNoteWrite(id), WRITE_RETRY_MS));
    }
  }

  // Selecting a frame (the stroke, the label or the handle all start this)
  // clears whatever else was selected, same as onNodePointerDown does in
  // reverse; the handle starts a RESIZE, everything else starts a MOVE.
  function onFramePointerDown(event, frame, mode) {
    if (event.button !== 0 || !event.isPrimary || view.spaceHeld || view.framing || view.noting) return;
    event.preventDefault();
    event.stopPropagation();
    focusCanvas();
    selectFrameInPlace(frame);
    if (!App.canWrite('mapper')) return;   // selection only: nothing to drag
    const target = event.currentTarget;
    target.setPointerCapture(event.pointerId);
    const startRect = { x: frame.x, y: frame.y, width: frame.width, height: frame.height };
    const rect = App.el('mp-svg').getBoundingClientRect();
    const perPixelX = (view.frame.width / Math.max(rect.width, 1)) / view.zoom;
    const perPixelY = (view.frame.height / Math.max(rect.height, 1)) / view.zoom;
    const startClient = { x: event.clientX, y: event.clientY };
    view.frameDrag = { id: frame.id, mode, startRect, dx: 0, dy: 0, moved: false };
    App.hideTooltip();
    const move = (moveEvent) => {
      if (!view.frameDrag) return;
      const cdx = moveEvent.clientX - startClient.x, cdy = moveEvent.clientY - startClient.y;
      if (!view.frameDrag.moved) {
        if (Math.hypot(cdx, cdy) <= MOVE_THRESHOLD_PX) return;
        view.frameDrag.moved = true;
      }
      view.frameDrag.dx = cdx * perPixelX;
      view.frameDrag.dy = cdy * perPixelY;
      requestFrameDragDraw();
    };
    const detach = () => {
      target.removeEventListener('pointermove', move);
      target.removeEventListener('pointerup', up);
      target.removeEventListener('pointercancel', cancel);
    };
    const up = () => {
      try {
        if (view.frameDrag && view.frameDrag.moved) {
          const snap = !!view.settings.snap_to_grid;
          const r = liveFrameRect(frame);
          let patch;
          if (mode === 'move') {
            let x = r.x, y = r.y;
            if (snap) { x = snapValue(x); y = snapValue(y); }
            frame.x = x; frame.y = y;
            patch = { x, y };
          } else {
            let width = r.width, height = r.height;
            if (snap) { width = Math.max(FRAME_MIN, snapValue(width)); height = Math.max(FRAME_MIN, snapValue(height)); }
            frame.width = width; frame.height = height;
            patch = { width, height };
          }
          queueFrameWrite(frame.id, patch);
        }
      } finally {
        detach();
        view.frameDrag = null;
        requestDraw();
        drawDetail();
      }
    };
    const cancel = () => { detach(); view.frameDrag = null; requestDraw(); };
    target.addEventListener('pointermove', move);
    target.addEventListener('pointerup', up);
    target.addEventListener('pointercancel', cancel);
  }

  // The note analogue of onFramePointerDown.
  function onNotePointerDown(event, note, mode) {
    if (event.button !== 0 || !event.isPrimary || view.spaceHeld || view.framing || view.noting) return;
    event.preventDefault();
    event.stopPropagation();
    focusCanvas();
    selectNoteInPlace(note);
    if (!App.canWrite('mapper')) return;   // selection only: nothing to drag
    const target = event.currentTarget;
    target.setPointerCapture(event.pointerId);
    const startRect = { x: note.x, y: note.y, width: note.width, height: note.height };
    const rect = App.el('mp-svg').getBoundingClientRect();
    const perPixelX = (view.frame.width / Math.max(rect.width, 1)) / view.zoom;
    const perPixelY = (view.frame.height / Math.max(rect.height, 1)) / view.zoom;
    const startClient = { x: event.clientX, y: event.clientY };
    view.noteDrag = { id: note.id, mode, startRect, dx: 0, dy: 0, moved: false };
    App.hideTooltip();
    const move = (moveEvent) => {
      if (!view.noteDrag) return;
      const cdx = moveEvent.clientX - startClient.x, cdy = moveEvent.clientY - startClient.y;
      if (!view.noteDrag.moved) {
        if (Math.hypot(cdx, cdy) <= MOVE_THRESHOLD_PX) return;
        view.noteDrag.moved = true;
      }
      view.noteDrag.dx = cdx * perPixelX;
      view.noteDrag.dy = cdy * perPixelY;
      requestNoteDragDraw();
    };
    const detach = () => {
      target.removeEventListener('pointermove', move);
      target.removeEventListener('pointerup', up);
      target.removeEventListener('pointercancel', cancel);
    };
    const up = () => {
      try {
        if (view.noteDrag && view.noteDrag.moved) {
          const snap = !!view.settings.snap_to_grid;
          const r = liveNoteRect(note);
          let patch;
          if (mode === 'move') {
            let x = r.x, y = r.y;
            if (snap) { x = snapValue(x); y = snapValue(y); }
            note.x = x; note.y = y;
            patch = { x, y };
          } else {
            let width = r.width, height = r.height;
            if (snap) { width = Math.max(FRAME_MIN, snapValue(width)); height = Math.max(FRAME_MIN, snapValue(height)); }
            note.width = width; note.height = height;
            patch = { width, height };
          }
          queueNoteWrite(note.id, patch);
        }
      } finally {
        detach();
        view.noteDrag = null;
        requestDraw();
        drawDetail();
      }
    };
    const cancel = () => { detach(); view.noteDrag = null; requestDraw(); };
    target.addEventListener('pointermove', move);
    target.addEventListener('pointerup', up);
    target.addEventListener('pointercancel', cancel);
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
    if (event.target.closest('.mp-node') || event.target.closest('.mp-link, .mp-link-hit')) return;
    if (view.framing) {
      // Reuses the rubber-band gesture wholesale (onSvgPointerMove/Up and
      // drawRubber read view.rubber generically) — only the `drawFrame`
      // flag and what pointerup does with the finished rectangle differ
      // from an ordinary multi-select drag.
      const p = scenePoint(event);
      if (!p) return;
      event.preventDefault();
      focusCanvas();
      event.currentTarget.setPointerCapture(event.pointerId);
      view.rubber = { x0: p.x, y0: p.y, x1: p.x, y1: p.y, drawFrame: true };
      return;
    }
    if (view.noting) {
      // The Note tool's own armed drag — same rubber-band reuse as framing
      // above, distinguished by `drawNote` instead of `drawFrame`.
      const p = scenePoint(event);
      if (!p) return;
      event.preventDefault();
      focusCanvas();
      event.currentTarget.setPointerCapture(event.pointerId);
      view.rubber = { x0: p.x, y0: p.y, x1: p.x, y1: p.y, drawNote: true };
      return;
    }
    if (view.dragPans) {
      event.preventDefault();
      focusCanvas();
      event.currentTarget.setPointerCapture(event.pointerId);
      view.panDrag = { x: event.clientX, y: event.clientY, pan: { ...view.pan } };
      App.el('mp-svg').classList.add('dragging');
      return;
    }
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
    if (view.rubber && view.rubber.drawFrame) {
      const { x0, y0, x1, y1 } = view.rubber;
      view.rubber = null;
      drawRubber();
      disarmFraming();   // one shot: a click without drag disarms the same way
      const x = Math.min(x0, x1), y = Math.min(y0, y1);
      const width = Math.abs(x1 - x0), height = Math.abs(y1 - y0);
      if (width >= FRAME_MIN && height >= FRAME_MIN) createFrame(x, y, width, height);
      return;
    }
    if (view.rubber && view.rubber.drawNote) {
      const { x0, y0, x1, y1 } = view.rubber;
      view.rubber = null;
      drawRubber();
      const anchorId = view.notingAnchorId;
      disarmNoting();   // one shot: a click without drag disarms the same way
      const x = Math.min(x0, x1), y = Math.min(y0, y1);
      const width = Math.abs(x1 - x0), height = Math.abs(y1 - y0);
      if (width >= FRAME_MIN && height >= FRAME_MIN) createNote(x, y, width, height, anchorId);
      return;
    }
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

  // Un-arms the Frame tool: the toolbar button loses its pressed look and
  // the canvas its crosshair. Called whichever way framing ends — a
  // finished drag, a click with no drag, or Escape.
  function disarmFraming() {
    view.framing = false;
    const btn = App.el('mp-add-frame');
    if (btn) btn.classList.remove('active');
    const canvas = App.el('mp-canvas');
    if (canvas) canvas.classList.remove('framing');
    // Escape and a click-with-no-drag both disarm through here rather than
    // the toolbar button — an empty map must fall back to the placeholder
    // the same way the button's own disarm does.
    requestDraw();
  }

  // The Note-tool analogue of disarmFraming.
  function disarmNoting() {
    view.noting = false;
    view.notingAnchorId = null;
    const btn = App.el('mp-add-note');
    if (btn) btn.classList.remove('active');
    const canvas = App.el('mp-canvas');
    if (canvas) canvas.classList.remove('noting');
    requestDraw();
  }

  async function createFrame(x, y, width, height) {
    try {
      await App.post(`/api/mapper/maps/${view.mapId}/frames`, { x, y, width, height });
      await loadMapData();
    } catch (error) {
      App.toast(`Could not add the frame: ${error.message}`, 'fail');
    }
  }

  // nodeId: the anchor captured when the Note tool was armed (exactly one
  // node selected at that moment), or null for an unanchored note.
  async function createNote(x, y, width, height, nodeId) {
    try {
      const body = { x, y, width, height };
      if (nodeId !== null && nodeId !== undefined) body.node_id = nodeId;
      await App.post(`/api/mapper/maps/${view.mapId}/notes`, body);
      await loadMapData();
    } catch (error) {
      App.toast(`Could not add the note: ${error.message}`, 'fail');
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
    if ((event.key === 'Delete' || event.key === 'Backspace') && view.selectedFrameId) {
      event.preventDefault();
      removeFrame(view.selectedFrameId);
      return;
    }
    if ((event.key === 'Delete' || event.key === 'Backspace') && view.selectedNoteId) {
      event.preventDefault();
      removeNote(view.selectedNoteId);
      return;
    }
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

  // Escape disarms the Frame tool from wherever focus is — the toolbar
  // button most of the time, since clicking it is what armed framing in
  // the first place, not necessarily the canvas itself.
  function wireFrameEscape() {
    window.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || App.state.tab !== 'mapper' || !view.framing) return;
      if (!App.el('modal').hidden) return;
      view.rubber = null;
      disarmFraming();
      drawRubber();
    });
  }

  // The Note-tool analogue of wireFrameEscape.
  function wireNoteEscape() {
    window.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || App.state.tab !== 'mapper' || !view.noting) return;
      if (!App.el('modal').hidden) return;
      view.rubber = null;
      disarmNoting();
      drawRubber();
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

  // The one selected node, when it is a real device -- not a placeholder,
  // an unmanaged peer, or one Nodes has since removed -- what the Mapper
  // strip's SSH/WEB buttons act on.
  function selectedDevice() {
    if (view.selection.size !== 1) return null;
    const node = nodeById([...view.selection][0]);
    if (!node || node.placeholder || node.unmanaged || node.missing) return null;
    return (node.device_id !== null && node.device_id !== undefined) ? node : null;
  }

  function drawToolbarState() {
    const canWrite = App.canWrite('mapper');
    const hasMap = view.mapId !== null;
    const device = selectedDevice();
    // Compared before assigning, for the reason App.setText/setHidden exist:
    // fastTick runs this ten times a second and an unconditional write
    // queues a real mutation even when the value is already there. There is
    // no App.setDisabled to borrow.
    const states = [
      ['mp-remove-node', !canWrite || (view.selection.size === 0
        && !view.selectedFrameId && !view.selectedNoteId)],
      ['mp-connect', !canWrite || view.selection.size !== 2],
      ['mp-align', !canWrite || view.selection.size < 2],
      ['mp-add-device', !canWrite || !hasMap],
      ['mp-add-neighbours', !canWrite || !hasMap],
      ['mp-add-placeholder', !canWrite || !hasMap],
      ['mp-add-frame', !canWrite || !hasMap],
      ['mp-add-note', !canWrite || !hasMap],
      ['mp-snap', !canWrite || !hasMap],
      ['mp-ssh-device', !App.canWrite('ssh') || !device],
      ['mp-web-device', !App.canWrite('web') || !(device || {}).ip],
    ];
    for (const [id, disabled] of states) {
      const button = App.el(id);
      if (button && button.disabled !== disabled) button.disabled = disabled;
    }
    // Write revoked (or the map changed out) mid-arm: nothing left to draw
    // a frame or note onto, so the tool disarms rather than staying pressed.
    if (view.framing && (!canWrite || !hasMap)) disarmFraming();
    if (view.noting && (!canWrite || !hasMap)) disarmNoting();
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
        drawLegend();
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
    const props = ['fill', 'stroke', 'color', 'stop-color', 'stroke-width', 'paint-order', 'stroke-linejoin',
      'font-family', 'font-size', 'font-weight', 'text-anchor', 'letter-spacing',
      'opacity', 'fill-opacity', 'stroke-opacity', 'stroke-dasharray', 'dominant-baseline', 'filter'];
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
      // A fiber link mid-pulse could be caught at its dim end; the export
      // always wants it at full glow, not whatever opacity happened to be
      // on screen the instant Export PNG was clicked.
      if (liveEls[i].classList.contains('fiber')) cloneEls[i].style.setProperty('stroke-opacity', '1');
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
    // Targets 4x for a crisp PNG at any zoom level -- drawImage still
    // targets the CSS size, so the scale-up happens once, on the canvas
    // backing store, not in the image -- backed off only as far as a
    // conservative browser canvas guard (no side over 16384px, total area
    // under ~268 Mpx) demands, and never below today's own
    // Math.min(window.devicePixelRatio || 1, 2): a huge map degrades to the
    // old resolution rather than to a canvas the browser refuses to paint.
    const MAX_CANVAS_SIDE = 16384;
    const MAX_CANVAS_AREA = 268000000;
    const dprScale = Math.min(window.devicePixelRatio || 1, 2);
    const guardScale = Math.min(MAX_CANVAS_SIDE / width, MAX_CANVAS_SIDE / height,
      Math.sqrt(MAX_CANVAS_AREA / (width * height)));
    const scale = Math.max(dprScale, Math.min(4, guardScale));
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = width * scale; canvas.height = height * scale;
      const ctx = canvas.getContext('2d');
      ctx.scale(scale, scale);
      ctx.drawImage(img, 0, 0, width, height);
      URL.revokeObjectURL(url);
      canvas.toBlob((blob) => {
        if (!blob) { App.toast('Could not render the map to PNG.', 'fail'); return; }
        App.download(blob, `${(view.map && view.map.name) || 'map'}.png`);
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
    wireFrameEscape();
    wireNoteEscape();
    App.el('mp-find').addEventListener('keydown', onFindKeydown);
    App.el('mp-find').addEventListener('input', onFindInput);
    App.el('mp-find').addEventListener('blur', onFindBlur);
    App.el('mp-find-list').addEventListener('pointerdown', onFindListPointerdown);
    App.el('mp-find-list').addEventListener('click', onFindListClick);
    document.addEventListener('pointerdown', onFindOutsideClick);
    App.el('mp-add-frame').onclick = () => {
      if (!App.canWrite('mapper') || !view.mapId) return;
      if (view.noting) disarmNoting();
      view.framing = !view.framing;
      App.el('mp-add-frame').classList.toggle('active', view.framing);
      App.el('mp-canvas').classList.toggle('framing', view.framing);
      // Arming on an empty map swaps the placeholder for the real canvas
      // (see draw()'s gate above); disarming without drawing a frame must
      // bring the placeholder back the same way.
      requestDraw();
    };
    App.el('mp-add-note').onclick = () => {
      if (!App.canWrite('mapper') || !view.mapId) return;
      if (view.framing) disarmFraming();
      view.noting = !view.noting;
      // The anchor is the operator's choice at THIS moment: exactly one
      // node selected when the tool is armed, never re-derived later.
      view.notingAnchorId = view.noting && view.selection.size === 1 ? [...view.selection][0] : null;
      App.el('mp-add-note').classList.toggle('active', view.noting);
      App.el('mp-canvas').classList.toggle('noting', view.noting);
      requestDraw();
    };

    App.el('mp-refresh').onclick = () => App.runJob(App.el('mp-refresh'),
      { queued: 'Refreshing…', done: 'Refreshed' }, forceRefresh());
    App.el('mp-maps').onclick = mapsDialog;
    // The dialog is its own file (mapper_upstream.js), fetched on first use.
    App.el('mp-upstream-suggestions').onclick = () => App.loadExtra('mapper_upstream')
      .then(() => App.extras.mapperUpstream.dialog())
      .catch((error) => App.toast(`Could not open upstream suggestions: ${error.message}`, 'fail'));
    App.el('mp-settings').onclick = settingsDialog;
    App.el('mp-ssh-device').onclick = () => {
      const n = selectedDevice();
      if (n && App.canWrite('ssh')) App.openSshWindow(n.device_id, n.name);
    };
    App.el('mp-web-device').onclick = () => {
      const n = selectedDevice();
      if (n && App.canWrite('web')) App.openWebTunnel(n.device_id);
    };
    App.el('mp-map').onchange = (event) => selectMap(Number(event.target.value));
    App.el('mp-add-device').onclick = openAddDevice;
    App.el('mp-add-neighbours').onclick = openAddNeighbours;
    App.el('mp-add-placeholder').onclick = openAddPlaceholder;
    App.el('mp-remove-node').onclick = removeSelected;
    App.el('mp-connect').onclick = openConnect;
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
    try { view.dragPans = localStorage.getItem('mapper.dragPans') === '1'; } catch (error) { view.dragPans = false; }
    App.el('mp-drag-pans').checked = view.dragPans;
    App.el('mp-drag-pans').onchange = (event) => {
      view.dragPans = event.target.checked;
      try { localStorage.setItem('mapper.dragPans', view.dragPans ? '1' : '0'); } catch (error) { /* per-browser convenience only */ }
    };
    try { view.fiberView = localStorage.getItem('mapper.fiberView') === '1'; } catch (error) { view.fiberView = false; }
    App.el('mp-fiberview').checked = view.fiberView;
    applyFiberView();
    App.el('mp-fiberview').onchange = (event) => {
      view.fiberView = event.target.checked;
      try { localStorage.setItem('mapper.fiberView', view.fiberView ? '1' : '0'); } catch (error) { /* per-browser convenience only */ }
      applyFiberView();
      drawLegend();
      requestDraw();
    };
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
      view.frameDrag = null; view.noteDrag = null;
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
    // app.js dispatches this on a theme switch; with loadMapData now
    // skipping the redraw on an unchanged payload, this is the only path
    // left that picks up the new font on the canvas.
    window.addEventListener('theme-changed', () => requestDraw());
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

  App.pages.mapper = {
    // The legend only changes with the map's data, so loadMapData()/
    // activate() draw it, not fastTick (which ran every beat before).
    init, refresh, activate, fastTick,
  };
})();

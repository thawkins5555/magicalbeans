/* The NetFlow page: collector status, stacked traffic chart, top-N bars and
   the flow record table. */
(() => {
  /* The categorical palette for stacked bands, top-N bars and their legend.

     The set this replaces was ten colours picked by eye. Two of them were
     the accent and the muted grey — the colours that mean "interactive"
     and "no data" everywhere else in the application — and the rest were
     never checked against the one thing a stacked chart has to survive:
     telling a band from the band it touches.

     Measured, simulating protanopia and comparing in Lab: the old set's
     closest ADJACENT pair was 11.3 apart and its lightness spread 15
     points, so bands blurred into each other and the brighter series read
     as more important. This one is 32.8 apart at its closest adjacent pair
     with a 7-point lightness band, and every entry clears 3:1 against the
     panel it is drawn on (lowest 4.7).

     Honest limit: with eight categories, two NON-adjacent entries still
     come within 5.5 of each other under simulation — closer than the pair
     they replace. Bands that touch are what the eye compares in a stack,
     and the legend and the hover tooltip both carry a swatch beside the
     name for the rest. Eight rather than ten because eight is near the
     limit of what anyone matches against a legend, and the server already
     folds the ninth series onwards into "Other". */
  const SERIES = [1, 2, 3, 4, 5, 6, 7, 8].map((n) => `var(--cat-${n})`);
  // "Other", and anything past the eighth series: deliberately the neutral
  // that means "nothing of its own" in the donuts too, not a ninth hue.
  const OTHER = 'var(--data-neutral)';

  /* One place decides a series' colour. The stacked bands, the legend, the
     tooltip and the top-N bars all read it from here, so a swatch always
     names the band the cursor is actually over. `index` is the series'
     position in data.series — never its position after any sorting the
     caller does. Past the palette it is OTHER, never a wrap back round to
     the first hue: a ninth entry painted --cat-1 claims a match with the
     first band that does not exist. */
  const isOther = (name) => String(name).startsWith('\u2014');
  const seriesColor = (name, index) =>
    (isOther(name) || index >= SERIES.length ? OTHER : SERIES[index]);

  /* How many bands the chart drew with a hue of their own — the response's
     series less "— other —". Read off the response rather than written
     down here as 8, so a top-N row past this count is swatched neutral
     whatever the server's limit is set to. */
  const namedBands = (data) =>
    ((data && data.series) || []).filter((series) => !isOther(series.name)).length;

  /* What a top-N row past that count says for itself, in its tooltip and
     in its accessible description: the chart put it inside "— other —",
     and a neutral swatch alone leaves that to be deduced. */
  const FOLDED_TEXT = 'Folded into \u2014 other \u2014 in the chart above';
  const PROTOCOLS = [['Any protocol', ''], ['TCP', 6], ['UDP', 17], ['ICMP', 1],
                     ['GRE', 47], ['ESP', 50], ['OSPF', 89]];
  const PAD = { left: 62, right: 12, top: 14, bottom: 26 };

  /* The narrowest drag-selection the chart accepts, in seconds and on
     screen. It used to be one bucket of the response on screen, and that
     bucket is the PREVIOUS window's, chosen for that window's span — six
     hours each on a 30-day chart — so any selection narrower than it did
     nothing at all, with no word said. A few seconds is what the server's
     own ladder (api._flow_bucket) can answer with a finer bucket, which is
     what the ladder exists for; the pixel floor is what tells a click with
     a wobble in it from a drag, since on a wide chart one pixel is already
     many minutes. applyWindow widens anything under a minute. */
  const DRAG_MIN_S = 3;
  const DRAG_MIN_PX = 4;

  // One sentence for "nothing matched the window/filters" — the chart, the
  // top-talker bars and the record table used to each say this their own
  // way (an SVG text node, a bare <p class="hint">, and a table silently
  // rendering its header over an empty tbody with no word said at all).
  const NO_FLOWS_TEXT = 'No flows match this window and filters. Widen the ' +
    'time window or clear a filter.';
  // The same word App.loading() puts in every other pane still waiting on a
  // fetch; here it also has to reach the chart, which is an SVG.
  const LOADING_TEXT = 'Loading…';
  // A fetch that never answered is not an empty window, so NO_FLOWS_TEXT here
  // would put words in a server's mouth: a 400 from a filter it refuses would
  // read as "the window is quiet". What broke is the connection status's
  // sentence to tell; all these three panes owe an operator is to stop saying
  // "Loading…" for a load that has already stopped.
  const FAILED_TEXT = 'Could not load flows for this window. The next refresh '
    + 'will try again.';

  // Records-only history (A: the operator's report): a view answered from
  // the raw records alone cannot reach back as far as the summaries do. A
  // window wholly before that reach is not "no flows match". The hint only
  // helps when a source/destination/port/protocol filter caused it.
  const recordsOnlyEmptyText = (data) => {
    const f = filters();
    const hint = f.src || f.dst || f.port || f.protocol
      ? ' Filter by exporter or interface for summary-backed history.' : '';
    return `No records kept before ${App.stamp(data.records_from)}; this view `
      + `is answered from records only.${hint}`;
  };

  const view = {
    t0: Date.now() / 1000 - 3600,
    t1: Date.now() / 1000,
    follow: true,
    data: null,
    records: [],
    fetchedAt: null,
    drag: null,
    windowTimer: null,
    request: 0,
    abort: null,
    loading: false,
    // Only ever set out of a blanked (loading) pane, so a failure never has
    // to decide whether the data underneath it is still worth showing --
    // showLoading has already taken that decision.
    failed: false,
    // Which of the three subtabs is on screen (Plixer-style rebuild): only
    // EXPORTERS/INTERFACES read this, to fetch on the poll while they are
    // the one showing rather than on every tick regardless.
    sub: 'traffic',
    // The exporter nf-iface's options were last built for, so a poll tick
    // that sees the same choice again does not refetch the interface list.
    ifaceExporter: '',
    exporters: [],
  };

  // Which of the four sentences a pane with nothing to draw is telling: the
  // fourth (recordsOnlyEmptyText) only when the window asked for lies
  // wholly before the records this filter can reach — genuinely empty is
  // still NO_FLOWS_TEXT.
  const emptyMessage = () => {
    if (view.loading) return LOADING_TEXT;
    if (view.failed) return FAILED_TEXT;
    const data = view.data;
    if (data && data.records_only && data.records_from != null
        && view.t1 <= data.records_from) {
      return recordsOnlyEmptyText(data);
    }
    return NO_FLOWS_TEXT;
  };

  const escape = App.escapeHtml;

  const ago = App.ago;
  const niceCeiling = App.niceCeiling;
  const extraCounterParts = App.extraCounterParts;

  // How many flow records the table asks the server for. The select's three
  // labels and its title are written from this in init(), so the number
  // lives in one place instead of four copies of "250" in the markup.
  const RECORD_LIMIT = 250;

  /* The server orders by volume over the most recent slice of the table
     rather than all of it (flowdb.FLOW_SCAN_CAP), because the sort key is
     bytes times a sampling rate that is rewritten after the fact and so
     cannot be indexed. Said out loud when the bound actually bit, rather
     than letting the list imply it searched every record in the window. */
  const ORDER_TITLE =
    `Which ${RECORD_LIMIT} records the server returns. Click a column heading to arrange them.`;
  const SCAN_BOUNDED_NOTE =
    ' These are the heaviest records from the most recent flows in this window,'
    + ' not from every one of them.';

  function showWindow() {
    const span = view.t1 - view.t0;
    App.el('nf-window').textContent =
      `${App.stamp(view.t0, span)} – ${App.stamp(view.t1, span)}`;
  }

  /* Long enough to swallow a gesture, short enough that one click on Reset
     still reads as an immediate answer — the busy line app.css draws at
     400 ms, and the Loading state below, carry the rest of the wait. */
  const REFETCH_MS = 250;

  /* The window an operator has just left is not worth finishing. Its two
     queries hold the same flow-database lock the collector writes flows
     through, and the token check in refresh() only hides a stale answer in
     the browser — the server had already computed it. The token is bumped
     here as well as aborted, for the pair that answered a moment before. */
  function dropInFlight() {
    view.request += 1;
    if (view.abort) { view.abort.abort(); view.abort = null; }
    if (view.windowTimer) clearTimeout(view.windowTimer);
    view.windowTimer = null;
  }

  /* Every change of view is collapsed into one fetch a quarter-second after
     the last of them — not just the wheel's, which was the only caller that
     ever asked. The wheel fires several events per zoom gesture, but so does
     stepping the range dropdown from 15m to 30d, and holding a zoom or pan
     button: each step used to launch a full overview + records pair over an
     ever wider window, so the dozen nobody wanted queued on the flow
     database ahead of the one they did. The window itself still moves on
     every event, so the label tracks the gesture live. */
  function requestFetch(windowChanged) {
    dropInFlight();
    view.windowTimer = setTimeout(() => {
      view.windowTimer = null;
      // Only once the burst has settled and this fetch is really going:
      // blanking the chart on every wheel event would take away the picture
      // the gesture is aiming with.
      if (windowChanged) showLoading();
      App.refreshNow('netflow');
    }, REFETCH_MS);
  }

  // The window, with no opinion about fetching it: init() sizes the first
  // window this way because activating the tab issues its first fetch a
  // moment later anyway, and asking here as well painted every open twice.
  function applyWindow(t0, t1, follow) {
    App.windowSet(view, App.el('nf-follow'), t0, t1, follow);
    showWindow();
  }

  function setWindow(t0, t1, follow) {
    applyWindow(t0, t1, follow);
    requestFetch(true);
  }

  const zoom = (factor) => App.windowZoom(view, factor, setWindow);
  const pan = (fraction) => App.windowPan(view, fraction, setWindow);

  // The span nf-range names, ending now.
  function rangeWindow() {
    const seconds = Number(App.el('nf-range').value) || 3600;
    const now = Date.now() / 1000;
    return [now - seconds, now];
  }

  function resetWindow() {
    const [t0, t1] = rangeWindow();
    setWindow(t0, t1, true);
  }

  /* A window change asks a different question, so the answer to the previous
     one stops being shown while the new one is fetched: a chart and a record
     table of the minutes an operator has just left read as the answer, and
     carry nothing that says otherwise. Scoped to the three views that are
     actually changing rather than modalling the page, and deliberately NOT
     the poll tick — re-reading the same window every two seconds must not
     blank the page it is refreshing. */
  function showLoading() {
    view.loading = true;
    view.failed = false;
    App.el('nf-totals').textContent = LOADING_TEXT;
    const overlay = App.el('nf-chart-loading');
    overlay.innerHTML = App.loadingMark();
    overlay.hidden = false;
    drawChart();
    drawBars();
    drawTable(view.records);
  }

  /* showLoading() puts "Loading…" in the three panes and only a refresh that
     COMPLETED ever took it back out, so a fetch that rejected -- a 400 from a
     filter the server refuses, an outage -- left the page reading "Loading…"
     for as long as the operator stayed on it. The error still leaves here:
     the connection status and the console report are runRefresh's job, and
     swallowing it would trade a stuck pane for a silent failure.

     A superseded abort is not a failure. The newer fetch it was abandoned
     for is still loading, and its answer is the one to show.

     Only the loading claim is retracted, never data. A poll tick that failed
     under a window already on screen leaves that window alone: it is still
     the answer to the question being asked, and blanking a working display
     over one missed poll is worse than the bug this fixes. */
  function loadFailed(error) {
    if ((error && error.superseded) || !view.loading) return;
    view.loading = false;
    view.failed = true;
    App.el('nf-totals').textContent = FAILED_TEXT;
    App.el('nf-chart-loading').hidden = true;
    drawChart();
    drawBars();
    drawTable(view.records);
  }

  function filters() {
    return {
      ...App.filterValues('nf', ['dimension', 'src', 'dst', 'port', 'protocol',
                                 'iface', 'direction']),
      // The exporter list is filled from the response below, so on the load
      // after a reload the restored choice is not on the element yet and the
      // first fetch would ignore it. Once the list exists the control answers
      // for itself, "All exporters" included — the old `value || saved` form
      // read an empty choice as "no answer" and re-sent the previous one.
      exporter: App.controlOrSaved('netflow', 'nf-exporter'),
    };
  }

  function exportFlowsCsv() {
    const f = filters();
    App.exportCsv('/api/netflow/records/export.csv', {
      t0: view.t0, t1: view.t1, src: f.src, dst: f.dst, port: f.port,
      protocol: f.protocol, exporter: f.exporter, iface: f.iface,
      direction: f.direction, order: App.el('nf-order').value,
    });
  }

  /* -------------------------------------------------------- exporter label

     The label every exporter picker on this page shows, named where
     namelookup resolved one, address-only otherwise (Symptom 1 in the
     plan): TRAFFIC's nf-exporter, INTERFACES' nf-if-exporter and the
     EXPORTERS table all read it from here, so the three cannot disagree
     about what a device is called. */
  function exporterLabel(item) {
    return item.name ? `${item.name} (${item.address}, v${item.version})`
                      : `${item.address} (v${item.version})`;
  }

  function exporterOptionsHtml(items) {
    const sorted = [...(items || [])].sort(
      (a, b) => exporterLabel(a).localeCompare(exporterLabel(b)));
    return '<option value="">All exporters</option>' + sorted.map((item) =>
      `<option value="${escape(item.address)}">${escape(exporterLabel(item))}</option>`
    ).join('');
  }

  /* --------------------------------------------------------- nf-iface/-direction

     Both only mean anything scoped to one exporter -- an interface index is
     only unique per device -- so both stay disabled and blank until
     nf-exporter names one, and reset the same way the moment it is cleared
     rather than going on filtering by an interface number nothing on screen
     names any more. */
  async function loadIfaceOptions(exporterAddress) {
    const iface = App.el('nf-iface');
    const direction = App.el('nf-direction');
    iface.disabled = !exporterAddress;
    direction.disabled = !exporterAddress;
    if (!exporterAddress) {
      iface.innerHTML = '<option value="">Any interface</option>';
      iface.value = '';
      App.rememberControl('netflow', 'nf-iface', '');
      direction.value = 'both';
      App.rememberControl('netflow', 'nf-direction', 'both');
      return;
    }
    const now = Date.now() / 1000;
    let data;
    try {
      data = await App.get('/api/netflow/interfaces',
        { exporter: exporterAddress, t0: now - 86400, t1: now });
    } catch (error) { return; }
    // A restored/previous choice survives the rebuild if it is still among
    // this exporter's interfaces; otherwise "Any interface" rather than a
    // number that would silently keep filtering by an interface gone from
    // the list.
    const current = iface.value || App.savedControl('netflow', 'nf-iface') || '';
    iface.innerHTML = '<option value="">Any interface</option>' +
      (data.interfaces || []).map((row) =>
        `<option value="${escape(String(row.if_index))}">${escape(row.name)}</option>`).join('');
    iface.value = [...iface.options].some((o) => o.value === current) ? current : '';
    if (iface.selectedIndex < 0) iface.value = '';
  }

  // Called on every nf-exporter change and on every refresh() poll; a no-op
  // once the interface list already matches the exporter on screen, so a
  // 2s poll tick does not refetch it every time.
  async function syncIfaceControls() {
    const exporterAddress = App.el('nf-exporter').value;
    if (exporterAddress === view.ifaceExporter) return;
    view.ifaceExporter = exporterAddress;
    await loadIfaceOptions(exporterAddress);
  }

  /* ------------------------------------------------------------- chart */

  // The end of the window the values were read over: the response's own
  // t1, not view.t1, which may already have moved on under a pending fetch.
  function windowEnd(data) {
    const times = data.times;
    return Number.isFinite(data.t1)
      ? data.t1 : times[times.length - 1] + data.bucket_s;
  }

  /* How many seconds of the window one slot of a response actually covers.
     Every slot but the last is a whole bucket; the last runs from its own
     start to the window's end and is almost always partial — flowdb sizes
     the window as int(span / bucket) + 1 slots, so the final slot starts
     on the last boundary before t1 and covers only what is left after it,
     which is nothing at all when t1 falls exactly on a boundary. Clamped
     to [0, bucket]: a slot cannot cover more than one bucket, and the
     zero is what slotCount reads to leave the empty slot undrawn. */
  function slotCovered(data, slot) {
    const last = data.times.length - 1;
    if (slot < last) return data.bucket_s;
    const covered = windowEnd(data) - data.times[last];
    return Math.min(Math.max(covered, 0), data.bucket_s);
  }

  /* The seconds a slot's bytes are divided by to make a rate.

     Dividing the final slot by the nominal bucket width drew a bucket a
     fifth full at a fifth of its true rate: a cliff at the right-hand edge
     of every chart, on exactly the newest data, and the hover confirmed
     the number. So the final slot is rated over the time it covers — but
     not all the way down to a sliver, because NetFlow credits a record's
     whole byte count to the second it ended: a five-second sliver holding
     the end of a minute-long 100 MB flow is not carrying 160 Mbps, and
     rating it over its five seconds would have said it was, in a spike
     that flickered on every refresh of a live window. The floor is a
     quarter of the bucket, whatever the bucket: any slot at least a
     quarter covered reads at its true rate, and the worst a slot can be
     over-read is 4x (flow ends credited to a sliver, rated over a quarter
     bucket), the same at ten seconds as at six hours. A floor in seconds
     could not promise that — the amplification would scale with the
     bucket, to 720x at an hour.

     Not padded out to a whole bucket either, which would invent empty
     future time and draw the same cliff on a live window. drawChart and
     slotTip both divide by this, so the chart and its tooltip cannot
     drift apart. */
  const SLOT_MIN_FRACTION = 0.25;

  function slotSeconds(data, slot) {
    return Math.max(slotCovered(data, slot), data.bucket_s * SLOT_MIN_FRACTION);
  }

  /* How many slots hold any of the window: all of them, unless t1 landed
     exactly on a bucket boundary, when flowdb's +1 puts a final slot AT
     the end of the window covering none of it. That slot is not drawn —
     its vertex would sit past the right-hand edge, and its value is zero
     unless a record ended on that very second — and the cursor never
     resolves to it. Never fewer than one: a zero-span window is one slot
     with nothing after it. */
  function slotCount(data) {
    const count = data.times.length;
    return count > 1 && slotCovered(data, count - 1) <= 0 ? count - 1 : count;
  }

  /* The chart's time axis: the window the server read, t0 to t1, mapped
     onto the plot's width. The slots used to be spread so that the last
     one sat on the right-hand edge with no width, which put every bucket
     one interval left of the time it held and left the newest one
     invisible; now t1 is the response's own windowEnd and the axis spans
     all of it. Built once per draw and handed to everything that turns a
     screen x into a time or a slot — the crosshair, the tooltip and the
     drag brush all go through the same three functions, so the slot named
     under the cursor is the slot whose time the cursor is over. Each
     slot's vertex sits at the centre of the time it covers — for the
     final, partial slot the centre of what it covers so far, which is
     slotCovered and never slotSeconds: the rate floor must not push the
     vertex past the window's end. */
  function axisOf(data, plot) {
    const t0 = data.times[0];
    const t1 = windowEnd(data);
    const count = slotCount(data);
    const axisSpan = Math.max(t1 - t0, 1e-6);
    const xOf = (ts) => plot.x + (ts - t0) / axisSpan * plot.w;
    const timeAt = (x) =>
      t0 + Math.min(Math.max((x - plot.x) / plot.w, 0), 1) * axisSpan;
    const slotAt = (ts) =>
      Math.min(Math.max(Math.floor((ts - t0) / data.bucket_s), 0), count - 1);
    const middleOf = (slot) => data.times[slot] + slotCovered(data, slot) / 2;
    return { t0, t1, count, xOf, timeAt, slotAt, middleOf };
  }

  /* The chart carries too many time buckets for one tab stop each (a wide
     window is hundreds of them), so the container is the one stop and the
     same keys the pan/zoom/reset buttons already run answer to it directly
     — panning IS how a keyboard user moves between buckets here, and
     showFocusTip re-announces the totals after every move. A discrete
     per-bucket walk would only fight those keys for the arrows. */
  function showFocusTip(container) {
    if (document.activeElement !== container) return;
    const box = container.getBoundingClientRect();
    App.tooltip(App.el('nf-totals').textContent || NO_FLOWS_TEXT,
      { clientX: box.left + box.width / 2, clientY: box.top + 24 });
  }

  function drawChart() {
    const container = App.el('nf-chart');
    const svg = App.el('nf-chart-svg');
    const box = container.getBoundingClientRect();
    const width = Math.max(box.width, 300), height = Math.max(box.height, 160);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    container.tabIndex = 0;
    container.setAttribute('role', 'img');
    container.setAttribute('aria-label', `Traffic over time chart. ` +
      `${App.el('nf-totals').textContent || NO_FLOWS_TEXT}. Focus and use ` +
      `left/right to pan, plus/minus to zoom, Home to reset.`);
    if (!container.dataset.keyboardWired) {
      container.dataset.keyboardWired = '1';
      container.addEventListener('keydown', (event) => {
        const zoomIn = event.key === '=' || event.key === '+';
        const zoomOut = event.key === '-' || event.key === '_';
        if (event.key === 'ArrowLeft') { event.preventDefault(); pan(-0.25); }
        else if (event.key === 'ArrowRight') { event.preventDefault(); pan(0.25); }
        else if (zoomIn) { event.preventDefault(); zoom(0.5); }
        else if (zoomOut) { event.preventDefault(); zoom(2); }
        else if (event.key === 'Home') { event.preventDefault(); resetWindow(); }
      });
      container.addEventListener('focus', () => showFocusTip(container));
      container.addEventListener('blur', App.hideTooltip);
    }
    // Redrawn only when the data or the drawing area changed: this ran on
    // every refresh and on every frame of a divider drag, tearing the SVG
    // down and rebuilding one hit rectangle with three listeners per
    // bucket each time, whether or not anything was different.
    // The brush is NOT part of the signature: it is one persistent rect
    // moved in place by the pointermove handler below, so a drag no longer
    // misses the signature, rebuilds the whole chart and re-stringifies
    // view.data once per pointer event.
    const signature = `${width}x${height}:`
      + (view.loading || view.failed ? emptyMessage() : JSON.stringify(view.data));
    if (svg.dataset.signature === signature) return;
    svg.dataset.signature = signature;
    svg.innerHTML = '';

    const data = view.data;
    const plot = {
      x: PAD.left, y: PAD.top,
      w: Math.max(width - PAD.left - PAD.right, 10),
      h: 0,
    };

    if (view.loading || view.failed || !data || !data.times.length
        || !data.series.length) {
      App.emptyText(svg, width, height, emptyMessage());
      showFocusTip(container);
      return;
    }

    /* The legend is laid out before the plot is sized, because it is what
       decides how tall the plot can be: an entry that no longer fits its
       row goes on to the next one rather than being dropped, since a band
       drawn with nothing naming it is a colour the operator has to guess
       at. Bounded: nine entries at most (eight named plus "— other —"),
       and an entry wider than the whole row still gets a row of its own. */
    const LEGEND_ROW_H = 16;
    const legend = [];
    let legendX = plot.x;
    let legendRow = 0;
    data.series.forEach((series, index) => {
      const label = series.name;
      const width_ = label.length * 6.5 + 24;
      if (legendX > plot.x && legendX + width_ > plot.x + plot.w) {
        legendRow += 1;
        legendX = plot.x;
      }
      legend.push({ label, index, x: legendX, row: legendRow });
      legendX += width_;
    });
    const legendH = 6 + LEGEND_ROW_H * (legendRow + 1);
    plot.h = Math.max(height - PAD.top - PAD.bottom - legendH, 10);

    const count = data.times.length;
    const cumulative = [];
    let running = new Array(count).fill(0);
    for (const series of data.series) {
      running = running.map((value, i) =>
        value + (series.values[i] || 0) * 8 / slotSeconds(data, i));
      cumulative.push([...running]);
    }
    const peak = Math.max(...running, 0);
    const axisMax = niceCeiling(peak);

    for (let step = 0; step <= 4; step += 1) {
      const fraction = step / 4;
      const y = plot.y + plot.h - plot.h * fraction;
      svg.appendChild(App.svgNode('line', {
        x1: plot.x, y1: y, x2: plot.x + plot.w, y2: y, stroke: 'var(--grid)',
      }));
      svg.appendChild(App.svgNode('text', {
        x: plot.x - 8, y: y + 4, 'text-anchor': 'end', fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, App.rate(axisMax * fraction / 8, 1)));
    }

    // `drawn` is the slots that cover some of the window: an empty,
    // boundary-aligned final slot is neither drawn nor ticked (slotCount
    // says why), though it still sits in `count` and `cumulative` above.
    const { t0, t1, xOf, timeAt, slotAt, middleOf, count: drawn } = axisOf(data, plot);
    const yOf = (top) => plot.y + plot.h - plot.h * Math.min(top / axisMax, 1);
    const baseline = plot.y + plot.h;
    /* Painted from the top of the stack down: every band is filled to the
       baseline, so drawing in series order would leave the last one covering
       all the others. */
    for (let index = data.series.length - 1; index >= 0; index -= 1) {
      const tops = cumulative[index];
      const points = [`${xOf(t0)},${baseline}`, `${xOf(t0)},${yOf(tops[0])}`];
      for (let slot = 0; slot < drawn; slot += 1) {
        points.push(`${xOf(middleOf(slot))},${yOf(tops[slot])}`);
      }
      points.push(`${xOf(t1)},${yOf(tops[drawn - 1])}`, `${xOf(t1)},${baseline}`);
      const name = data.series[index].name;
      svg.appendChild(App.svgNode('polygon', {
        points: points.join(' '),
        fill: seriesColor(name, index),
        'fill-opacity': 0.85,
      }));
    }

    // Coverage honesty (the operator's report): a records-only answer whose
    // records do not reach the whole way back to t0 is shaded rather than
    // left to read as "nothing happened here" — the same reach the totals
    // line and the empty-pane message below both say in words.
    if (data.records_only && data.records_from != null && data.records_from > t0) {
      const shadeEnd = Math.min(data.records_from, t1);
      svg.appendChild(App.svgNode('rect', {
        x: xOf(t0), y: plot.y, width: Math.max(xOf(shadeEnd) - xOf(t0), 0),
        height: plot.h, fill: 'var(--data-neutral)', 'fill-opacity': 0.12,
      }));
      svg.appendChild(App.svgNode('text', {
        x: plot.x + 4, y: plot.y + 12, fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, `no records kept before ${App.stamp(data.records_from, view.t1 - view.t0)}`));
    } else if (data.breakdown_from != null && data.breakdown_from > t0) {
      // Below the breakdown floor a scoped window holds totals only, in "— other —".
      // Fainter than the records-only shade (0.08 vs 0.12), which the `else` lets win.
      const shadeEnd = Math.min(data.breakdown_from, t1);
      svg.appendChild(App.svgNode('rect', {
        x: xOf(t0), y: plot.y, width: Math.max(xOf(shadeEnd) - xOf(t0), 0),
        height: plot.h, fill: 'var(--data-neutral)', 'fill-opacity': 0.08,
      }));
      svg.appendChild(App.svgNode('text', {
        x: plot.x + 4, y: plot.y + 12, fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, `totals only before ${App.stamp(data.breakdown_from, view.t1 - view.t0)}; ` +
         'breakdown by application, host and interface from the upgrade onward'));
    }

    const span = view.t1 - view.t0;
    const tickEvery = Math.max(1, Math.floor(drawn / 7));
    for (let slot = 0; slot < drawn; slot += tickEvery) {
      // Each tick marks the start of the slot it labels.
      const x = xOf(data.times[slot]);
      svg.appendChild(App.svgNode('text', {
        x, y: plot.y + plot.h + 15, 'text-anchor': 'middle', fill: 'var(--dim)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, App.stamp(data.times[slot], span)));
    }

    for (const entry of legend) {
      const y = height - legendH + 6 + entry.row * LEGEND_ROW_H;
      svg.appendChild(App.svgNode('rect', {
        x: entry.x, y, width: 9, height: 9, rx: 2,
        fill: seriesColor(entry.label, entry.index),
      }));
      svg.appendChild(App.svgNode('text', {
        x: entry.x + 14, y: y + 8, fill: 'var(--muted)',
        'font-family': 'var(--mono)', 'font-size': 'var(--fs-2xs)',
      }, entry.label));
    }

    const brush = App.svgNode('rect', {
      x: 0, y: plot.y, width: 0, height: plot.h,
      fill: 'var(--accent)', 'fill-opacity': 0.18, stroke: 'var(--accent)',
      visibility: 'hidden',
    });
    svg.appendChild(brush);
    // Moved in place per pointermove; a chart rebuilt mid-drag (a refresh
    // landing) gets it back from view.drag here.
    const paintBrush = () => {
      if (!view.drag) { brush.setAttribute('visibility', 'hidden'); return; }
      const a = xOf(Math.min(view.drag.from, view.drag.to));
      const b = xOf(Math.max(view.drag.from, view.drag.to));
      brush.setAttribute('x', a);
      brush.setAttribute('width', Math.max(b - a, 2));
      brush.setAttribute('visibility', 'visible');
    };
    paintBrush();

    const crosshair = App.svgNode('line', {
      y1: plot.y, y2: plot.y + plot.h,
      stroke: 'var(--muted)', 'stroke-dasharray': '2 3', visibility: 'hidden',
    });
    svg.appendChild(crosshair);

    svg.onpointerdown = (event) => {
      if (event.button !== 0 || !event.isPrimary) return;
      event.preventDefault();
      // Captured so the brush follows a finger or a mouse out of the chart.
      svg.setPointerCapture(event.pointerId);
      const x = event.offsetX * (width / svg.clientWidth);
      view.drag = { from: timeAt(x), to: timeAt(x), moved: false };
    };
    svg.onpointermove = (event) => {
      const x = event.offsetX * (width / svg.clientWidth);
      if (view.drag) {
        view.drag.to = timeAt(x);
        view.drag.moved = true;
        paintBrush();
        return;
      }
      if (x < plot.x || x > plot.x + plot.w) {
        crosshair.setAttribute('visibility', 'hidden');
        return App.hideTooltip();
      }
      crosshair.setAttribute('x1', x);
      crosshair.setAttribute('x2', x);
      crosshair.setAttribute('visibility', 'visible');
      App.tooltip(slotTip(data, slotAt(timeAt(x))), event);
    };
    svg.onpointerleave = () => {
      crosshair.setAttribute('visibility', 'hidden');
      App.hideTooltip();
    };
    svg.onpointerup = () => {
      if (!view.drag) return;
      const { from, to, moved } = view.drag;
      view.drag = null;
      paintBrush();
      // A click (`moved` false) redraws and nothing more, as it always has;
      // a drag is accepted down to DRAG_MIN_S and DRAG_MIN_PX, not down to
      // the previous response's bucket. The server picks the bucket for
      // the narrower window from its own ladder.
      if (moved && Math.abs(to - from) >= DRAG_MIN_S
          && Math.abs(xOf(to) - xOf(from)) >= DRAG_MIN_PX) {
        setWindow(Math.min(from, to), Math.max(from, to), false);
      } else drawChart();
    };
    svg.onpointercancel = () => { view.drag = null; paintBrush(); drawChart(); };
    svg.onwheel = (event) => {
      event.preventDefault();
      const x = event.offsetX * (width / svg.clientWidth);
      // Anchor on the window's own time axis: it is what setWindow moves,
      // and the plotted axis spans the same window now (it used to stop
      // short of the right edge by one interval), differing only by the
      // server's snapping of t0 to a bucket boundary.
      const fraction = Math.min(Math.max((x - plot.x) / plot.w, 0), 1);
      const anchor = view.t0 + fraction * (view.t1 - view.t0);
      const [start, end] = App.wheelWindow(event, view.t0, view.t1, anchor);
      setWindow(start, end, false);
    };
    showFocusTip(container);
  }

  function slotTip(data, slot) {
    const seconds = slotSeconds(data, slot);
    const covered = slotCovered(data, slot);
    const span = windowEnd(data) - data.times[0];
    let heading = App.stamp(data.times[slot], span);
    if (covered < data.bucket_s) {
      // Said rather than deduced: the newest slot is a rate over what it
      // covers so far, not over a whole interval like the rest — and when
      // that is less than the quarter-bucket floor, over the floor, which
      // the heading says too rather than let the number imply a division
      // that was not done.
      heading += ` \u00b7 ${App.span(covered)} of ${App.span(data.bucket_s)} so far`;
      if (covered < seconds) heading += `, rated over ${App.span(seconds)}`;
    }
    const rows = [{ text: heading }];
    // Same floor as the shaded region: such a slot's whole value sits in "— other —".
    if (data.breakdown_from != null && data.times[slot] < data.breakdown_from) {
      rows.push({ text: 'totals only (before the upgrade)' });
    }
    // The index has to survive the sort: it is what maps a series to the
    // colour of its band, and sorting by volume reorders the rows.
    const pairs = data.series
      .map((series, index) => ({
        name: series.name, value: series.values[slot] || 0, index,
      }))
      .filter((entry) => entry.value > 0)
      .sort((a, b) => b.value - a.value);
    for (const entry of pairs.slice(0, 8)) {
      rows.push({
        text: `${entry.name}: ${App.rate(entry.value, seconds)}`,
        color: seriesColor(entry.name, entry.index),
      });
    }
    const total = data.series.reduce((sum, s) => sum + (s.values[slot] || 0), 0);
    rows.push({ text: `total: ${App.rate(total, seconds)}` });
    return rows;
  }

  /* -------------------------------------------------------------- bars */

  // A stable, position-independent id fragment for one top-N row: derived
  // from the dimension's own key (a port, an address, an exporter) rather
  // than its rank, which reorders on every refresh as traffic shifts — a
  // fragment identifier has to survive that reorder to identify anything.
  // Non-identifier characters (an IPv6 colon, a dotted address) become
  // dashes rather than being dropped, so two keys that differ only in
  // punctuation cannot collide onto the same id.
  function barRowId(dimension, key) {
    return `nf-bar-${dimension}-${String(key).replace(/[^A-Za-z0-9_-]/g, '-')}`;
  }

  function drawBars() {
    const wrap = App.el('nf-bars');
    wrap.innerHTML = '';
    if (view.loading) { wrap.innerHTML = App.loadingMark(); return; }
    const rows = view.data && !view.failed ? view.data.top : [];
    if (!rows.length) {
      wrap.innerHTML = `<p class="empty">${emptyMessage()}</p>`;
      return;
    }
    const dimension = App.el('nf-dimension').value;
    const peak = Math.max(...rows.map((r) => r.bytes), 1);
    // The rows and the chart's series come off one sorted list on the
    // server, so row i IS band i for as long as there are bands; the rows
    // after that are inside "— other —" up there, and get its neutral.
    const drawn = namedBands(view.data);
    const bars = [];
    rows.forEach((row, index) => {
      const folded = index >= drawn;
      const color = folded ? OTHER : seriesColor(row.label, index);
      const div = document.createElement('div');
      div.className = 'bar-row';
      // id carries the row's real identity (row.key: a port, an address, an
      // exporter — see barRowId); it must never rest on `index` when a rank
      // itself reorders across refreshes. The value span gets its own id so
      // the traffic figures — the part that DOES change every refresh — can
      // still reach assistive tech, through aria-describedby below, without
      // being the thing the row's accessible NAME is built from. A folded
      // row's sentence gets a (visually hidden) span of its own for the
      // same reason, rather than being written into the visible figures.
      div.id = barRowId(dimension, row.key);
      const valueId = `${div.id}-value`;
      const foldId = `${div.id}-fold`;
      // share is a fraction of the window's own total (Plixer's Percent
      // column) -- guarded, so a response from before it existed still
      // draws the bar, just without the trailing percentage.
      const shareText = row.share != null ? ` · ${Math.round(row.share * 100)}%` : '';
      div.innerHTML =
        `<div class="bar-fill" style="width:${(row.bytes / peak) * 100}%;` +
        `background:${color}"></div>` +
        `<span class="bar-label">${escape(row.label)}</span>` +
        `<span class="bar-value" id="${valueId}">${row.bytes_text} · ${row.rate_text}` +
        `${shareText}</span>` +
        (folded ? `<span class="sr-only" id="${foldId}">${FOLDED_TEXT}</span>` : '');
      div.onclick = () => {
        // A bar picked with the mouse becomes the one the keyboard returns
        // to, same as a table row's own click already does.
        for (const other of bars) other.tabIndex = other === div ? 0 : -1;
        filterByBar(row);
      };
      div.style.cursor = 'pointer';
      // Swatched to match its own bar: for the first `drawn` rows that is
      // the band of the same name in the chart above, and for the rest it
      // is the neutral the chart draws "— other —" in, because that is
      // where the chart put them. Said in words as well, so a grey swatch
      // reads as a fact and not as a colour that ran out.
      const tip = [
        { text: row.label, color },
        { text: `${row.bytes_text} · ${row.rate_text}` },
      ];
      // Guarded the same way the value span above is: a response from
      // before packets_text existed still draws a tooltip, just a shorter one.
      if (row.packets_text) tip.push({ text: `${row.packets_text} packets` });
      tip.push({ text: `${row.flows} flow records` });
      if (folded) tip.push({ text: FOLDED_TEXT });
      div.setAttribute('role', 'button');
      // The accessible NAME is what the row IS — this port, this address,
      // this exporter — and nothing else, precisely because that is the one
      // thing here that does NOT change out from under a screen-reader user
      // between refreshes; the traffic figures a sighted operator reads off
      // the bar itself are still announced, as the row's DESCRIPTION via
      // aria-describedby, just not folded into the name a repeat visitor or
      // a future automated check would use to find this exact row again.
      div.setAttribute('aria-label', row.label);
      div.setAttribute('aria-describedby', folded ? `${valueId} ${foldId}` : valueId);
      div.addEventListener('mousemove', (event) => App.tooltip(tip, event));
      div.addEventListener('mouseleave', App.hideTooltip);
      div.addEventListener('focus', () => {
        const box = div.getBoundingClientRect();
        App.tooltip(tip, { clientX: box.left + box.width / 2, clientY: box.bottom });
      });
      div.addEventListener('blur', App.hideTooltip);
      wrap.appendChild(div);
      bars.push(div);
    });
    // A short list (App.el('n-topn') caps it at 25) so every bar gets its
    // own tab stop, roving the way wireRowKeyboard does for table rows
    // rather than making the operator step through all of them on Tab alone.
    bars.forEach((div, index) => {
      div.tabIndex = index === 0 ? 0 : -1;
      div.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          div.click();
          return;
        }
        const step = event.key === 'ArrowDown' ? 1 : event.key === 'ArrowUp' ? -1 : 0;
        if (!step) return;
        const next = bars[index + step];
        if (!next) return;
        event.preventDefault();
        div.tabIndex = -1;
        next.tabIndex = 0;
        next.focus();
      });
    });
  }

  function filterByBar(row) {
    const dimension = App.el('nf-dimension').value;
    if (dimension === 'Source') App.el('nf-src').value = row.key;
    else if (dimension === 'Destination') App.el('nf-dst').value = row.key;
    else if (dimension === 'Application') App.el('nf-port').value = row.key;
    else if (dimension === 'Exporter') App.el('nf-exporter').value = row.key;
    else return;
    App.refreshNow('netflow');
  }

  /* Mirrors the filters into the hash after filterBar's own refresh, so a
     link into this view can be shared. src/dst are the round trip for
     App.ipCell's "NetFlow from" / "NetFlow to" actions (see activate());
     also called from EXPORTERS' Report action and INTERFACES' row click
     below, so it is module-level rather than a local of init(). */
  function syncNetflowRoute() {
    App.syncFilterRoute('netflow', {
      src: 'nf-src', dst: 'nf-dst', port: 'nf-port', protocol: 'nf-protocol',
      exporter: 'nf-exporter', iface: 'nf-iface', direction: 'nf-direction',
      window: 'nf-range',
    });
  }

  /* ------------------------------------------------------- exporters / interfaces

     The two Plixer-style report views: TRAFFIC's own subtab keeps its data
     fresh on every poll regardless of which subtab is on screen (drawStatus
     needs it live and switching back to TRAFFIC must not show a stale
     chart); these two fetch only when they are the one showing, on
     selectSub and on the module's own poll. */

  function selectSub(name) {
    view.sub = name;
    App.selectSub('netflow', name);
    if (name === 'exporters') refreshExporters();
    else if (name === 'interfaces') refreshInterfaces();
  }

  // A device on TRAFFIC's own exporter and iface pickers, set from a report
  // click below: iface/direction/dimension are optional so a caller can set
  // only the exporter (the EXPORTERS Report action clears iface instead).
  async function goToTrafficFiltered({ exporter, iface, direction, dimension }) {
    if (exporter !== undefined) {
      App.el('nf-exporter').value = exporter;
      view.ifaceExporter = exporter;
      await loadIfaceOptions(exporter);
    }
    if (iface !== undefined) App.el('nf-iface').value = String(iface);
    if (direction !== undefined) App.el('nf-direction').value = direction;
    if (dimension !== undefined) App.el('nf-dimension').value = dimension;
    App.rememberSub('netflow', 'traffic');
    selectSub('traffic');
    App.refreshNow('netflow');
    syncNetflowRoute();
  }

  function goToInterfaces(row) {
    const select = App.el('nf-if-exporter');
    // nf-if-exporter may never have been built yet (INTERFACES not opened
    // this session) — a temporary option makes the value stick immediately;
    // refreshInterfaces() below rebuilds the list for real and keeps it.
    if (![...select.options].some((o) => o.value === row.address)) {
      const option = document.createElement('option');
      option.value = row.address;
      option.textContent = exporterLabel(row);
      select.appendChild(option);
    }
    select.value = row.address;
    App.rememberSub('netflow', 'interfaces');
    selectSub('interfaces');
  }

  const EXPORTER_STATE_COLOR = { active: 'var(--ok)', idle: 'var(--warn)', silent: 'var(--fail)' };

  const EXPORTER_COLUMNS = [
    { key: 'status', label: 'Status', width: 70, sortable: false,
      cell: (r) => `<span class="dot" style="background:` +
        `${EXPORTER_STATE_COLOR[r.state] || 'var(--line)'}" ` +
        `title="${escape(r.state || '')}"></span>` },
    { key: 'name', label: 'Exporter', width: 170,
      value: (r) => (r.name || r.address || '').toLowerCase(),
      cell: (r) => escape(r.name || r.address || '') },
    { key: 'address', label: 'Address', width: 130, cell: (r) => escape(r.address) },
    { key: 'version', label: 'Version', width: 70, numeric: true,
      cell: (r) => escape(String(r.version)) },
    { key: 'flows_per_s', label: 'Flows/s', width: 90, numeric: true, descendingFirst: true,
      cell: (r) => (r.flows_per_s != null ? r.flows_per_s.toFixed(1) : '—') },
    { key: 'bits_per_s', label: 'Bits/s', width: 100, numeric: true, descendingFirst: true,
      value: (r) => r.bits_per_s, cell: (r) => escape(r.rate_text || '—') },
    { key: 'interfaces', label: 'Interfaces', width: 90, numeric: true,
      cell: (r) => String(r.interfaces || 0) },
    { key: 'seq_missed', label: 'Missed seq', width: 100, numeric: true,
      cell: (r) => {
        const missed = (r.seq_missed || 0).toLocaleString();
        return r.seq_resets > 0
          ? `${missed} (${r.seq_resets.toLocaleString()} resets)` : missed;
      } },
    { key: 'sampling', label: 'Sampling', width: 90, numeric: true,
      value: (r) => r.sampling || 0,
      cell: (r) => (r.sampling ? escape(`1:${r.sampling}`) : '—') },
    { key: 'last_seen', label: 'Last flow', width: 110, numeric: true, descendingFirst: true,
      value: (r) => r.last_seen || 0,
      cell: (r) => (r.last_seen ? escape(ago(r.last_seen)) : '—') },
    { key: 'first_seen', label: 'First seen', width: 110, numeric: true,
      value: (r) => r.first_seen || 0,
      cell: (r) => (r.first_seen ? escape(ago(r.first_seen)) : '—') },
    // A fixed column filled in the row callback below, the same pattern the
    // flow table's own Route column uses.
    { key: 'report', label: '', sortable: false, fixed: true, width: 84, cell: () => '' },
  ];

  // Missed seq hover: the gap event count and the most recent gap.
  function seqTip(row) {
    const rows = [{ text: `${(row.seq_gaps || 0).toLocaleString()} gap events` }];
    const last = row.seq_last;
    if (last) {
      rows.push({ text: `last gap: expected ${last.expected.toLocaleString()}, ` +
        `got ${last.got.toLocaleString()}, domain ${last.domain}, ${ago(last.ts)}, ` +
        (last.gap_s != null ? `${last.gap_s.toFixed(1)}s after the previous packet`
          : 'interval unknown') });
    }
    return rows;
  }

  let exportersSort = { key: 'flows_per_s', descending: true };
  function onExportersSort(key, descending) {
    exportersSort = { key, descending };
    drawExportersTable(view.exporters);
  }

  function drawExportersTable(rows) {
    const table = App.grid(App.el('nf-exporters'),
      { name: 'nf-exporters', caption: 'NetFlow exporters',
        columns: EXPORTER_COLUMNS, sort: exportersSort, onSort: onExportersSort });
    const body = document.createElement('tbody');
    const sorted = App.sortRows(rows, exportersSort.key, exportersSort.descending,
                                EXPORTER_COLUMNS);
    App.drawRows(body, sorted, EXPORTER_COLUMNS, (tr, row) => {
      tr.className = 'clickable';
      tr.title = `View ${row.name || row.address} on INTERFACES`;
      tr.onclick = (event) => {
        if (event.target.closest('.nf-exp-report')) return;
        goToInterfaces(row);
      };
      const seqCell = tr.cells[EXPORTER_COLUMNS.findIndex((c) => c.key === 'seq_missed')];
      if (seqCell) {
        const tip = seqTip(row);
        seqCell.addEventListener('mousemove', (event) => App.tooltip(tip, event));
        seqCell.addEventListener('mouseleave', App.hideTooltip);
      }
      const reportCell = tr.cells[EXPORTER_COLUMNS.findIndex((c) => c.key === 'report')];
      if (!reportCell) return;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'linkish nf-exp-report';
      btn.textContent = 'Report';
      btn.title = `Filter TRAFFIC to ${row.name || row.address}`;
      btn.onclick = (event) => {
        event.stopPropagation();
        goToTrafficFiltered({ exporter: row.address, iface: '' });
      };
      reportCell.appendChild(btn);
    }, 'No exporters have sent flows yet.');
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  async function refreshExporters() {
    let data;
    try {
      data = await App.get('/api/netflow/exporters', {});
    } catch (error) { return; }
    if (view.sub !== 'exporters') return;    // an operator moved on while this was in flight
    view.exporters = data.exporters || [];
    drawExportersTable(view.exporters);
  }

  // A utilisation bar reusing .bar-row/.bar-fill (the top-N bars' own
  // classes), sized down to fit a table cell, beside the server's own
  // formatted rate text; text alone when the interface's speed is unknown.
  function utilCell(text, util) {
    if (util == null) {
      return escape(text || '—');
    }
    const pct = Math.round(Math.min(Math.max(util, 0), 1) * 100);
    return `<div class="bar-row" style="display:inline-block;vertical-align:middle;` +
      `width:64px;height:12px;margin-right:6px" title="${pct}%">` +
      `<div class="bar-fill" style="width:${pct}%;background:var(--accent)"></div>` +
      `</div>${escape(text || '—')}`;
  }

  const INTERFACE_COLUMNS = [
    { key: 'exporter_name', label: 'Exporter', width: 160,
      value: (r) => (r.exporter_name || r.exporter || '').toLowerCase(),
      cell: (r) => escape(r.exporter_name || r.exporter || '') },
    { key: 'name', label: 'Interface', width: 150,
      value: (r) => (r.name || String(r.if_index)).toLowerCase(),
      cell: (r) => escape(r.name || String(r.if_index)) },
    { key: 'speed', label: 'Speed', width: 90, numeric: true,
      value: (r) => r.speed_bps,
      cell: (r) => (r.speed_bps ? App.rate(r.speed_bps / 8, 1) : '—') },
    { key: 'in', label: 'In', width: 170, numeric: true, descendingFirst: true,
      value: (r) => r.in_bps, cell: (r) => utilCell(r.in_text, r.in_util) },
    { key: 'out', label: 'Out', width: 170, numeric: true, descendingFirst: true,
      value: (r) => r.out_bps, cell: (r) => utilCell(r.out_text, r.out_util) },
    { key: 'flows', label: 'Flows', width: 90, numeric: true, descendingFirst: true,
      value: (r) => (r.in_flows || 0) + (r.out_flows || 0),
      cell: (r) => String((r.in_flows || 0) + (r.out_flows || 0)) },
  ];

  let interfacesSort = App.recallSort('nf-interfaces', { key: 'in', descending: true });
  function onInterfacesSort(key, descending) {
    interfacesSort = { key, descending };
    drawInterfacesTable(view.interfaces || []);
  }

  function drawInterfacesTable(rows) {
    const table = App.grid(App.el('nf-interfaces'),
      { name: 'nf-interfaces', caption: 'NetFlow interfaces', columns: INTERFACE_COLUMNS,
        sort: interfacesSort, onSort: onInterfacesSort });
    const body = document.createElement('tbody');
    const sorted = App.sortRows(rows, interfacesSort.key, interfacesSort.descending,
                                INTERFACE_COLUMNS);
    App.drawRows(body, sorted, INTERFACE_COLUMNS, (tr, row) => {
      tr.className = 'clickable';
      tr.title = `View ${row.name || row.if_index} on TRAFFIC`;
      tr.onclick = () => goToTrafficFiltered({
        exporter: row.exporter, iface: row.if_index, direction: 'both',
        dimension: 'Application',
      });
    }, 'No interfaces reported yet.');
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  function ifaceRangeWindow() {
    const seconds = Number(App.el('nf-if-range').value) || 3600;
    const now = Date.now() / 1000;
    return [now - seconds, now];
  }

  async function refreshInterfaces() {
    const [t0, t1] = ifaceRangeWindow();
    const exporterSelect = App.el('nf-if-exporter');
    const exporter = exporterSelect.value;
    let exportersData;
    let data;
    try {
      [exportersData, data] = await Promise.all([
        App.get('/api/netflow/exporters', {}),
        App.get('/api/netflow/interfaces', { t0, t1, exporter }),
      ]);
    } catch (error) { return; }
    if (view.sub !== 'interfaces') return;   // an operator moved on while this was in flight
    const current = exporterSelect.value;
    App.setHtml(exporterSelect, exporterOptionsHtml(exportersData.exporters || []));
    exporterSelect.value = current;
    drawInterfacesTable(data.interfaces || []);
  }

  /* ------------------------------------------------------------- table */

  /* `value` is what the column sorts on, which is not always what it shows:
     Bytes displays "4.2 MB" but must order by the number behind it, and the
     address columns order by the name when there is one, because that is what
     the eye is reading down. */
  /* Widths are only defaults — the grip on each header drags them wider or
     narrower, and App.grid remembers whatever a browser last dragged them
     to. Source and Destination default wider than the rest since either
     can show a resolved hostname rather than a bare address; everything
     else only needs room for what it actually holds. */
  const COLUMNS = [
    { key: 'ts', label: 'Time', numeric: true, descendingFirst: true, on: true,
      width: 92, value: (r) => r.ts, title: App.timeZoneTitle(), cell: (r) => App.timeCell(r.ts) },
    // Second, immediately after Time: which device reported a flow is
    // context for reading the rest of the row, not a footnote to it. Sorts
    // on the name where there is one, the way Source and Destination do.
    { key: 'exporter', label: 'Exporter', width: 150, on: true,
      value: (r) => (r.exporter_name || r.exporter || '').toLowerCase(),
      // Escaped, unlike the bare address it replaces — a device name is
      // typed by an admin, and this is interpolated into innerHTML.
      cell: (r) => escape(r.exporter_name || r.exporter || '') },
    { key: 'src', label: 'Source', width: 190, on: true,
      value: (r) => r.src_name || r.src_ip,
      cell: (r) => App.ipCell(r.src_ip, { label: r.src_name || undefined }) },
    { key: 'src_port', label: 'Src port', numeric: true, on: true,
      width: 96, value: (r) => r.src_port_num, cell: (r) => escape(r.src_port) },
    { key: 'dst', label: 'Destination', width: 190, on: true,
      value: (r) => r.dst_name || r.dst_ip,
      cell: (r) => App.ipCell(r.dst_ip, { label: r.dst_name || undefined }) },
    { key: 'dst_port', label: 'Dst port', numeric: true, on: true,
      width: 96, value: (r) => r.dst_port_num, cell: (r) => escape(r.dst_port) },
    { key: 'protocol', label: 'Proto', width: 76, on: true,
      cell: (r) => escape(r.protocol) },
    { key: 'bytes', label: 'Bytes', numeric: true, descendingFirst: true, on: true,
      width: 84, value: (r) => r.bytes, cell: (r) => r.bytes_text },
    { key: 'packets', label: 'Packets', numeric: true, descendingFirst: true, on: true,
      width: 84, value: (r) => r.packets, cell: (r) => r.packets_text },
    { key: 'interfaces', label: 'In/Out', sortable: false, width: 96, on: true,
      value: (r) => `${r.in_if} / ${r.out_if}`,
      cell: (r) => `${escape(r.in_if)} / ${escape(r.out_if)}` },
    { key: 'src_ip', label: 'Source IP', width: 140,
      cell: (r) => App.ipCell(r.src_ip, {}) },
    { key: 'dst_ip', label: 'Destination IP', width: 140,
      cell: (r) => App.ipCell(r.dst_ip, {}) },
    { key: 'exporter_ip', label: 'Exporter IP', width: 140,
      value: (r) => r.exporter || '', cell: (r) => escape(r.exporter || '') },
    // The route button is a `fixed` column, not an appendix bolted on after
    // the row was built: it used to be appended outside the cell map, which
    // is exactly the pattern that breaks the moment columns can be hidden.
    { key: 'route', label: '', sortable: false, fixed: true, width: 84,
      cell: () => '' },
  ];

  /* Which column the table is ordered by. Separate from the selector above it:
     that one decides which records the server sends back, this one decides how
     the returned records are arranged. */
  let sort = App.recallSort('nf-records', { key: 'bytes', descending: true });

  function onSort(key, descending) {
    sort = { key, descending };
    drawTable(view.records || []);
  }

  const recordColumns = () => App.visibleColumns(
    COLUMNS, (App.state.flowSettings || {}).table_columns);

  function drawTable(records) {
    // While loading these records belong to the window being left, so they
    // are neither shown nor remembered as the answer to the one being asked.
    if (!view.loading && !view.failed) view.records = records;
    const columns = recordColumns();
    const table = App.grid(App.el('nf-table'),
                           { name: 'nf-records', caption: 'NetFlow records',
                             columns, sort, onSort });
    const body = document.createElement('tbody');
    const rows = view.loading || view.failed
      ? [] : App.sortRows(records, sort.key, sort.descending, columns);
    App.drawRows(body, rows, columns, (tr, record) => {
      const dst = record.dst_name || record.dst_ip || '';
      // Flow-to-path correlation: jump straight to the NetPath route that
      // this conversation's destination was last traced over. Always shown,
      // greyed when no target has ever traced that address, so the control's
      // position in the row stays constant and its existence is discoverable.
      const routeCell = tr.cells[columns.findIndex((c) => c.key === 'route')];
      if (routeCell && record.dst_target_id) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'linkish';
        btn.title = `View the NetPath route to ${dst}`;
        btn.textContent = '\u2192 Route';
        // A real route (window.location.hash), not a direct call into
        // NetPath's own App.pages entry: NetPath is a lazy module, and this
        // button is reachable long before an operator has ever opened that
        // tab — its entry does not exist yet until that module's own script
        // has run, and calling straight into it threw out of this handler
        // (so the tab-switch call that used to follow it never ran either,
        // leaving the click looking like it did nothing). The hash change
        // goes through the same applyRoute -> ensureModuleReady path every
        // other cross-tab link in this app already relies on; see the
        // matching comment on netpath.js's activate().
        btn.onclick = (event) => {
          event.stopPropagation();
          window.location.hash = App.buildRoute('netpath', [record.dst_target_id],
            { t0: record.ts - 300, t1: record.ts + 300 });
        };
        routeCell.appendChild(btn);
      } else if (routeCell) {
        routeCell.textContent = '\u2014';
        routeCell.style.color = 'var(--dim)';
        routeCell.title = 'No NetPath target has traced a route to this destination';
      }
      const tip = [
        App.when(record.ts),
        `${record.src_ip}:${record.src_port} → ${record.dst_ip}:${record.dst_port}`,
      ];
      if (record.src_name) tip.push(`source      ${record.src_name}`);
      if (record.dst_name) tip.push(`destination ${record.dst_name}`);
      tip.push(`protocol    ${record.protocol}`);
      tip.push(`volume      ${record.bytes_text} · ${record.packets_text} packets`);
      tip.push(`interfaces  ${record.in_if} / ${record.out_if}`);
      // Both, always: the name is what identifies the device and the
      // address is what the collector actually received the flow from.
      if (record.exporter_name) tip.push(`exporter    ${record.exporter_name}`);
      tip.push(`${record.exporter_name ? 'exporter IP ' : 'exporter    '}${record.exporter}`);
      const text = tip.join('\n');
      tr.addEventListener('mousemove', (event) => App.tooltip(text, event));
      tr.addEventListener('mouseleave', App.hideTooltip);
      // wireRowKeyboard below gives the row the keyboard; this is what a
      // mouse hover already shows it once it lands there.
      tr.addEventListener('focus', () => {
        const box = tr.getBoundingClientRect();
        App.tooltip(text, { clientX: box.left + box.width / 2, clientY: box.bottom });
      });
      tr.addEventListener('blur', App.hideTooltip);
    }, emptyMessage());
    table.appendChild(body);
    App.wireRowKeyboard(body);
  }

  /* ---------------------------------------------------------- settings */

  App.registerHelp({
    'netflow.settings.sampling': { title: 'Sampling', html: `
      <p>An exporter under load rarely reports every packet it forwards — it
      samples, sending only 1 in every N, and expects the collector to
      multiply what it does receive back up. Every byte, packet and flow
      figure in NetFlow (the flow table, the top-N charts, the totals on this
      page) is the raw decoded count times whatever rate applied to that
      flow — get the rate wrong and every one of those figures is wrong by
      the same fixed factor, silently.</p>
      <p><b>Use the rate the exporter reports, when it sends one</b> (on by
      default) reads the rate from the exporter's own IPFIX/v9 options
      template rather than guessing — most modern exporters send one.
      <b>Assumed rate</b> is what is used when it does not (v5 carries no
      sampling information at all, so this is the only rate v5 ever gets),
      and is also what every exporter uses if this checkbox is off.</p>
      <p>An exporter's options template arrives on its own, slower cycle than
      its flow data — flows decoded before the first one lands are stored at
      whatever rate was already known (1, the first time this collector has
      ever seen that exporter) and corrected once it arrives, so a brief
      under-count right after the collector or exporter restarts is expected,
      not a sign the rate is wrong.</p>` },
  });

  /* A5/root-cause: "Records reach back <span> · per-exporter summaries
     since <stamp> · per-interface since <stamp>", each part omitted when
     its floor is not known yet -- a fresh install or a collector that has
     never run. Read straight off the same coverage() /api/state polls, so
     this line and the strip's own history readout cannot disagree. */
  function coverageSettingsLine() {
    const coverage = ((App.state.serverState || {}).collector || {}).coverage || {};
    const bits = [];
    if (coverage.raw_oldest != null) {
      bits.push(`Records reach back ${App.span(Date.now() / 1000 - coverage.raw_oldest)}`);
    }
    const exporterFloor = coverage.scoped_hourly_floor != null
      ? coverage.scoped_hourly_floor : coverage.scoped_minute_floor;
    if (exporterFloor != null) {
      bits.push(`per-exporter summaries since ${App.stamp(exporterFloor)}`);
    }
    if (coverage.iface_hourly_floor != null) {
      bits.push(`per-interface since ${App.stamp(coverage.iface_hourly_floor)}`);
    }
    return bits.join(' · ');
  }

  function settingsDialog() {
    const s = App.state.flowSettings || {};
    const { check, number } = App.form;
    const coverageLineText = coverageSettingsLine();
    const settingsBox = App.modal('NetFlow settings', `
      <fieldset><legend>COLLECTOR</legend>
        ${check('n-enabled', 'Run the collector', s.enabled)}
        ${App.form.text('n-bind', 'Bind address', escape(s.bind_address))}
        ${number('n-port', 'UDP port', s.port, 'min=1 max=65535')}
        ${number('n-buffer', 'Receive buffer (KB)', s.socket_buffer_kb, 'min=64')}
        <div class="row start">
          ${check('n-v5', 'v5', s.accept_v5)}
          ${check('n-v9', 'v9', s.accept_v9)}
          ${check('n-ipfix', 'IPFIX', s.accept_ipfix)}
        </div>
        <p class="hint">Ports below 1024 need administrator rights. Most exporters
          default to UDP 2055, 2056, 4739 or 9995.</p>
      </fieldset>
      <fieldset><legend>SAMPLING</legend>
        ${number('n-sampling', 'Assumed rate (1 in N)', s.default_sampling, 'min=1')}
        ${check('n-trust', 'Use the rate the exporter reports, when it sends one', s.trust_exporter_sampling)}
        <p class="hint">Every byte and packet figure in NetFlow is this rate,
          multiplied.${App.helpLink('netflow.settings.sampling')}</p>
      </fieldset>
      <fieldset><legend>EXPORTERS</legend>
        ${check('n-auto', 'Accept flows from any exporter', s.auto_accept_exporters)}
        <label>Allow list <textarea id="n-allowed" rows="2">${escape(s.allowed_exporters)}</textarea></label>
        <label>Interface names <textarea id="n-ifaces" rows="2">${escape(s.interface_names)}</textarea></label>
        <label>Port names <textarea id="n-ports-custom" rows="2" placeholder="22609 = NVR">${escape(s.custom_ports || '')}</textarea></label>
        <p class="hint">Port names cover ports that are not registered with IANA — anything a
          vendor picked for itself — which cannot be known from here. Registered ports are
          named automatically from the built-in table and this machine's services file.</p>
      </fieldset>
      <fieldset><legend>STORAGE AND DISPLAY</legend>
        ${number('n-retention', 'Keep flows for (days)', s.retention_days, 'min=1')}
        ${number('n-max', 'Row cap', s.max_flows, 'min=10000 step=100000')}
        ${number('n-rollup-min', 'Keep minute summaries for (days)', s.rollup_minute_days, 'min=0')}
        ${number('n-rollup-days', 'Keep hourly summaries for (days)', s.rollup_retention_days, 'min=0')}
        ${number('n-rollup-iface', 'Keep per-interface summaries for (days)', s.rollup_interface_days, 'min=0')}
        ${number('n-topn', 'Top N', s.top_n, 'min=3 max=25')}
        ${number('n-bucket', 'Chart interval (s, 0 = auto)', s.bucket_seconds, 'min=0')}
        ${check('n-ports', 'Show service names for well-known ports', s.resolve_ports)}
        ${check('n-addr', 'Reverse-resolve addresses in the flow table', s.resolve_addresses)}
        <p class="hint">The EXPORTERS and INTERFACES views, and TRAFFIC with no
          source, destination, port or protocol filter, are drawn from the
          summaries above; a source, destination, port or protocol filter
          reads the records instead, and how far back it can reach is
          bounded by the row cap.</p>
        ${coverageLineText ? `<p class="hint">${escape(coverageLineText)}</p>` : ''}
        <p class="hint">Reverse DNS threads, timeout and cache lifetime are shared with
          NetPath and live on the Settings tab.</p>
      </fieldset>
      ${App.columnPickerFieldset('FLOW LIST COLUMNS', 'netflow', COLUMNS,
                                 s.table_columns)}`, [
      { label: 'Cancel', onClick: App.closeModal },
      { label: 'Save', primary: true, onClick: (box, button) => App.runJob(button,
        { queued: 'Saving…', done: 'Saved' }, (async () => {
        const { on, num, text } = App.form.readers(box);
        await App.post('/api/settings', { scope: 'netflow', values: {
          enabled: on('#n-enabled'), bind_address: text('#n-bind'),
          port: num('#n-port'), socket_buffer_kb: num('#n-buffer'),
          accept_v5: on('#n-v5'), accept_v9: on('#n-v9'), accept_ipfix: on('#n-ipfix'),
          default_sampling: num('#n-sampling'), trust_exporter_sampling: on('#n-trust'),
          auto_accept_exporters: on('#n-auto'), allowed_exporters: text('#n-allowed'),
          interface_names: text('#n-ifaces'),
          custom_ports: text('#n-ports-custom'),
          retention_days: num('#n-retention'),
          max_flows: num('#n-max'),
          rollup_minute_days: num('#n-rollup-min'),
          rollup_retention_days: num('#n-rollup-days'),
          rollup_interface_days: num('#n-rollup-iface'),
          top_n: num('#n-topn'),
          bucket_seconds: num('#n-bucket'), resolve_ports: on('#n-ports'),
          resolve_addresses: on('#n-addr'),
          table_columns: App.readColumnPicker(
            box.querySelector('#cols-netflow'), COLUMNS),
        } });
        await App.loadState();
        App.closeModal();
        App.refreshNow('netflow');
        })()) },
    ], { buttonsTop: true });
    App.wireColumnPickers(settingsBox);
  }

  async function sendTestPacket() {
    const result = await App.post('/api/netflow/testpacket', {});
    App.modal('Loopback test packet', `
      <p>${result.sent
        ? `Sent a 24-byte NetFlow v5 header with zero records to ${result.host}:${result.port}.`
        : `<span class="err">Could not send the test packet: ${escape(result.error)}</span>`}</p>
      <p class="hint">Watch the collector status above. The packet counter should reach the
        new total within a few seconds. Flows stored will not move: the packet declares zero
        records, which is the point — it separates "the socket is receiving" from "the decoder
        is producing flows".</p>
      <p class="hint">The same thing from PowerShell:</p>
      <pre id="test-script">${escape(result.script)}</pre>`, [
      { label: 'Copy command', onClick: () => {
        navigator.clipboard.writeText(result.script).catch(() => {});
      } },
      { label: 'Close', primary: true, onClick: App.closeModal },
    ]);
  }

  /* ----------------------------------------------------------- refresh */

  /* The collector strip is read from the shared state poll, so it keeps
     ticking at the usual rate while the charts below refresh far less often. */

  /* A5: "history: raw 13h · minute 2.0d (3m behind) · hourly 41d" — how
     far back each tier reaches, from FlowDatabase.coverage(). The minute
     figure grows a "(behind)" note once the rollup watermark has fallen
     more than a minute short of sealed time, the same lag the server's own
     SYSTEM log line watches at a coarser 15-minute threshold. */
  function coverageLine(coverage) {
    if (!coverage) return '';
    const bits = [];
    if (coverage.raw_oldest != null && coverage.raw_newest != null) {
      bits.push(`raw ${App.span(coverage.raw_newest - coverage.raw_oldest)}`);
    }
    if (coverage.minute_floor != null && coverage.minute_watermark != null) {
      let text = `minute ${App.span(coverage.minute_watermark - coverage.minute_floor)}`;
      const lagS = Date.now() / 1000 - coverage.minute_watermark;
      if (lagS > 60) text += ` (${App.span(lagS)} behind)`;
      bits.push(text);
    }
    if (coverage.hourly_floor != null && coverage.hourly_watermark != null) {
      bits.push(`hourly ${App.span(coverage.hourly_watermark - coverage.hourly_floor)}`);
    }
    if (!bits.length) return '';
    let line = `history: ${bits.join(' · ')}`;
    if (coverage.cap_held_back) {
      line += ` · ${coverage.cap_held_back} row(s) held back by the row `
             + 'cap pending the minute rollup';
    }
    return line;
  }

  function drawStatus() {
    const server = App.state.serverState || {};
    const collector = server.collector || { counters: {}, decoder: {} };
    const counters = collector.counters || {};
    const decoder = collector.decoder || {};
    const parts = [`${counters.packets || 0} packets`,
      `${counters.flows || 0} flows received`,
      `${decoder.templates || 0} templates`];
    if (decoder.no_template) parts.push(`${decoder.no_template} awaiting template`);
    if (counters.dropped) parts.push(`${counters.dropped} dropped`);
    if (counters.errors) parts.push(`${counters.errors} decode errors`);
    if (counters.rejected) parts.push(`${counters.rejected} rejected`);
    // Not one of App.extraCounterParts' fixed EXTRA_COUNTERS entries (that
    // list is shared by every module's strip), so it is added here instead.
    if (counters.seq_missed) parts.push(`${counters.seq_missed} missed sequence`);
    parts.push(...extraCounterParts(counters));
    // v9 and IPFIX stay undecodable until a template arrives, and exporters
    // resend them only every few minutes, so this is as useful as packet age.
    // Used to just say "no template yet" forever, with nothing to tell an
    // operator watching it not move whether that is normal (wait) or wrong
    // (go check the exporter) — the same fact this comment already knew.
    parts.push(counters.last_template
      ? `last template ${ago(counters.last_template)}`
      : 'no template yet (v9/IPFIX exporters resend theirs every few ' +
        'minutes; if this never clears, check the exporter is actually ' +
        'sending one)');
    if (view.fetchedAt) {
      const age = Math.round((Date.now() - view.fetchedAt) / 1000);
      parts.push(`charts ${age}s old`);
    }
    const historyLine = coverageLine(collector.coverage);
    if (historyLine) parts.push(historyLine);
    App.strip('nf', collector, { stopped: 'Collector stopped', start: 'Start collector',
      stop: 'Stop collector', parts, tooltip: true });

    const missing = collector.missing_templates || [];
    const missingEl = App.el('nf-missing');
    missingEl.hidden = missing.length === 0;
    if (missing.length) {
      const items = missing.map((m) =>
        `${m.exporter} domain ${m.domain} template ${m.template_id} — ` +
        `${m.count.toLocaleString()} sets, first seen ${ago(m.first_ts)} (${m.reason})`);
      missingEl.textContent = 'Records dropped for lack of a template: ' + items.join(' · ');
    }
  }

  async function refresh() {
    if (App.state.tab !== 'netflow') return;
    drawStatus();
    // EXPORTERS/INTERFACES fetch on the poll only while they are the pane
    // on screen, independent of TRAFFIC's own window-change debounce below.
    if (view.sub === 'exporters') refreshExporters();
    else if (view.sub === 'interfaces') refreshInterfaces();
    /* A window change is still settling. The poll tick can see the window
       half way through the burst — the dropdown is on 6h on its way to 30d —
       and fetching that one is exactly the waste requestFetch() exists to
       remove; the fetch it has already scheduled is the one worth making. */
    if (view.windowTimer) return;

    if (view.follow) {
      const span = view.t1 - view.t0;
      view.t1 = Date.now() / 1000;
      view.t0 = view.t1 - span;
    }

    const f = filters();
    // A wide window answers slower than the narrow one that replaced it, so
    // without this guard a stale response repaints over the newer view.
    const token = (view.request += 1);
    // One controller for the whole generation, so the pair can be abandoned
    // together: call()'s own in-flight map is keyed on the full URL, and a
    // window that has changed is by definition a different URL, so it only
    // ever helps a page polling the same address.
    if (view.abort) view.abort.abort();
    const abort = new AbortController();
    view.abort = abort;
    const options = { signal: abort.signal };
    // Independent questions, so asked together: in series every window
    // change cost the sum of the two round trips, in parallel the slower.
    let data;
    let records;
    try {
      [data, records] = await Promise.all([
        App.get('/api/netflow/overview', {
          t0: view.t0, t1: view.t1, dimension: f.dimension, src: f.src, dst: f.dst,
          port: f.port, protocol: f.protocol, exporter: f.exporter,
        }, options),
        App.get('/api/netflow/records', {
          t0: view.t0, t1: view.t1, src: f.src, dst: f.dst, port: f.port,
          protocol: f.protocol, exporter: f.exporter, order: App.el('nf-order').value,
        }, options),
      ]);
    } catch (error) {
      // Same stale guard as the token check below: an older generation's
      // failure must not repaint over the newer one now in flight.
      if (token === view.request) loadFailed(error);
      throw error;
    }
    if (token !== view.request) return;
    view.loading = false;
    view.failed = false;
    view.data = data;

    const totals = view.data.totals;
    let totalsText = `${totals.bytes_text} · ${totals.rate_text} avg · ` +
      `${totals.packets_text} packets · ${totals.flows} flow records`;
    // Coverage honesty: a records-only answer reaches back less far than the
    // summaries — said in words, not just implied by a chart gone quiet.
    if (data.records_only && data.records_from != null) {
      totalsText += ' · answered from records only · records reach back '
        + `to ${App.stamp(data.records_from)}`;
    }
    // The chart's shaded floor, in words for screen readers.
    if (data.breakdown_from != null && data.breakdown_from > data.t0) {
      totalsText += ` · breakdown from ${App.stamp(data.breakdown_from)}`;
    }
    if (data.widened) totalsText += ' · hourly summary';
    App.el('nf-totals').textContent = totalsText;
    showWindow();
    App.el('nf-top-title').textContent = `TOP ${f.dimension.toUpperCase()}`;

    const exporter = App.el('nf-exporter');
    const currentExporter = exporter.value;
    App.setHtml(exporter, exporterOptionsHtml(view.data.exporters));
    exporter.value = currentExporter;
    // The one late-filled control on this page: a restored exporter can only
    // be selected once the option it names exists. An exporter that has
    // stopped sending never appears, and the filter stays on "All".
    if (!exporter.value) {
      exporter.value = App.savedControl('netflow', 'nf-exporter') || '';
      // Nothing to select it on: drop it, rather than let filters() keep
      // asking the server for an exporter this page cannot show as chosen.
      if (exporter.selectedIndex < 0) {
        exporter.value = '';
        App.rememberControl('netflow', 'nf-exporter', '');
      }
    }
    // nf-iface/nf-direction follow whatever exporter just landed above,
    // including the restore-on-reload path just above this line.
    syncIfaceControls();

    App.el('nf-order').title =
      ORDER_TITLE + (records.scan_bounded ? SCAN_BOUNDED_NOTE : '');

    view.fetchedAt = Date.now();
    drawChart();
    drawBars();
    drawTable(records.records);
    drawStatus();
  }

  function init() {
    /* Registered before this module's own onchange handlers below, so a
       filter change writes the store before the refresh those handlers start
       reads it back — listeners run in registration order. restoreControls
       stays at the end, after the dimension, protocol and range lists exist;
       it assigns from script, which fires no event. Follow is deliberately
       not restored. */
    const CONTROLS = ['nf-range', 'nf-dimension', 'nf-src', 'nf-dst', 'nf-port',
      'nf-protocol', 'nf-exporter', 'nf-iface', 'nf-direction', 'nf-order'];
    App.rememberControls('netflow', CONTROLS);
    App.fillRanges(App.el('nf-range'), 'Last hour', undefined, { custom: true });
    const dimension = App.el('nf-dimension');
    // `dimensions` — like every other block in /api/state — is omitted
    // entirely for an account that cannot read this module (see
    // _STATE_MODULE_KEYS in api.py), and init() runs for every module
    // whatever the account may read. Defaulting rather than assuming is the
    // rule for anything that comes out of state: the tab is hidden anyway,
    // so an empty list here is exactly right.
    for (const name of App.state.dimensions || []) {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = name;
      dimension.appendChild(option);
    }
    dimension.value = 'Application';
    const protocol = App.el('nf-protocol');
    for (const [label, value] of PROTOCOLS) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      protocol.appendChild(option);
    }
    const exporter = App.el('nf-exporter');
    exporter.innerHTML = '<option value="">All exporters</option>';
    // Both mean nothing without an exporter chosen (an interface index is
    // only unique per device); loadIfaceOptions() flips them live as
    // nf-exporter changes.
    App.el('nf-iface').innerHTML = '<option value="">Any interface</option>';
    App.el('nf-iface').disabled = true;
    App.el('nf-direction').innerHTML =
      '<option value="both">Bidirectional</option>' +
      '<option value="in">Inbound</option>' +
      '<option value="out">Outbound</option>';
    App.el('nf-direction').disabled = true;

    App.el('nf-range').onchange = async () => {
      const select = App.el('nf-range');
      if (select.value !== 'custom') { resetWindow(); return; }
      const picked = await App.rangeDialog({ t0: view.t0, t1: view.t1 });
      if (!picked) {
        select.value = view.follow ? String(Math.round(view.t1 - view.t0)) : 'custom';
        return;
      }
      setWindow(picked.t0, picked.t1, false);
    };
    App.el('nf-reset').onclick = resetWindow;

    /* The documented chart shortcuts. Ctrl-modified on purpose (README
       :362): bare `+` and the arrow keys belong to whichever filter box or
       dropdown has focus. Home is the one exception the table already
       allows, so it is ignored while a text field has focus. */
    document.addEventListener('keydown', (event) => {
      if (App.state.tab !== 'netflow') return;
      if (!App.el('modal').hidden) return;      // a dialog owns the keyboard
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(
        (document.activeElement || {}).tagName || '');
      if (event.key === 'Home' && !typing) {
        event.preventDefault();
        resetWindow();
        return;
      }
      if (!event.ctrlKey || event.altKey || event.metaKey) return;
      // '=' and '+' are the same key; '_' is shift-'-'. Accept the pairs so
      // the shortcut works whether or not Shift is held.
      const zoomIn = event.key === '=' || event.key === '+';
      const zoomOut = event.key === '-' || event.key === '_';
      if (zoomIn) { event.preventDefault(); zoom(0.5); }
      else if (zoomOut) { event.preventDefault(); zoom(2); }
      else if (event.key === 'ArrowLeft') { event.preventDefault(); pan(-0.25); }
      else if (event.key === 'ArrowRight') { event.preventDefault(); pan(0.25); }
      else if (event.key === '0') { event.preventDefault(); resetWindow(); }
    });
    App.el('nf-in').onclick = () => zoom(0.5);
    App.el('nf-out').onclick = () => zoom(2);
    App.el('nf-back').onclick = () => pan(-0.25);
    App.el('nf-fwd').onclick = () => pan(0.25);
    App.el('nf-follow').onchange = (event) => {
      view.follow = event.target.checked;
      if (view.follow) {
        const span = view.t1 - view.t0;
        setWindow(Date.now() / 1000 - span, Date.now() / 1000);
      }
    };
    const order = App.el('nf-order');
    order.title = ORDER_TITLE;
    for (const option of order.options) {
      option.textContent = { bytes: `Top ${RECORD_LIMIT} by volume`,
        packets: `Top ${RECORD_LIMIT} by packets`,
        time: `Most recent ${RECORD_LIMIT}` }[option.value] || option.textContent;
    }
    // Through the same collapse as a window change, minus its Loading state:
    // re-ordering asks for different records, not for a different window, so
    // the chart above them is still the answer to the question on screen.
    App.el('nf-order').onchange = () => requestFetch(false);
    // nf-range is deliberately NOT in this list: its change handler is
    // resetWindow (above), which re-sizes the window before refreshing; a
    // plain refresh here would have overwritten it and left the chart on
    // the old window.
    App.filterBar('netflow', {
      text: ['nf-src', 'nf-dst', 'nf-port'],
      selects: ['nf-dimension', 'nf-protocol', 'nf-exporter', 'nf-iface', 'nf-direction'],
      apply: 'nf-apply', clear: 'nf-clear',
      clears: ['nf-src', 'nf-dst', 'nf-port', 'nf-protocol', 'nf-exporter',
               'nf-iface', 'nf-direction'],
    });
    App.el('nf-apply').addEventListener('click', syncNetflowRoute);
    App.el('nf-clear').addEventListener('click', syncNetflowRoute);
    App.el('nf-export-csv').onclick = exportFlowsCsv;
    // "Resolve names" used to sit here, in the filter bar beside per-view
    // controls (source/dest/port), silently writing a server-wide setting
    // — one operator ticking it changed every operator's flow table. The
    // same setting (resolve_addresses) now lives only in its
    // correctly-scoped control in Settings ("Reverse-resolve addresses in
    // the flow table").
    App.el('nf-settings').onclick = settingsDialog;
    App.el('nf-test').onclick = sendTestPacket;
    App.wireToggle('nf-toggle', 'collector', '/api/netflow/collector', refresh);
    App.onRelayout('netflow', drawChart);

    // TRAFFIC / EXPORTERS / INTERFACES, wired the way every other module's
    // subtabs are (alerts.js's own selectSub is the pattern this follows).
    for (const btn of document.querySelectorAll('#page-netflow > .subtabs > .subtab')) {
      btn.onclick = () => {
        App.rememberSub('netflow', btn.dataset.subtab);
        selectSub(btn.dataset.subtab);
      };
    }
    App.fillRanges(App.el('nf-if-range'), 'Last hour');
    App.el('nf-if-exporter').innerHTML = '<option value="">All exporters</option>';
    App.el('nf-if-range').onchange = () => refreshInterfaces();
    App.el('nf-if-exporter').onchange = () => refreshInterfaces();

    // Restored before the window is sized, which reads the range straight
    // off nf-range — after it, the window would be built from the markup
    // default and only correct itself on the next change.
    App.restoreControls('netflow', CONTROLS);
    applyWindow(...rangeWindow(), true);
    selectSub(App.recallSub('netflow', 'traffic'));
  }

  /* #/netflow?ip=&t0=&t1=&window=: a link in from App.ipCell or another
     tab's "view in NetFlow" action. ip lands in the Source filter (see
     syncNetflowRoute above); t0/t1 pin a custom window, window (seconds)
     picks a range-select entry — t0/t1 wins when both are given. Either
     one's own fetch (setWindow/resetWindow, debounced through
     requestFetch) carries the filter along once it lands. */
  function activate(opts) {
    if (!opts) return;
    const query = opts.query || {};
    let filtered = false;
    for (const [key, id] of [['src', 'nf-src'], ['dst', 'nf-dst'], ['port', 'nf-port'],
      ['protocol', 'nf-protocol'], ['exporter', 'nf-exporter'], ['iface', 'nf-iface'],
      ['direction', 'nf-direction']]) {
      if (query[key] !== undefined) {
        App.el(id).value = query[key];
        filtered = true;
      }
    }
    const t0 = query.t0 !== undefined ? Number(query.t0) : undefined;
    const t1 = query.t1 !== undefined ? Number(query.t1) : undefined;
    if (Number.isFinite(t0) && Number.isFinite(t1)) {
      App.el('nf-range').value = 'custom';
      setWindow(t0, t1, false);
    } else if (query.window !== undefined) {
      App.el('nf-range').value = query.window;
      resetWindow();
    } else if (filtered) {
      App.refreshNow('netflow');
    }
  }

  function ipWindow() {
    return { t0: view.t0, t1: view.t1 };
  }

  App.pages.netflow = { init, refresh, activate, fastTick: drawStatus, ipWindow };
})();

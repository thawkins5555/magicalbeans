/* Marks which tab should paint first, and writes the rule that paints it,
   before <body> has a single byte of content to render.

   Loaded from <head> as a plain <script src> (no defer, no module) so it
   still blocks parsing right there, that split second before <body>: the
   attribute and the rule are both in place by the time any .tab/.page
   element exists, so there is no "wrong page" moment to flash.

   It lives in its own file rather than inline in index.html because the
   server sends `default-src 'self'` (server.py), under which an inline
   <script> is refused outright — the browser console showed exactly that,
   and this anti-flash pass never ran. Restoring the selected tab itself was
   never affected: app.js reads the same key on load and selects the tab
   regardless. This is only about painting it without a flicker.

   The key and the 'netpath' fallback must stay in step with app.js's own
   TAB_KEY / default tab. */
(function () {
  /* The theme comes first and runs on every page — index, sign-in and the
     SSH window all load this file — because it is the one thing that
     would flash on all three: a light-theme browser painting one dark
     frame before app.js gets to it. Dark is the default and is expressed
     by the ABSENCE of the attribute, so a browser that has never chosen
     stores nothing and tokens.css's :root block simply applies. The key
     must stay in step with app.js's THEME_KEY. */
  var THEMES = ['dark', 'light', 'contrast'];
  var theme = 'dark';
  try {
    theme = localStorage.getItem('sappiwhere.theme') || 'dark';
  } catch (error) { theme = 'dark'; }
  if (THEMES.indexOf(theme) === -1) theme = 'dark';
  if (theme !== 'dark') document.documentElement.dataset.theme = theme;

  // Everything below paints the first tab of the application page; the
  // sign-in and SSH pages have no tabs and stop here.
  if (!/^\/(index\.html)?$/.test(window.location.pathname)) return;

  var DEFAULT_TAB = 'dashboard';
  var TABS = ['dashboard', 'nodes', 'alerts', 'netpath', 'netflow', 'snmp',
              'syslog', 'ipam', 'wireless', 'configrx', 'debug', 'settings'];
  var tab = null;
  // A hash route names the tab explicitly and beats the remembered one, the
  // same order app.js applies once it runs (its ROUTE_TABS must stay in
  // step with the list above). Reading it here is what stops a link to
  // #/alerts/998 painting the remembered tab for a frame first.
  try {
    var hash = String(window.location.hash || '').replace(/^#\/?/, '');
    var first = hash.split('?')[0].split('/')[0];
    if (TABS.indexOf(first) !== -1) tab = first;
  } catch (error) { /* fall through to the remembered tab */ }
  if (tab === null) {
    try {
      tab = localStorage.getItem('sappiwhere.tab') || DEFAULT_TAB;
    } catch (error) {
      // Private browsing, or storage disabled: fall back to the default tab
      // rather than leaving the attribute unset (which paints nothing).
      tab = DEFAULT_TAB;
    }
  }
  // Every name this file writes is a plain lower-case word. Anything else
  // came from a corrupted or hand-edited store, and it is about to be
  // interpolated into a selector, so it does not get the benefit of the
  // doubt. app.js does its own check against the tabs that actually exist;
  // this one only has to keep the generated rule well-formed.
  if (!/^[a-z]+$/.test(tab)) tab = DEFAULT_TAB;
  document.documentElement.dataset.tab = tab;

  /* The rule that actually paints the first frame.

     This used to be written out in app.css, one selector per tab, and that
     is how it rotted: the list named ten tabs while the product shipped
     twelve, so anyone whose last tab was Wireless or ConfigRX reloaded into
     a blank page — no page shown, no tab underlined — until app.js had
     finished loading half a megabyte of module scripts and run selectTab().
     Worse than the flash the mechanism exists to prevent. Generated from the
     stored name, the rule cannot fall behind the tab strip again.

     "Half a megabyte of module scripts" was true before 4.49.0 made every
     module but Dashboard load lazily, on first selection rather than
     unconditionally — a cold load's own scripts are tens of KB now, not
     hundreds. The flash this file exists to prevent got shorter; it did
     not go away. A remembered tab that is one of the eleven lazy modules
     still waits on that one module's own script fetch before its data can
     paint — smaller than before, since it is one script rather than all
     twelve, but not instant, and this file's own CSS-only illusion still
     covers exactly that gap the same way it always has.

     A <style> element is allowed where an inline <script> is not: the
     server sends `style-src 'self' 'unsafe-inline'`. Appending it to <head>
     puts it after app.css, so it wins on source order at equal specificity —
     which is why the one page that needs a different flex direction says so
     in app.css with a selector heavy enough to outweigh this. */
  var style = document.createElement('style');
  style.textContent =
    'html[data-tab="' + tab + '"] .tab[data-tab="' + tab + '"]' +
    '{color:var(--text);border-bottom-color:var(--accent)}' +
    'html[data-tab="' + tab + '"] #page-' + tab +
    '{display:flex;flex-direction:column}';
  document.head.appendChild(style);
})();

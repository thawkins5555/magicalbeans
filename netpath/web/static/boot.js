/* Marks which tab should paint first, before <body> has a single byte of
   content to render — see app.css's html[data-tab] rules.

   Loaded from <head> as a plain <script src> (no defer, no module) so it
   still blocks parsing right there, that split second before <body>,
   rather than racing it: the attribute is already set by the time any
   .tab/.page element exists, so there is no "wrong page" moment to flash.

   It lives in its own file rather than inline in index.html because the
   server sends `default-src 'self'` (server.py), under which an inline
   <script> is refused outright — the browser console showed exactly that,
   and this anti-flash pass never ran. Restoring the selected tab itself
   was never affected: app.js reads the same key on load and selects the
   tab regardless. This is only about painting it without a flicker.

   The key and the 'netpath' fallback must stay in step with app.js's own
   TAB_KEY / default tab. */
(function () {
  var TABS = ['dashboard', 'nodes', 'alerts', 'netpath', 'netflow', 'snmp',
              'syslog', 'ipam', 'wireless', 'configrx', 'debug', 'settings'];
  // A hash route names the tab explicitly and beats the remembered one, the
  // same order app.js applies once it runs (its ROUTE_TABS must stay in
  // step with the list above). Reading it here is what stops a link to
  // #/alerts/998 painting the remembered tab for a frame first.
  try {
    var hash = String(window.location.hash || '').replace(/^#\/?/, '');
    var first = hash.split('?')[0].split('/')[0];
    if (TABS.indexOf(first) !== -1) {
      document.documentElement.dataset.tab = first;
      return;
    }
  } catch (error) { /* fall through to the remembered tab */ }
  try {
    var stored = localStorage.getItem('sappiwhere.tab');
    document.documentElement.dataset.tab = stored || 'netpath';
  } catch (error) {
    // Private browsing, or storage disabled: fall back to the default tab
    // rather than leaving the attribute unset (which paints nothing).
    document.documentElement.dataset.tab = 'netpath';
  }
})();

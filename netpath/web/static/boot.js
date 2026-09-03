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
  var DEFAULT_TAB = 'netpath';
  var tab = DEFAULT_TAB;
  try {
    tab = localStorage.getItem('sappiwhere.tab') || DEFAULT_TAB;
  } catch (error) {
    // Private browsing, or storage disabled: fall back to the default tab
    // rather than leaving the attribute unset (which paints nothing).
    tab = DEFAULT_TAB;
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

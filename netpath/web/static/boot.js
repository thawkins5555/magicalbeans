/* Sets the theme and first-tab attributes and the rule that paints them,
   before <body> is parsed. Its own blocking file because the server sends
   `default-src 'self'`. Anti-flash only; the keys mirror app.js's. */
(function () {
  // Every page loads this. Dark is the default, and is the ABSENCE of the
  // attribute, so a browser that never chose stores nothing.
  var THEMES = ['dark', 'light', 'contrast', 'midnight', 'nord', 'solarized', 'slate'];
  var theme = 'dark';
  try {
    theme = localStorage.getItem('sappiwhere.theme') || 'dark';
  } catch (error) { theme = 'dark'; }
  if (THEMES.indexOf(theme) === -1) theme = 'dark';
  if (theme !== 'dark') document.documentElement.dataset.theme = theme;

  // The sign-in and SSH pages have no tabs and stop here.
  if (!/^\/(index\.html)?$/.test(window.location.pathname)) return;

  var DEFAULT_TAB = 'dashboard';
  var TABS = ['dashboard', 'nodes', 'alerts', 'netpath', 'netflow', 'snmp',
              'syslog', 'ipam', 'wireless', 'configrx', 'mapper', 'debug',
              'settings'];
  var tab = null;
  // A hash route beats the remembered tab, the order app.js applies too.
  try {
    var hash = String(window.location.hash || '').replace(/^#\/?/, '');
    var first = hash.split('?')[0].split('/')[0];
    if (TABS.indexOf(first) !== -1) tab = first;
  } catch (error) { /* fall through to the remembered tab */ }
  if (tab === null) {
    try {
      tab = localStorage.getItem('sappiwhere.tab') || DEFAULT_TAB;
    } catch (error) { tab = DEFAULT_TAB; }
  }
  // About to be interpolated into a selector.
  if (!/^[a-z]+$/.test(tab)) tab = DEFAULT_TAB;
  document.documentElement.dataset.tab = tab;

  /* Generated from the stored name, not written per tab in app.css, where
     that list rotted once. A <style> is allowed where an inline <script> is
     not, and lands after app.css, so it wins at equal specificity. */
  var style = document.createElement('style');
  style.textContent =
    'html[data-tab="' + tab + '"] .tab[data-tab="' + tab + '"]' +
    '{color:var(--text);border-bottom-color:var(--accent)}' +
    'html[data-tab="' + tab + '"] #page-' + tab +
    '{display:flex;flex-direction:column}';
  document.head.appendChild(style);
})();

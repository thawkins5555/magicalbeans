Vendored third-party frontend libraries
=======================================

Content Security Policy here is `default-src 'self'`, and the appliance is
often installed on a network with no route to the public internet, so a CDN
is not an option: the few third-party browser libraries this application
uses are checked in, unmodified, and served from /vendor/ like any other
static file. There is no build step; these are the published UMD bundles.

  xterm.js              5.5.0    npm registry, package `@xterm/xterm`
                                 (lib/xterm.js, css/xterm.css)
                                 exposes window.Terminal
  @xterm/addon-fit      0.10.0   npm registry, package `@xterm/addon-fit`
                                 (lib/addon-fit.js)
                                 exposes window.FitAddon.FitAddon

Both are MIT licensed by the xterm.js authors; the licence text they ship
with is LICENSE-xterm.txt (identical in both packages).

Updating one means replacing the file with the new release's bundle byte for
byte, updating the version above, and nothing else. Never patch a file here:
a local fix is invisible to the next update and would be silently lost.

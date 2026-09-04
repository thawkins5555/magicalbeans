/* The SSH window.

   A standalone page like login.html: it shares app.css and nothing else, so
   none of the application's own machinery (boot.js, app.js, the refresh
   loop, App.modal) is loaded into a window that exists to hold one terminal.
   Everything below talks to one WebSocket, whose protocol is documented in
   INTERNALS: text frames are JSON control messages in both directions,
   binary frames are terminal bytes.

   xterm.js and its fit addon are vendored under /vendor/ (see
   vendor/README.txt) — the CSP here is `default-src 'self'` and appliances
   are routinely installed with no route out, so a CDN is not an option. */
(() => {
  'use strict';

  const params = new URLSearchParams(window.location.search);
  const deviceId = Number(params.get('device')) || 0;
  /* The opener passes the display name so the window has a title and a
     header before the first API call answers; displayName() itself is
     private to nodes.js and the precedence it encodes is not worth
     duplicating here. Whatever the API returns wins once it arrives. */
  const openerName = params.get('name') || '';

  const el = (id) => document.getElementById(id);
  const nameEl = el('ssh-name');
  const ipEl = el('ssh-ip');
  const statusEl = el('ssh-status');
  const noticeEl = el('ssh-notice');
  const termEl = el('ssh-term');
  const logEl = el('ssh-log');
  const reconnectBtn = el('ssh-reconnect');
  const disconnectBtn = el('ssh-disconnect');
  const credsBox = el('ssh-creds');
  const credsForm = el('ssh-creds-form');
  const hostkeyBox = el('ssh-hostkey');

  let term = null;
  let fitAddon = null;
  let socket = null;
  let device = null;          // {id, ip, name, ssh_port}
  let storedUsername = '';
  let lastSize = { cols: 0, rows: 0 };
  const encoder = new TextEncoder();

  /* Close codes the server uses (INTERNALS: the WebSocket protocol).
     Anything else is reported by number, which is more use to whoever is
     reading it than a flat "connection lost". */
  const CLOSE_WORDS = {
    1000: '',
    1001: 'the window is closing',
    1006: 'the connection to the server was lost',
    1011: 'the server hit an internal error',
    4401: 'you are not signed in',
    4408: 'the session was idle for too long',
    4429: 'too many SSH sessions are already open',
  };

  // -------------------------------------------------------------- chrome

  function setStatus(kind, text) {
    statusEl.textContent = text;
    statusEl.className = 'ssh-status is-' + kind;
    disconnectBtn.disabled = !(socket && socket.readyState === WebSocket.OPEN);
  }

  /* The notice bar sits above the terminal and takes its own height when it
     is shown, so showing or hiding one changes how many rows are left. Refit
     afterwards or the bottom rows — the prompt among them — stay clipped
     until the window happens to be resized. */
  function setNotice(text, kind) {
    noticeEl.textContent = text || '';
    noticeEl.className = 'ssh-notice' + (kind ? ' is-' + kind : '');
    noticeEl.hidden = !text;
    fit();
  }

  function setTitle() {
    const shown = nameEl.textContent || openerName || 'device';
    const ip = device ? device.ip : '';
    document.title = ip ? `SSH — ${shown} (${ip})` : `SSH — ${shown}`;
    // xterm renders to a canvas a screen reader cannot see; the accessible
    // name at least says whose shell a tab lands the operator in.
    termEl.setAttribute('aria-label',
      ip ? `Terminal session with ${shown} (${ip})` : `Terminal session with ${shown}`);
  }

  function show(box, visible) {
    box.hidden = !visible;
  }

  // -------------------------------------------------------------- sr log

  /* #ssh-log mirrors completed lines of device output as plain text, for a
     screen reader that cannot read xterm's canvas even with screenReaderMode
     on. Buffered rather than pushed byte-for-byte: a device echoes typed
     characters back one at a time, and announcing a line before Enter ends
     it would read every keystroke of a typed username out loud. */
  const logDecoder = new TextDecoder();
  let logBuffer = '';
  const LOG_MAX_LINES = 500;

  function stripAnsi(text) {
    return text
      .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, '')   // OSC (title-setting, etc.)
      .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '')             // CSI (colour, cursor movement)
      .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');      // stray control bytes
  }

  function logLine(text) {
    if (!logEl || !text) return;
    for (const line of stripAnsi(text).split('\n')) {
      const trimmed = line.replace(/\r$/, '');
      if (!trimmed) continue;
      const div = document.createElement('div');
      div.textContent = trimmed;
      logEl.appendChild(div);
    }
    while (logEl.childElementCount > LOG_MAX_LINES) logEl.removeChild(logEl.firstChild);
  }

  function logOutputBytes(bytes) {
    logBuffer += logDecoder.decode(bytes, { stream: true });
    let newline;
    while ((newline = logBuffer.indexOf('\n')) !== -1) {
      logLine(logBuffer.slice(0, newline));
      logBuffer = logBuffer.slice(newline + 1);
    }
  }

  /* Written into the terminal rather than onto the one-line notice: connect
     failures carry ConfigRX's guidance text, which runs to several lines and
     matters more than it fits. */
  function writeMessage(text, colour) {
    if (!term || !text) return;
    logLine(text);
    const colourOn = colour === 'error' ? '\u001b[31m' : '\u001b[33m';
    term.write('\r\n' + colourOn + text.replace(/\n/g, '\r\n') + '\u001b[0m\r\n');
  }

  // ------------------------------------------------------------ terminal

  function cssVar(name, fallback) {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
    return value || fallback;
  }

  /* The palette is the application's, read from the CSS variables rather
     than copied, so the terminal keeps matching the rest of the product if
     those ever move. */
  function theme() {
    const fg = cssVar('--text', '#DCE3EA');
    return {
      background: cssVar('--bg', '#0E1116'),
      foreground: fg,
      cursor: cssVar('--accent', '#7AA2F7'),
      cursorAccent: cssVar('--bg', '#0E1116'),
      selectionBackground: cssVar('--checked-strong', '#2E4470'),
      black: cssVar('--nodata', '#1E242D'),
      red: cssVar('--fail', '#F8544C'),
      green: cssVar('--ok', '#3FB950'),
      yellow: cssVar('--warn', '#E3B341'),
      blue: cssVar('--accent', '#7AA2F7'),
      magenta: cssVar('--error', '#A371F7'),
      cyan: cssVar('--overrun', '#4DB6AC'),
      white: fg,
      brightBlack: cssVar('--line', '#646E7C'),
      brightWhite: '#FFFFFF',
    };
  }

  function buildTerminal() {
    if (!window.Terminal) {
      setStatus('error', 'The terminal library did not load');
      return false;
    }
    // Defensive: nothing today calls buildTerminal() a second time, but a
    // reconnect that ever grows one must not leave the previous Terminal's
    // helper textarea behind, stacked a second time in the tab order.
    if (term) {
      term.dispose();
      term = null;
      fitAddon = null;
    }
    term = new window.Terminal({
      fontFamily: cssVar('--mono', 'monospace'),
      fontSize: 13,
      theme: theme(),
      cursorBlink: true,
      scrollback: 5000,
      // The device decides what a newline means; translating here would
      // corrupt anything full-screen (a vendor menu, top, vi).
      convertEol: false,
      // xterm's own accessibility layer: a live region that tracks what is
      // actually rendered, on top of #ssh-log's own coarser line-by-line one.
      screenReaderMode: true,
    });
    if (window.FitAddon && window.FitAddon.FitAddon) {
      fitAddon = new window.FitAddon.FitAddon();
      term.loadAddon(fitAddon);
    }
    term.open(termEl);
    /* #ssh-term, not this textarea, is the one stop in the tab order — see
       the focus listener below, which hands real keyboard focus on to it. */
    const helper = termEl.querySelector('.xterm-helper-textarea');
    if (helper) helper.tabIndex = -1;
    if (!termEl.dataset.focusWired) {
      termEl.dataset.focusWired = '1';
      termEl.addEventListener('focus', () => { if (term) term.focus(); });
    }
    /* Escape is a real keystroke inside plenty of shell programs (vi among
       them), so it is not simply swallowed — attachCustomKeyEventHandler
       runs before xterm decides what to do with a key, and returning false
       here is what stops this one short of the pty. Documented in the hint
       line under the header, since a trap with no escape is a WCAG failure
       whichever key gets you out. */
    term.attachCustomKeyEventHandler((event) => {
      if (event.type === 'keydown' && event.key === 'Escape') {
        reconnectBtn.focus();
        return false;
      }
      return true;
    });
    /* Keystrokes go out as binary frames exactly as typed; the server
       forwards them to the channel without looking at them. */
    term.onData((data) => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(encoder.encode(data));
      }
    });
    fit();
    return true;
  }

  /* Sizes the terminal to the window and records the result in lastSize,
     telling nobody. Returns true when the size actually changed. Kept apart
     from fit() because the size is needed before the session exists: the
     `open` message carries it, and a `resize` that arrives first is a
     protocol error the server closes the socket on. */
  function measure() {
    if (!fitAddon) return false;
    try {
      fitAddon.fit();
    } catch (error) {
      return false;      // the window can still be 0x0 while it is opening
    }
    const cols = term.cols;
    const rows = term.rows;
    if (cols === lastSize.cols && rows === lastSize.rows) return false;
    lastSize = { cols, rows };
    return true;
  }

  function fit() {
    if (measure() && socket && socket.readyState === WebSocket.OPEN) {
      send({ type: 'resize', cols: lastSize.cols, rows: lastSize.rows });
    }
  }

  let fitTimer = null;
  window.addEventListener('resize', () => {
    window.clearTimeout(fitTimer);
    fitTimer = window.setTimeout(fit, 80);
  });

  // ----------------------------------------------------------- transport

  function send(message) {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(message));
    }
  }

  function socketUrl() {
    const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${scheme}//${window.location.host}/api/ssh/devices/${deviceId}/socket`;
  }

  function connect() {
    closeSocket(1000, 'reconnecting');
    show(credsBox, false);
    show(hostkeyBox, false);
    setStatus('connecting', 'Connecting…');
    let ws;
    try {
      ws = new WebSocket(socketUrl());
    } catch (error) {
      setStatus('error', 'Could not open the connection');
      return;
    }
    socket = ws;
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      if (socket !== ws) return;
      // Measure before the first message: the server sizes the pty from the
      // cols/rows in `open`, and a wrong size there is a wrapped prompt for
      // the life of the session. measure() rather than fit() because `open`
      // has to be the first message on the socket — anything a notice shown
      // in the meantime changed rides out in `open` itself, and every later
      // change goes as a `resize` through fit().
      measure();
      send({ type: 'open', cols: lastSize.cols || 80, rows: lastSize.rows || 24 });
      setStatus('connecting', 'Opening the session…');
    };

    ws.onmessage = (event) => {
      if (socket !== ws) return;
      if (typeof event.data === 'string') {
        let message;
        try {
          message = JSON.parse(event.data);
        } catch (error) {
          return;
        }
        handleControl(message);
        return;
      }
      const bytes = new Uint8Array(event.data);
      if (term) term.write(bytes);
      logOutputBytes(bytes);
    };

    ws.onerror = () => {
      if (socket !== ws) return;
      // onclose always follows, and carries the code worth reporting.
      setStatus('error', 'Connection error');
    };

    ws.onclose = (event) => {
      if (socket !== ws) return;
      socket = null;
      if (event.code === 4401) {
        window.location.href = '/login';
        return;
      }
      const words = CLOSE_WORDS[event.code];
      const why = words !== undefined ? words
        : `the connection closed (code ${event.code})`;
      setStatus('closed', why ? `Disconnected — ${why}` : 'Disconnected');
      if (why) setNotice(`Disconnected — ${why}.`, event.code >= 4400 ? 'warn' : '');
    };
  }

  function closeSocket(code, reason) {
    if (!socket) return;
    const ws = socket;
    socket = null;
    ws.onclose = null;
    ws.onerror = null;
    ws.onmessage = null;
    try {
      ws.close(code, reason);
    } catch (error) { /* already gone; nothing to be done about it */ }
  }

  function handleControl(message) {
    switch (message.type) {
      case 'status':
        if (message.state === 'connected') {
          show(credsBox, false);
          show(hostkeyBox, false);
          setStatus('connected', message.message || 'Connected');
          if (term) term.focus();
        } else if (message.state === 'connecting') {
          setStatus('connecting', message.message || 'Connecting…');
        } else {
          setStatus('closed', message.message || 'Disconnected');
        }
        break;

      case 'need-credentials':
        askForCredentials(message);
        break;

      case 'hostkey':
        if (message.event === 'changed') {
          showHostKeyWarning(message);
        } else {
          setNotice(`Host key ${message.fingerprint}` +
            (message.key_type ? ` (${message.key_type})` : '') +
            ' stored on this first connection.');
        }
        break;

      case 'error': {
        const friendly = friendlyError(message.message);
        setStatus('error', firstLine(friendly) || 'Failed');
        writeMessage(friendly, 'error');
        break;
      }

      default:
        break;      // an unknown control message is not worth a failure
    }
  }

  function firstLine(text) {
    return (text || '').split('\n')[0].trim();
  }

  /* paramiko surfaces a bare socket.error on a failed TCP connect —
     "[Errno None] Unable to connect to port 2201 on 127.0.0.250" — which
     names neither the fix nor where to make it. Recognise that shape and
     say what an operator actually needs instead. */
  function friendlyError(text) {
    const raw = text || '';
    if (!/unable to connect to port/i.test(raw) && !/^\[errno/i.test(raw)) return raw;
    const host = device && device.ip ? device.ip : 'the device';
    const port = device && device.ssh_port ? device.ssh_port : '';
    return `Could not reach ${host}${port ? `:${port}` : ''} over SSH. Check that ` +
      'the device is reachable and listening on that port, or change the port ' +
      'under ConfigRX → Device settings.';
  }

  // ------------------------------------------------------------ overlays

  const CRED_REASONS = {
    'none-stored': 'No SSH credential is stored for this device in ConfigRX.',
    'auth-failed': 'The stored credential was refused by the device.',
    'decrypt-failed': 'The stored password could not be decrypted on this machine.',
  };

  function askForCredentials(message) {
    el('ssh-creds-host').textContent = device ? device.ip : '';
    el('ssh-creds-why').textContent =
      CRED_REASONS[message.reason] || 'The device is asking for credentials.';
    const user = el('ssh-user');
    const pass = el('ssh-pass');
    storedUsername = message.username || storedUsername;
    user.value = storedUsername;
    pass.value = '';
    show(credsBox, true);
    setStatus('connecting', 'Waiting for credentials');
    (storedUsername ? pass : user).focus();
  }

  credsForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const user = el('ssh-user');
    const pass = el('ssh-pass');
    if (!user.value.trim()) {
      user.focus();
      return;
    }
    send({ type: 'auth', username: user.value.trim(), password: pass.value });
    // Nothing typed here is kept: the field is emptied the moment it has
    // been sent, and the page never puts it anywhere else.
    pass.value = '';
    show(credsBox, false);
    setStatus('connecting', 'Signing in…');
  });

  function showHostKeyWarning(message) {
    el('ssh-hk-ip').textContent = device ? device.ip : '';
    el('ssh-hk-old').textContent = message.old_fingerprint || 'unknown';
    el('ssh-hk-new').textContent = message.fingerprint || 'unknown';
    el('ssh-hk-since').textContent = message.old_first_seen
      ? new Date(message.old_first_seen * 1000).toLocaleString() : 'unknown';
    show(hostkeyBox, true);
    setStatus('error', 'Host key changed — nothing was sent');
    setNotice('The host key for this device has changed. The connection was ' +
      'refused.', 'error');
  }

  el('ssh-hk-trust').addEventListener('click', () => {
    show(hostkeyBox, false);
    setNotice('');
    setStatus('connecting', 'Trusting the new key…');
    send({ type: 'trust' });
  });

  el('ssh-hk-cancel').addEventListener('click', () => {
    show(hostkeyBox, false);
    closeSocket(1000, 'host key not trusted');
    setStatus('closed', 'Disconnected — the new host key was not trusted');
  });

  // -------------------------------------------------------------- header

  reconnectBtn.addEventListener('click', () => {
    setNotice('');
    if (device) connect();
    else load();
  });

  disconnectBtn.addEventListener('click', () => {
    closeSocket(1000, 'closed by the operator');
    setStatus('closed', 'Disconnected');
    setNotice('');
  });

  /* A closed window must not leave a session (and an SSH channel into the
     device) open behind it: the server tears the session down when the
     socket closes, so closing it here is the whole cleanup. */
  window.addEventListener('beforeunload', () => {
    closeSocket(1000, 'window closed');
  });

  // ---------------------------------------------------------------- boot

  async function load() {
    setStatus('connecting', 'Looking the device up…');
    let response;
    try {
      response = await fetch(`/api/ssh/devices/${deviceId}`,
        { headers: { Accept: 'application/json' } });
    } catch (error) {
      setStatus('error', 'The server did not answer. It may have stopped.');
      return;
    }
    if (response.status === 401) {
      window.location.href = '/login';
      return;
    }
    const payload = await response.json().catch(() => ({}));
    if (response.status === 403) {
      setStatus('error', 'Your account has no SSH access');
      setNotice('Your account has no SSH access. An administrator grants it ' +
        'under Settings, as write on the SSH module.', 'warn');
      return;
    }
    if (!response.ok) {
      // This also covers the route being absent altogether (an older server,
      // or one whose SSH service failed to start): a connection problem,
      // said in the one place this window says connection problems.
      const detail = payload.error ? `${payload.error} (HTTP ${response.status})`
        : `HTTP ${response.status}`;
      setStatus('error', `Could not reach the SSH service — ${detail}`);
      setNotice(`Could not reach the SSH service — ${detail}.`, 'error');
      return;
    }

    device = payload.device || { id: deviceId, ip: '' };
    device.ssh_port = payload.ssh_port || 22;
    // The server resolves the display-name precedence once and sends the
    // answer as `name`; the opener's name is only the stand-in until it does.
    nameEl.textContent = device.name || openerName;
    ipEl.textContent = device.ip ? `${device.ip}:${device.ssh_port}` : '';
    setTitle();

    const paramiko = payload.paramiko || {};
    if (!paramiko.available) {
      setStatus('error', 'SSH is unavailable on this server');
      setNotice(paramiko.message || 'The paramiko library is not installed.',
        'error');
      return;
    }
    if (!payload.has_credential) {
      setNotice('No SSH credential is stored for this device; you will be ' +
        'asked for one.');
    }
    connect();
  }

  nameEl.textContent = openerName;
  setTitle();
  if (!deviceId) {
    setStatus('error', 'No device was named in the address');
  } else if (buildTerminal()) {
    load();
  }
})();

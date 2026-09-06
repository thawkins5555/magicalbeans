/* The SSH terminal: a standalone page like login.html, sharing only
   app.css. One WebSocket carries the session — text frames are JSON
   control messages, binary frames are terminal bytes (see INTERNALS).
   Vendored xterm.js 5.5.0 and addon-fit 0.10.0 are checked in unmodified;
   see vendor/LICENSE-xterm.txt. */
(() => {
  'use strict';

  const params = new URLSearchParams(window.location.search);
  const deviceId = Number(params.get('device')) || 0;
  // The opener's name is a placeholder; the API's own answer wins once it arrives.
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

  // Close codes the server uses (INTERNALS); anything else is reported by number.
  const CLOSE_WORDS = {
    1000: '',
    1001: 'the window is closing',
    1006: 'the connection to the server was lost',
    1011: 'the server hit an internal error',
    4401: 'you are not signed in',
    4408: 'the session was idle for too long',
    4429: 'too many SSH sessions are already open',
  };

  function setStatus(kind, text) {
    statusEl.textContent = text;
    statusEl.className = 'ssh-status is-' + kind;
    disconnectBtn.disabled = !(socket && socket.readyState === WebSocket.OPEN);
  }

  // Showing/hiding the notice changes how many rows are left; refit or the bottom rows stay clipped.
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
    // xterm renders to a canvas a screen reader cannot see; this at least names whose shell it is.
    termEl.setAttribute('aria-label',
      ip ? `Terminal session with ${shown} (${ip})` : `Terminal session with ${shown}`);
  }

  function show(box, visible) {
    box.hidden = !visible;
  }

  // #ssh-log mirrors completed output lines as plain text for a screen reader,
  // which cannot read xterm's canvas; buffered, or a typed username would be
  // announced one keystroke at a time.
  const logDecoder = new TextDecoder();
  let logBuffer = '';
  const LOG_MAX_LINES = 500;
  // Most device prompts carry no trailing newline, so a line is announced after a short idle gap.
  const LOG_IDLE_MS = 400;
  let logIdleTimer = null;

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
    window.clearTimeout(logIdleTimer);
    logBuffer += logDecoder.decode(bytes, { stream: true });
    let newline;
    while ((newline = logBuffer.indexOf('\n')) !== -1) {
      logLine(logBuffer.slice(0, newline));
      logBuffer = logBuffer.slice(newline + 1);
    }
    if (logBuffer) {
      logIdleTimer = window.setTimeout(() => {
        if (!logBuffer) return;
        logLine(logBuffer);
        logBuffer = '';
      }, LOG_IDLE_MS);
    }
  }

  // Written into the terminal, not the one-line notice: connect failures carry guidance text that runs to several lines.
  function writeMessage(text, colour) {
    if (!term || !text) return;
    logLine(text);
    const colourOn = colour === 'error' ? '\u001b[31m' : '\u001b[33m';
    term.write('\r\n' + colourOn + text.replace(/\n/g, '\r\n') + '\u001b[0m\r\n');
  }

  function cssVar(name, fallback) {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
    return value || fallback;
  }

  // Reads the application's tokens rather than copying them; black/white/brightBlack/brightWhite follow the resolved theme.
  function ansiColors() {
    const light = document.documentElement.getAttribute('data-theme') === 'light';
    const red = cssVar('--fail', '#F8544C'), green = cssVar('--ok', '#3FB950'),
          yellow = cssVar('--warn', '#E3B341'), blue = cssVar('--accent', '#7AA2F7'),
          magenta = cssVar('--error', '#A371F7'), cyan = cssVar('--overrun', '#4DB6AC');
    return {
      black: light ? cssVar('--text', '#161C24') : cssVar('--nodata', '#1E242D'),
      brightBlack: light ? cssVar('--muted', '#4E5967') : cssVar('--line', '#646E7C'),
      white: light ? cssVar('--dim', '#5E6975') : cssVar('--text', '#DCE3EA'),
      brightWhite: light ? cssVar('--line', '#76818F') : cssVar('--text', '#DCE3EA'),
      red, green, yellow, blue, magenta, cyan,
      brightRed: red, brightGreen: green, brightYellow: yellow,
      brightBlue: cssVar('--accent-hover', '#97B6FF'),
      brightMagenta: magenta, brightCyan: cyan,
    };
  }

  function theme() {
    return {
      background: cssVar('--bg', '#0E1116'),
      foreground: cssVar('--text', '#DCE3EA'),
      cursor: cssVar('--accent', '#7AA2F7'),
      cursorAccent: cssVar('--bg', '#0E1116'),
      selectionBackground: cssVar('--checked-strong', '#2E4470'),
      ...ansiColors(),
    };
  }

  function buildTerminal() {
    if (!window.Terminal) {
      setStatus('error', 'The terminal library did not load');
      return false;
    }
    // Defensive: a second call must not leave the previous Terminal's helper textarea stacked in the tab order.
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
      // The device decides what a newline means; translating here would corrupt anything full-screen (a menu, top, vi).
      convertEol: false,
      // xterm's own live-region accessibility layer, on top of #ssh-log.
      screenReaderMode: true,
    });
    if (window.FitAddon && window.FitAddon.FitAddon) {
      fitAddon = new window.FitAddon.FitAddon();
      term.loadAddon(fitAddon);
    }
    term.open(termEl);
    // #ssh-term, not this textarea, is the one stop in the tab order; the focus listener below hands focus on to it.
    const helper = termEl.querySelector('.xterm-helper-textarea');
    if (helper) helper.tabIndex = -1;
    if (!termEl.dataset.focusWired) {
      termEl.dataset.focusWired = '1';
      termEl.addEventListener('focus', () => { if (term) term.focus(); });
    }
    // A terminal that keeps Tab needs another way out or it is a keyboard trap. Ctrl+F6, not Escape, since Escape
    // is a real keystroke to the device (vi, less, a menu console); documented in the hint line under the header.
    term.attachCustomKeyEventHandler((event) => {
      if (event.type === 'keydown' && event.key === 'F6' && event.ctrlKey) {
        reconnectBtn.focus();
        return false;
      }
      return true;
    });
    // Keystrokes go out as binary frames exactly as typed.
    term.onData((data) => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(encoder.encode(data));
      }
    });
    fit();
    return true;
  }

  // Sizes the terminal and records it in lastSize; returns true if it changed. Kept apart from fit() because the
  // size is needed before the session exists — a `resize` before `open` is a protocol error.
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
    // A reconnect starts a new device session; a partial line left over from the last one must not be glued on.
    window.clearTimeout(logIdleTimer);
    logBuffer = '';
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
      // The server sizes the pty from `open`'s cols/rows, so measure() (not fit()) runs first — `open` is sent first.
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
        handleControl(message, ws);
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
      // Prefer the server's own status:closed message (stashed on this socket by handleControl) over the fixed
      // CLOSE_WORDS phrase; kept on the socket itself so an unrelated close on a different socket never inherits it.
      if (ws.__closeMessage) {
        setStatus('closed', ws.__closeMessage);
        setNotice(`${ws.__closeMessage}.`, event.code >= 4400 ? 'warn' : '');
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

  function handleControl(message, ws) {
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
          // Only when this frame actually carries one; ws.onclose reads this before falling back to CLOSE_WORDS.
          if (ws && message.message) ws.__closeMessage = message.message;
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

  // paramiko surfaces a bare socket.error on a failed TCP connect; recognise that shape and say what an operator needs.
  function friendlyError(text) {
    const raw = text || '';
    if (!/unable to connect to port/i.test(raw) && !/^\[errno/i.test(raw)) return raw;
    const host = device && device.ip ? device.ip : 'the device';
    const port = device && device.ssh_port ? device.ssh_port : '';
    return `Could not reach ${host}${port ? `:${port}` : ''} over SSH. Check that ` +
      'the device is reachable and listening on that port, or change the port ' +
      'under ConfigRX → Device settings.';
  }

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
    // Nothing typed here is kept: the field is emptied the moment it is sent.
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

  // A closed window must not leave the device's SSH channel open; the server tears the session down on close.
  window.addEventListener('beforeunload', () => {
    closeSocket(1000, 'window closed');
  });

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
      // Also covers the route being absent (an older server, or one whose SSH service failed to start).
      const detail = payload.error ? `${payload.error} (HTTP ${response.status})`
        : `HTTP ${response.status}`;
      setStatus('error', `Could not reach the SSH service — ${detail}`);
      setNotice(`Could not reach the SSH service — ${detail}.`, 'error');
      return;
    }

    device = payload.device || { id: deviceId, ip: '' };
    device.ssh_port = payload.ssh_port || 22;
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

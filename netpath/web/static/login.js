// The sign-in page: shares the stylesheet and nothing else of the application.
(() => {
  const form = document.getElementById('login-form');
  const error = document.getElementById('login-error');
  const button = document.getElementById('login-button');

  function show(message) {
    error.textContent = message;
    error.hidden = !message;
    for (const id of ['username', 'password']) {
      const field = document.getElementById(id);
      if (!field) continue;
      if (message) field.setAttribute('aria-invalid', 'true');
      else field.removeAttribute('aria-invalid');
    }
  }

  async function submit(event) {
    event.preventDefault();
    show('');
    button.disabled = true;
    button.textContent = 'Signing in…';

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
        }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        // The server is vague on purpose; do not add detail here either.
        show(payload.error || 'Could not sign in');
        document.getElementById('password').value = '';
        document.getElementById('password').focus();
        return;
      }
      // A fresh sign-in lands on Dashboard; app.js's reload-preserves-tab
      // logic takes over for every reload after this one.
      try { localStorage.setItem('sappiwhere.tab', 'dashboard'); } catch (e) { /* private browsing, or storage full */ }
      // ...unless a redirect (e.g. a 401 on #/alerts/998) preserved a hash to finish the journey to.
      const wanted = String(window.location.hash || '');
      // The query string rides along too, so a kiosk link bounced through sign-in still comes back as one.
      const search = String(window.location.search || '');
      window.location.href = `/${search}${wanted.startsWith('#/') ? wanted : ''}`;
    } catch (err) {
      show('The server did not answer. It may have stopped.');
    } finally {
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  }

  form.addEventListener('submit', submit);

  // Already signed in? Do not make them type it again; on a fresh install, say the default account exists.
  fetch('/api/session')
    .then((r) => r.json())
    .then((d) => {
      if (d.authenticated) { window.location.href = '/'; return; }
      const note = document.getElementById('login-note');
      if (note && d.first_run) {
        note.hidden = false;
        const user = document.getElementById('username');
        if (user && !user.value) user.value = 'admin';
      }
      // Not every build sends d.version, so this draws only once something supplies one.
      const versionEl = document.getElementById('login-version');
      if (versionEl && d.version) {
        versionEl.textContent = `v${d.version}`;
        versionEl.hidden = false;
      }
    })
    .catch(() => {});
})();

/* The sign-in page. Deliberately small: it shares the stylesheet and nothing
   else, so none of the application loads for someone who is not signed in. */
(() => {
  const form = document.getElementById('login-form');
  const error = document.getElementById('login-error');
  const button = document.getElementById('login-button');

  function show(message) {
    error.textContent = message;
    error.hidden = !message;
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
      // A fresh sign-in always lands on Dashboard, whatever tab was open
      // last time — app.js's own reload-preserves-tab logic (same
      // 'sappiwhere.tab' key) takes over for every reload after this one.
      try { localStorage.setItem('sappiwhere.tab', 'dashboard'); } catch (e) { /* private browsing, or storage full: not worth failing */ }
      // ...unless they were sent here from a link. A 401 on #/alerts/998
      // redirects to /login, and signing in should finish the journey rather
      // than dropping them on the Dashboard with the link lost. The hash is
      // preserved by the redirect, so it is still here to hand back.
      const wanted = String(window.location.hash || '');
      // The query string rides along too: a wall display opened as
      // /?kiosk=1 and bounced through sign-in should come back as one.
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

  // Already signed in? Do not make them type it again. And on a fresh
  // install nobody has signed in to, say that the default account exists.
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
    })
    .catch(() => {});
})();

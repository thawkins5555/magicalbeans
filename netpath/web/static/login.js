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
      window.location.href = '/';
    } catch (err) {
      show('The server did not answer. It may have stopped.');
    } finally {
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  }

  form.addEventListener('submit', submit);

  // Already signed in? Do not make them type it again.
  fetch('/api/session')
    .then((r) => r.json())
    .then((d) => { if (d.authenticated) window.location.href = '/'; })
    .catch(() => {});
})();

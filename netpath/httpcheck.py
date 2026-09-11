"""Is the web page on this destination answering?

A traceroute says the path to a destination works; it says nothing about
whether the thing at the end of it is serving anything. This module is the
other half: one HTTPS GET, mapped onto available / unavailable-with-a-reason.

GET rather than HEAD deliberately — a great many servers answer HEAD with 405
and would be reported down while serving the page perfectly. The body is read
only far enough to prove the response is real (MAX_BODY_BYTES) and discarded.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request

from dataclasses import dataclass

from . import __version__

USER_AGENT = f"SappiWhere/{__version__}"

# Follow a redirect chain this far and no further. A site that bounces
# through a login and a region picker is normal; a loop is not.
MAX_REDIRECTS = 5

# Enough to prove a response body exists without pulling a disk image
# through a monitoring check every interval.
MAX_BODY_BYTES = 64 * 1024

# The longest an operator-configured URL may be, matching what the API
# refuses past.
URL_MAX = 2048

DEFAULT_TIMEOUT_S = 10.0

# An error string is stored on every failed check and rendered in a badge.
ERROR_MAX = 200


@dataclass
class HttpsResult:
    ok: bool
    status_code: int | None = None
    latency_ms: float | None = None
    error: str = ""
    final_url: str = ""


class _CountedRedirects(urllib.request.HTTPRedirectHandler):
    """Follow, but only so far, and never off HTTPS.

    redirect_request is the one extension point every 3xx handler calls
    through (the shape alertmail._RefuseRedirects uses to refuse them), so
    counting here covers 301/302/303/307/308 rather than only the couple
    urllib's own handler names. A redirect onto plain HTTP is refused
    outright: the destination was configured as an HTTPS URL, and quietly
    measuring an unverified cleartext page instead would be answering a
    different question.
    """

    # Above MAX_REDIRECTS, so urllib's own two guards never fire first and
    # report a chain that is merely long as an HTTP error from the last hop.
    max_repeats = MAX_REDIRECTS + 1
    max_redirections = MAX_REDIRECTS + 1

    def __init__(self) -> None:
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(f"redirect to a non-HTTPS URL ({newurl})")
        self.count += 1
        if self.count > MAX_REDIRECTS:
            raise urllib.error.URLError(f"more than {MAX_REDIRECTS} redirects")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def is_https_url(url: str) -> bool:
    return bool(url) and url.strip().lower().startswith("https://")


def _tls_text(error) -> str:
    message = getattr(error, "verify_message", "") or getattr(error, "reason", "")
    return f"TLS: {message}" if message else "TLS: handshake failed"


def _error_text(error) -> str:
    """The short reason a check failed, as it is stored and shown."""
    if isinstance(error, ssl.SSLCertVerificationError):
        return f"TLS: certificate verify failed ({error.verify_message})" \
            if error.verify_message else "TLS: certificate verify failed"
    if isinstance(error, ssl.SSLError):
        return _tls_text(error)
    if isinstance(error, socket.gaierror):
        return f"DNS: {error.strerror or error}"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, urllib.error.URLError):
        reason = error.reason
        return _error_text(reason) if isinstance(reason, BaseException) else str(reason)
    if isinstance(error, OSError) and error.strerror:
        return str(error.strerror)
    return str(error) or type(error).__name__


def check(url: str, timeout_s: float = DEFAULT_TIMEOUT_S,
          insecure: bool = False) -> HttpsResult:
    """One GET. 2xx/3xx is available; everything else is not, with the reason.

    Certificates are verified against the system store plus the vendored
    bundle (selfupdate._ssl_context, the same context every other outbound
    HTTPS call here uses) unless the destination opted out with `insecure`,
    which is for the appliances whose management page ships a self-signed
    certificate nobody is going to replace.
    """
    url = (url or "").strip()
    if not is_https_url(url):
        return HttpsResult(False, error="URL must start with https://")
    if insecure:
        context = ssl._create_unverified_context()
    else:
        from . import selfupdate
        context = selfupdate._ssl_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), _CountedRedirects())
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout_s) as response:
            response.read(MAX_BODY_BYTES)
            code = int(response.getcode() or 0)
            final = response.geturl() or url
        latency = (time.monotonic() - started) * 1000.0
        ok = 200 <= code < 400
        return HttpsResult(ok, code, latency, "" if ok else f"HTTP {code}", final)
    except urllib.error.HTTPError as error:
        # The server answered, which is a real measurement of an unhealthy
        # page rather than a failure to reach one.
        try:
            error.read(MAX_BODY_BYTES)
        except Exception:
            pass
        code = int(error.code or 0)
        return HttpsResult(False, code, (time.monotonic() - started) * 1000.0,
                           f"HTTP {code}"[:ERROR_MAX], error.geturl() or url)
    except Exception as error:                                # noqa: BLE001
        return HttpsResult(False, None, (time.monotonic() - started) * 1000.0,
                           _error_text(error)[:ERROR_MAX], url)

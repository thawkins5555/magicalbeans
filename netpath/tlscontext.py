"""One verified TLS context for every outbound HTTPS client."""
import os
import ssl


def verified_context(cafile: str | None = None) -> ssl.SSLContext:
    """The system trust store (plus `cafile` when given) and hostname
    checking, without VERIFY_X509_STRICT: Python 3.13 turns it on and it
    refuses the AKI-less certificates SSL-inspecting firewalls and internal
    CAs issue."""
    context = ssl.create_default_context()
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if strict:
        context.verify_flags &= ~strict
    if cafile and os.path.isfile(cafile):
        try:
            context.load_verify_locations(cafile=cafile)
        except ssl.SSLError:
            pass  # a corrupt bundle shouldn't break the system store's own certs
    return context

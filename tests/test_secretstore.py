"""Tier 1 item 9: a portable secret store behind dpapi.py's existing
protect()/unprotect()/available() interface, for hosts DPAPI cannot reach
(see CREDENTIAL-SECURITY.md, "The portable secret store" — the design here
is the one that section's analysis calls genuinely equivalent to DPAPI for
the file-theft case: a passphrase supplied at start-up, a key derived from
it with scrypt, held in memory only).

Two kinds of check live here. Most are unit tests against
netpath.secretstore directly — blob format, MAC verification, tamper
resistance, passphrase-file permissions, nonce uniqueness, scrypt
parameters travelling with the blob. The last section drives a real
Service + WebServer with the *real* dpapi module — not the reversible
stand-in most other suites install (see test_security_fixes.py's own note
on why they replace it) — to prove the existing DHCP-credential route in
api.py works completely unmodified once a passphrase is configured, the
way it would on an actual Linux install.
"""
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("secretstore_")

import netpath.secretstore as ss  # noqa: E402
import netpath.dpapi as dpapi  # noqa: E402

FAILS = []
_FILE_COUNTER = [0]


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------- test plumbing
#
# Every test below runs against a throwaway salt file and a clean key
# cache, and manages the two passphrase-source environment variables
# itself — this suite is the one place in the repo that exercises the real
# secretstore/dpapi implementation rather than a fake stand-in, so it has
# to behave like the one real install it is pretending to be, one test at
# a time.

_SALT_FILE = os.path.join(TMPDIR, "install.salt")
ss._salt_path = lambda: _SALT_FILE


def reset():
    os.environ.pop(ss.ENV_PASSPHRASE_FILE, None)
    os.environ.pop(ss.ENV_PASSPHRASE, None)
    ss._key_cache.clear()
    try:
        os.unlink(_SALT_FILE)
    except OSError:
        pass


def passphrase_file(text, mode=0o600):
    _FILE_COUNTER[0] += 1
    path = os.path.join(TMPDIR, f"pass_{_FILE_COUNTER[0]}.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)
    return path


# ------------------------------------------------------------------ (a) available()

def test_available_nothing_configured():
    reset()
    if os.name == "nt":
        check("available() with nothing configured "
              "(skipped: Windows always has DPAPI)", True)
        return
    check("secretstore.configured() is False with nothing set",
          ss.configured() is False)
    check("dpapi.available() is False with nothing set",
          dpapi.available() is False)


# -------------------------------------------------------------- (b) round trips

def test_roundtrip_file_source():
    reset()
    path = passphrase_file("correct horse battery staple\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path
    check("configured() true with a passphrase file", ss.configured())
    if os.name != "nt":
        check("dpapi.available() true with a passphrase file", dpapi.available())
    blob = dpapi.protect(b"s3cret-value")
    check("the blob is tagged as a portable-store blob", blob.startswith(ss.MAGIC))
    check("...and ss.is_portable_blob() agrees", ss.is_portable_blob(blob))
    plain = dpapi.unprotect(blob)
    check("round trip through dpapi.protect/unprotect returns the plaintext",
          plain == b"s3cret-value")
    check("...and through secretstore directly, too",
          ss.unprotect(ss.protect(b"another value")) == b"another value")


def test_roundtrip_env_source():
    reset()
    os.environ[ss.ENV_PASSPHRASE] = "another passphrase entirely, not a file"
    check("configured() true with NETPATH_SECRET_PASSPHRASE alone", ss.configured())
    blob = ss.protect(b"env-sourced-secret")
    check("round trip through the plain env var works",
          ss.unprotect(blob) == b"env-sourced-secret")


def test_file_takes_precedence_over_env():
    reset()
    os.environ[ss.ENV_PASSPHRASE] = "the weaker source"
    file_path = passphrase_file("the file source\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = file_path
    check("the file source wins when both are set",
          ss._load_passphrase() == b"the file source")


def test_trailing_newline_stripped_from_file():
    reset()
    path = passphrase_file("has-a-trailing-newline\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path
    check("a trailing newline in the passphrase file is not part of the passphrase",
          ss._load_passphrase() == b"has-a-trailing-newline")


# -------------------------------------------------------- (c) wrong passphrase

def test_wrong_passphrase_fails_cleanly():
    reset()
    path = passphrase_file("first-passphrase\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path
    blob = ss.protect(b"top-secret-value")

    ss._key_cache.clear()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("a-completely-different-passphrase\n")
    try:
        ss.unprotect(blob)
        ok, detail = False, "did not raise"
    except ss.SecretStoreError as exc:
        ok = "decrypted" in str(exc).lower() or "wrong" in str(exc).lower()
        detail = str(exc)
    check("a wrong passphrase raises SecretStoreError, not garbage plaintext",
          ok, detail)

    # And through dpapi's own interface, the same failure surfaces as the
    # one exception every existing caller already catches.
    try:
        dpapi.unprotect(blob)
        ok = False
    except dpapi.DpapiUnavailable:
        ok = True
    check("...and dpapi.unprotect() reports it as DpapiUnavailable", ok)


# ------------------------------------------------------------------- (d) tamper

def test_tamper_every_region_of_the_blob():
    reset()
    path = passphrase_file("tamper-test-passphrase\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path
    plaintext = b"tamper with me if you can, once per byte"
    blob = ss.protect(plaintext)

    # One flipped bit at a sampling of offsets across the whole blob --
    # magic, version, each scrypt parameter, the nonce, the ciphertext and
    # the MAC itself -- covers every region the format defines, not just
    # the ciphertext.
    step = max(1, len(blob) // 40)
    tested = list(range(0, len(blob), step))
    slipped_through = []
    for pos in tested:
        tampered = bytearray(blob)
        tampered[pos] ^= 0x01
        try:
            ss.unprotect(bytes(tampered))
            slipped_through.append(pos)
        except ss.SecretStoreError:
            pass
    check(f"flipping any single bit across all {len(tested)} sampled "
          f"offsets is caught", not slipped_through,
          f"offsets that decrypted anyway: {slipped_through}")

    # The check above would pass vacuously if unprotect() simply always
    # raised -- prove it doesn't.
    check("...while the untampered blob still verifies and decrypts",
          ss.unprotect(blob) == plaintext)

    # Truncation is its own kind of tamper: too short to hold a header.
    try:
        ss.unprotect(blob[:len(ss.MAGIC) + 2])
        ok = False
    except ss.SecretStoreError:
        ok = True
    check("a truncated blob is refused, not read out of bounds", ok)


# --------------------------------------------------- (e) blob tag discrimination

def test_blob_tag_discrimination():
    reset()
    path = passphrase_file("discrimination-test-passphrase\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path

    portable_blob = dpapi.protect(b"a portable-store secret")
    check("a portable blob is recognised as one",
          ss.is_portable_blob(portable_blob))

    # Something that is not one of ours at all (stands in for an opaque
    # DPAPI CMS blob moved over from a Windows install, or plain garbage).
    not_ours = b"\x30\x82\x01\x00" + os.urandom(64)   # a DER-ish prefix, not NPSS
    check("an untagged blob is not mistaken for a portable-store one",
          not ss.is_portable_blob(not_ours))
    try:
        ss.unprotect(not_ours)
        ok = False
    except ss.SecretStoreError:
        ok = True
    check("secretstore.unprotect() on an untagged blob refuses outright", ok)

    if os.name != "nt":
        try:
            dpapi.unprotect(not_ours)
            ok, detail = False, "did not raise"
        except dpapi.DpapiUnavailable as exc:
            detail = str(exc)
            ok = "DPAPI" in detail and "Windows" in detail
        check("dpapi.unprotect() on this (non-Windows) host refuses an "
              "untagged blob with a message naming DPAPI/Windows, rather "
              "than trying to decrypt it as its own", ok, detail)

    # A version byte this build does not understand is refused by name,
    # not silently reinterpreted.
    from_module = bytearray(portable_blob)
    version_offset = len(ss.MAGIC)
    from_module[version_offset] = ss.VERSION + 1
    try:
        ss.unprotect(bytes(from_module))
        ok = False
    except ss.SecretStoreError as exc:
        ok = "version" in str(exc).lower()
    check("an unrecognised blob version is refused by name", ok)


# -------------------------------------------------------- (f) file permissions

def test_world_readable_passphrase_file_refused():
    reset()
    if os.name == "nt":
        check("world-readable passphrase file refused "
              "(skipped: Windows has no POSIX mode)", True)
        return
    path = passphrase_file("this file is too open\n", mode=0o644)
    os.environ[ss.ENV_PASSPHRASE_FILE] = path
    # configured() only checks that a source is *named* -- the detailed
    # permission failure is supposed to surface from an actual attempt to
    # use it, the same way dpapi.available() doesn't itself call
    # CryptProtectData.
    check("configured() is still true (the failure is in using it, not naming it)",
          ss.configured())
    try:
        ss.protect(b"should never be reachable")
        ok, detail = False, "did not raise"
    except ss.SecretStoreError as exc:
        detail = str(exc)
        ok = "0644" in detail or "readable by more than its owner" in detail
    check("a group/world-readable passphrase file is refused, by mode",
          ok, detail)

    os.chmod(path, 0o600)
    ss._key_cache.clear()
    try:
        ss.protect(b"now this should work")
        ok = True
    except ss.SecretStoreError as exc:
        ok, detail = False, str(exc)
    check("...and accepted once tightened to owner-only", ok)


def test_missing_passphrase_file_refused():
    reset()
    os.environ[ss.ENV_PASSPHRASE_FILE] = os.path.join(TMPDIR, "does-not-exist.txt")
    try:
        ss.protect(b"x")
        ok = False
    except ss.SecretStoreError as exc:
        ok = "could not be read" in str(exc)
    check("a passphrase file that does not exist is refused, not crashed on", ok)


def test_empty_passphrase_file_refused():
    reset()
    path = passphrase_file("")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path
    try:
        ss.protect(b"x")
        ok = False
    except ss.SecretStoreError as exc:
        ok = "empty" in str(exc)
    check("an empty passphrase file is refused", ok)


# ---------------------------------------------------------------- (g) nonces

def test_nonce_never_repeats():
    reset()
    path = passphrase_file("nonce-uniqueness-passphrase\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path

    plaintext = b"the exact same plaintext, every single time"
    blobs = [ss.protect(plaintext) for _ in range(64)]
    nonces = [ss._unpack(b)[3] for b in blobs]
    check("64 encryptions of identical plaintext never reuse a nonce",
          len(set(nonces)) == len(nonces))
    ciphertexts = [ss._unpack(b)[4] for b in blobs]
    check("...and so the ciphertexts differ from each other too, "
          "even though the plaintext is identical",
          len(set(ciphertexts)) == len(ciphertexts))
    check("...while every one of them still decrypts back to the same plaintext",
          all(ss.unprotect(b) == plaintext for b in blobs))


# ------------------------------------------------------ (h) scrypt parameters

def test_scrypt_parameters_recorded_in_blob():
    reset()
    path = passphrase_file("scrypt-params-passphrase\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path

    blob = ss.protect(b"whatever")
    n, r, p, _nonce, _ct, _mac = ss._unpack(blob)
    check("the blob records this module's current scrypt N/r/p",
          (n, r, p) == (ss.SCRYPT_N, ss.SCRYPT_R, ss.SCRYPT_P),
          f"got n={n} r={r} p={p}")

    # A blob "from an older release" made under a cheaper cost setting --
    # hand-built with different parameters, proving unprotect() uses what
    # the blob says, not this module's current constants, which is the
    # entire reason the parameters travel with the blob at all. (Lower
    # cost, not higher: a lower N is well inside this build's fixed
    # scrypt-memory ceiling and stays fast to derive; a *higher* one is the
    # case _SCRYPT_MAXMEM exists to refuse -- see test_tamper's coverage of
    # a corrupted/inflated parameter, and _derive_keys's own docstring.)
    legacy_n, legacy_r, legacy_p = ss.SCRYPT_N // 2, ss.SCRYPT_R, ss.SCRYPT_P
    key_enc, key_mac = ss._derive_keys(ss._load_passphrase(), ss._install_salt(),
                                       legacy_n, legacy_r, legacy_p)
    nonce = secrets.token_bytes(ss.NONCE_BYTES)
    plaintext = b"encrypted under an older, cheaper parameter set"
    ciphertext = ss._xor(plaintext, ss._keystream(key_enc, nonce, len(plaintext)))
    mac = hmac.new(key_mac, bytes([ss.VERSION]) + nonce + ciphertext,
                   hashlib.sha256).digest()
    legacy_blob = ss._pack(legacy_n, legacy_r, legacy_p, nonce, ciphertext, mac)

    check("a blob made with non-default (but valid) scrypt parameters "
          "still round-trips, decrypted using its own recorded parameters",
          ss.unprotect(legacy_blob) == plaintext)

    # And the reverse direction -- a blob claiming parameters costlier than
    # this build's fixed memory ceiling allows -- is refused rather than
    # honoured, which is what keeps a corrupted or hostile blob (see
    # test_tamper) from being able to ask this process to allocate however
    # much memory it likes.
    try:
        ss._derive_keys(ss._load_passphrase(), ss._install_salt(),
                        ss.SCRYPT_N, ss.SCRYPT_R * 4, ss.SCRYPT_P)
        ok = False
    except ss.SecretStoreError:
        ok = True
    check("scrypt parameters costlier than this build's fixed ceiling are refused",
          ok)


# --------------------------------------------------- (i) real end-to-end route
#
# Everything above talks to netpath.secretstore / netpath.dpapi directly.
# This section instead drives a real Service + WebServer with the real
# dpapi module wired in -- proving the existing DHCP-credential route in
# api.py (which this workstream was explicitly told not to touch) keeps
# working, unmodified, once a passphrase is configured.

def req(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    try:
        conn.request(method, path,
                     json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        data = response.read()
        head = {k.lower(): v for k, v in response.getheaders()}
        try:
            return response.status, head, json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return response.status, head, data
    finally:
        conn.close()


def login(port, username, password):
    status, head, payload = req(port, "POST", "/api/login",
                                {"username": username, "password": password})
    cookie = head.get("set-cookie", "").split(";")[0]
    return (cookie if status == 200 else ""), status, payload


def test_real_dpapi_through_the_dhcp_credential_route():
    if os.name == "nt":
        print("      note: skipping the real end-to-end pass -- this host "
              "IS Windows, so it is DPAPI, not the portable store, that "
              "would actually be exercised, and that is covered by dpapi's "
              "own self_test(), not this suite.")
        return
    reset()
    path = passphrase_file("end-to-end-passphrase, not typed anywhere else\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path

    from netpath.web.server import WebServer
    from netpath.web.service import Service

    data_dir = os.path.join(TMPDIR, "e2e-data")
    os.makedirs(data_dir, exist_ok=True)
    db_names = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps",
                "nodes", "alerts", "wireless", "configrx")
    service = Service(*[os.path.join(data_dir, n + ".db") for n in db_names])
    port = _paths.free_tcp_port()
    server = WebServer(service, host="127.0.0.1", port=port)
    if not server.start(block=False):
        print(f"SKIP: could not bind 127.0.0.1:{port}: {server.error}")
        raise SystemExit(77)

    try:
        admin_cookie, status, _p = login(port, "admin", "admin")
        check("e2e sign in as the seeded admin", status == 200 and bool(admin_cookie))
        NEW_PW = "correct horse battery staple e2e"
        req(port, "POST", "/api/password",
            {"current_password": "admin", "new_password": NEW_PW},
            cookie=admin_cookie)
        admin_cookie, status, _p = login(port, "admin", NEW_PW)
        check("e2e password change clears must_change", status == 200)

        status, _h, payload = req(port, "GET", "/api/state", cookie=admin_cookie)
        check("e2e the server is up", status == 200)

        status, _h, payload = req(port, "POST", "/api/ipam/dhcp/servers",
                                  {"address": "10.44.0.5", "label": "e2e-dhcp"},
                                  cookie=admin_cookie)
        check("e2e a DHCP server can be created", status == 200, f"{status} {payload}")
        server_id = payload.get("id")

        status, _h, payload = req(
            port, "POST", f"/api/ipam/dhcp/servers/{server_id}/credential",
            {"username": "svc-dhcp", "password": "N0tStoredInTheClear!"},
            cookie=admin_cookie)
        check("e2e the credential route accepts a password with a real "
              "passphrase configured -- the exact route that used to "
              "refuse outright on every non-Windows host",
              status == 200, f"{status} {payload}")

        stored = service.ipam_db.dhcp_server(server_id)
        blob = bytes(stored["password_enc"]) if stored else b""
        check("e2e the value actually stored on disk is a portable-store "
              "blob, not plaintext and not a DPAPI blob",
              blob.startswith(ss.MAGIC), blob[:8])
        check("e2e ...and it decrypts back to the password that was typed in",
              dpapi.unprotect(blob).decode("utf-8") == "N0tStoredInTheClear!")

        # And with the passphrase removed (an operator who forgot to carry
        # the configuration to a new host), the same stored value refuses
        # cleanly rather than returning garbage.
        del os.environ[ss.ENV_PASSPHRASE_FILE]
        ss._key_cache.clear()
        try:
            dpapi.unprotect(blob)
            ok = False
        except dpapi.DpapiUnavailable:
            ok = True
        check("e2e removing the passphrase configuration makes the same "
              "stored credential unreadable again, cleanly", ok)
    finally:
        try:
            server.stop()
            service.shutdown()
        except Exception:
            pass


# --------------------------------------------------------------------- main

def main() -> int:
    test_available_nothing_configured()
    test_roundtrip_file_source()
    test_roundtrip_env_source()
    test_file_takes_precedence_over_env()
    test_trailing_newline_stripped_from_file()
    test_wrong_passphrase_fails_cleanly()
    test_tamper_every_region_of_the_blob()
    test_blob_tag_discrimination()
    test_world_readable_passphrase_file_refused()
    test_missing_passphrase_file_refused()
    test_empty_passphrase_file_refused()
    test_nonce_never_repeats()
    test_scrypt_parameters_recorded_in_blob()
    test_real_dpapi_through_the_dhcp_credential_route()
    reset()
    return 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"\n{len(FAILS)} check(s) failed: " + ", ".join(FAILS))
        code = 1
    else:
        print("\nall checks passed")
    raise SystemExit(code)

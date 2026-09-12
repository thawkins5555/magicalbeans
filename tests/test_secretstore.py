"""A portable secret store behind dpapi.py's existing
protect()/unprotect()/available() interface, for hosts DPAPI cannot reach:
a passphrase supplied at start-up, a key derived from it with scrypt, held
in memory only. Most checks are unit tests against netpath.secretstore
directly; the last section drives a real Service + WebServer with the
*real* dpapi module to prove the DHCP-credential route works once set.
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

import stat as stat_mod  # noqa: E402

import netpath.secretstore as ss  # noqa: E402
import netpath.dpapi as dpapi  # noqa: E402
from netpath import configrx_redact  # noqa: E402

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
    # On Windows dpapi.protect() is real DPAPI whatever this passphrase says,
    # so the blob it returns is not — and must not be — a portable-store one.
    # The portable store's own shape is asserted through its own entry point,
    # which is what this suite is actually about.
    blob = ss.protect(b"s3cret-value") if os.name == "nt" else dpapi.protect(b"s3cret-value")
    check("the blob is tagged as a portable-store blob", blob.startswith(ss.MAGIC))
    check("...and ss.is_portable_blob() agrees", ss.is_portable_blob(blob))
    plain = ss.unprotect(blob) if os.name == "nt" else dpapi.unprotect(blob)
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

    # ss.protect(), not dpapi.protect(): on Windows the latter is real DPAPI.
    portable_blob = ss.protect(b"a portable-store secret")
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


def test_foreign_owned_passphrase_file_refused():
    """CREDENTIAL-SECURITY.md promises the file is refused unless it is
    chmod 600 *and* owned by the account the service runs as. Only the mode
    half was enforced."""
    reset()
    path = passphrase_file("owned by somebody else\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path

    real_stat = os.stat
    real_getuid = getattr(os, "getuid", None)
    real_posix = ss._POSIX
    target = os.path.abspath(path)
    OURS, THEIRS = 1000, 12345

    def fake_stat(p, *args, **kwargs):
        info = real_stat(p, *args, **kwargs)
        try:
            same = os.path.abspath(p) == target
        except TypeError:                        # a file descriptor, not a path
            same = False
        if not same:
            return info
        # fields[0]=st_mode, fields[4]=st_uid; force 0600 since Windows chmod can't.
        fields = list(info[:10])
        fields[0] = stat_mod.S_IFREG | 0o600
        fields[4] = THEIRS
        return os.stat_result(fields)

    os.stat = fake_stat
    os.getuid = lambda: OURS
    ss._POSIX = True
    try:
        ss._key_cache.clear()
        try:
            ss.protect(b"should never be reachable")
            ok, detail = False, "did not raise"
        except ss.SecretStoreError as exc:
            detail = str(exc)
            ok = "owned by" in detail and str(THEIRS) in detail
        check("a 0600 passphrase file owned by another account is refused",
              ok, detail)
        check("...and the refusal names the uid the service runs as, so "
              "whoever configured it can see both halves",
              ok and str(OURS) in detail, detail)

        # The same file, now ours: the check must not refuse every file.
        os.getuid = lambda: THEIRS
        ss._key_cache.clear()
        try:
            ss.protect(b"now this should work")
            ok, detail = True, ""
        except ss.SecretStoreError as exc:
            ok, detail = False, str(exc)
        check("...and accepted once it belongs to this account", ok, detail)

        # root is allowed: a service drops privileges after reading a root-owned file.
        os.getuid = lambda: OURS
        fields = list(real_stat(path)[:10])
        fields[0] = stat_mod.S_IFREG | 0o600
        fields[4] = 0
        os.stat = lambda p, *a, **k: (os.stat_result(fields)
                                      if os.path.abspath(p) == target
                                      else real_stat(p, *a, **k))
        ss._key_cache.clear()
        try:
            ss.protect(b"root-owned is fine")
            ok, detail = True, ""
        except ss.SecretStoreError as exc:
            ok, detail = False, str(exc)
        check("...and a root-owned file is still accepted, for a service "
              "that drops privileges after start-up", ok, detail)
    finally:
        os.stat = real_stat
        if real_getuid is None:
            del os.getuid
        else:
            os.getuid = real_getuid
        ss._POSIX = real_posix
        ss._key_cache.clear()


def test_foreign_owned_check_is_skipped_off_posix():
    """POSIX-only: Windows has no meaningful st_uid, so _POSIX gates it off."""
    reset()
    path = passphrase_file("owned by somebody else\n")
    os.environ[ss.ENV_PASSPHRASE_FILE] = path
    real_posix = ss._POSIX
    ss._POSIX = False
    try:
        ss._key_cache.clear()
        try:
            ss.protect(b"accepted off POSIX")
            ok, detail = True, ""
        except ss.SecretStoreError as exc:
            ok, detail = False, str(exc)
        check("off POSIX the ownership check does not run at all", ok, detail)
    finally:
        ss._POSIX = real_posix
        ss._key_cache.clear()


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


# ------------------------------------------- (j) rotation and vendor redaction
#
# Merged from test_credential_review_fixes.py: two CONFIRMED defects fixed
# in secretstore.py and configrx_redact.py. _keys_for() used to cache
# derived keys on the (n, r, p) triple alone, and protect() always calls it
# with this build's own three scrypt constants -- so once a key had been
# derived in a process, a rotated passphrase file was never re-read. And
# configrx_redact.PATTERNS was anchored on Cisco-IOS/FortiOS syntax only,
# so redact() matched nothing for juniper/mikrotik/hp/aruba vendors.
#
# Runs in its own tmpdir and with its own salt-path stub (restored after),
# independent of the fixtures above.

def credential_review_fixes_checks():
    tmp_dir = _paths.tmpdir("credential_review_fixes_")
    salt_file = os.path.join(tmp_dir, "install.salt")
    file_counter = [0]
    original_salt_path = ss._salt_path
    ss._salt_path = lambda: salt_file

    def reset_rotation():
        os.environ.pop(ss.ENV_PASSPHRASE_FILE, None)
        os.environ.pop(ss.ENV_PASSPHRASE, None)
        ss._key_cache.clear()
        try:
            os.unlink(salt_file)
        except OSError:
            pass

    def rotation_passphrase_file(text, mode=0o600):
        file_counter[0] += 1
        path = os.path.join(tmp_dir, f"pass_{file_counter[0]}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(path, mode)
        return path

    def test_rotation_takes_effect_without_restart():
        reset_rotation()
        path = rotation_passphrase_file("rotation-first-passphrase, not typed anywhere else\n")
        os.environ[ss.ENV_PASSPHRASE_FILE] = path

        key_enc_1, key_mac_1 = ss._keys_for(ss.SCRYPT_N, ss.SCRYPT_R, ss.SCRYPT_P)
        blob_under_p1 = ss.protect(b"credential entered under the first passphrase")
        check("round trip under the first passphrase works",
              ss.unprotect(blob_under_p1) == b"credential entered under the first passphrase")

        # Rotate: rewrite the SAME file this process already has open via
        # os.environ. No ss._key_cache.clear(), no restart -- exactly what an
        # operator does after believing a passphrase leaked.
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("rotation-second-passphrase, different from the first\n")

        key_enc_2, key_mac_2 = ss._keys_for(ss.SCRYPT_N, ss.SCRYPT_R, ss.SCRYPT_P)
        check("the derived key changes the moment the passphrase file changes, "
              "with no cache clear and no restart in between",
              (key_enc_2, key_mac_2) != (key_enc_1, key_mac_1))

        # The behavioural proof that actually matters: ciphertext made under
        # the OLD passphrase must stop decrypting once the file has been
        # rotated in this same process -- if the bug were still present,
        # protect()/unprotect() would still be using the FIRST key this
        # process ever derived, and this would silently keep working.
        try:
            ss.unprotect(blob_under_p1)
            ok, detail = False, "old ciphertext still decrypted after rotation"
        except ss.SecretStoreError as exc:
            ok, detail = True, str(exc)
        check("ciphertext made under the OLD passphrase no longer unprotects "
              "once the passphrase file has been rotated, within the same "
              "process", ok, detail)

        blob_under_p2 = ss.protect(b"credential re-entered under the new passphrase")
        check("a credential re-entered right after rotation round-trips under "
              "the new passphrase",
              ss.unprotect(blob_under_p2) == b"credential re-entered under the new passphrase")

        # And the reverse: reverting the file back to the FIRST passphrase must
        # make the blob just produced under the SECOND one stop decrypting too.
        # If protect() had actually used a stale cached key from before the
        # rotation (the bug), this blob would really be encrypted under the
        # first passphrase and would decrypt right back here.
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("rotation-first-passphrase, not typed anywhere else\n")
        try:
            ss.unprotect(blob_under_p2)
            ok = False
        except ss.SecretStoreError:
            ok = True
        check("...and that credential is NOT readable under the passphrase "
              "that was current before the rotation, proving protect() used "
              "the passphrase that was actually current, not a stale cached "
              "key", ok)

    def test_cache_still_avoids_rederiving_scrypt():
        reset_rotation()
        path = rotation_passphrase_file("cache-still-works-passphrase\n")
        os.environ[ss.ENV_PASSPHRASE_FILE] = path

        # Counting derivations rather than timing them -- robust on a slow or
        # loaded CI box where a timing threshold would be a guess.
        calls = [0]
        original_derive_keys = ss._derive_keys

        def counting_derive_keys(*args, **kwargs):
            calls[0] += 1
            return original_derive_keys(*args, **kwargs)

        ss._derive_keys = counting_derive_keys
        try:
            ss.protect(b"first value")
            ss.protect(b"second value")
            blob = ss.protect(b"third value")
            ss.unprotect(blob)
        finally:
            ss._derive_keys = original_derive_keys

        check("four protect()/unprotect() calls with an unchanged passphrase "
              "run scrypt exactly once, not once per call -- the entire reason "
              "this cache exists (nodepoll.py can call protect()/unprotect() "
              "once per device, per poll cycle)",
              calls[0] == 1, f"scrypt ran {calls[0]} time(s)")

    def test_cache_bounded_across_many_rotations():
        reset_rotation()
        for i in range(ss._MAX_CACHE_ENTRIES + 5):
            path = rotation_passphrase_file(f"rotation-bound-passphrase-{i}\n")
            os.environ[ss.ENV_PASSPHRASE_FILE] = path
            ss.protect(b"probe value")
        check(f"the key cache never grows past its {ss._MAX_CACHE_ENTRIES}-entry "
              f"bound, even after {ss._MAX_CACHE_ENTRIES + 5} distinct "
              "passphrase rotations in this one process",
              len(ss._key_cache) <= ss._MAX_CACHE_ENTRIES,
              f"cache has {len(ss._key_cache)} entries")

    def test_new_vendor_patterns_redact_secrets():
        # One representative secret-bearing line per newly-covered vendor,
        # plus the bare Cisco `password 7 ...` line.
        # (name, config line, the literal secret text, how many matches expected)
        cases = [
            ("cisco bare line password (enc-type 7)",
             "line vty 0 4\n password 7 070C285F4D06\n login",
             "070C285F4D06", 1),
            ("cisco bare line password (cleartext)",
             "line con 0\n password Cisc0ConsolePW\n login",
             "Cisc0ConsolePW", 1),
            ("juniper radius-server secret",
             'set system radius-server 10.0.0.1 secret "MyRadiusSecret1"',
             "MyRadiusSecret1", 1),
            ("juniper pre-shared-key ascii-text",
             'set security ike policy IKE-POLICY-1 pre-shared-key ascii-text '
             '"MyJunosPSK123"',
             "MyJunosPSK123", 1),
            ("juniper root-authentication encrypted-password",
             'set system root-authentication encrypted-password "$6$abcXYZ789"',
             "abcXYZ789", 1),
            ("mikrotik password=",
             'add name=admin password="hunter2Router" group=full',
             "hunter2Router", 1),
            ("mikrotik wpa2-pre-shared-key=",
             '/interface wireless security-profiles add authentication-types='
             'wpa2-psk name=default wpa2-pre-shared-key="MyMikrotikPSK"',
             "MyMikrotikPSK", 1),
            ("hp/aruba password sha256",
             "password sha256 09a1b2c3d4e5f6a7b8c9",
             "09a1b2c3d4e5f6a7b8c9", 1),
            ("hp/aruba wpa-passphrase",
             "wpa-passphrase MyWifiPass123",
             "MyWifiPass123", 1),
            ("hp/aruba key-string",
             "key 1 key-string cipher SecretKeyChainValue",
             "SecretKeyChainValue", 1),
        ]
        for label, text, secret, expected_count in cases:
            redacted, count = configrx_redact.redact(text)
            check(f"{label}: the secret text does not appear in the redacted "
                  f"output", secret not in redacted, redacted)
            check(f"{label}: the {configrx_redact.REDACTED!r} placeholder is "
                  f"present", configrx_redact.REDACTED in redacted, redacted)
            check(f"{label}: redacted_count reflects the match "
                  f"(expected {expected_count})",
                  count == expected_count, f"got {count}")

    def test_ordinary_config_lines_are_untouched():
        # A pattern that over-matches and destroys non-secret config is worse
        # than one that misses -- guard against exactly that across every
        # vendor family this suite touches, plus a couple of lines chosen
        # specifically because they *mention* a secret-bearing keyword in a
        # context that must not be redacted (a comment, a banner, a "no ..."
        # negation).
        lines = [
            "interface GigabitEthernet0/1",
            " description uplink to core switch",
            "hostname switch1",
            "! a comment about the site password rotation policy",
            "no service password-recovery",
            "vlan 10",
            " name PRODUCTION",
            "router bgp 65000",
            " neighbor 10.0.0.2 remote-as 65001",
            "set interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/24",
            "set system host-name router1",
            "/interface ethernet set [ find default-name=ether1 ] name=ether1-wan",
            "add address=192.168.1.1/24 interface=ether1",
            "snmp-server location Server Room 2",
        ]
        for line in lines:
            redacted, count = configrx_redact.redact(line)
            check(f"non-secret line left byte-for-byte untouched: {line!r}",
                  redacted == line and count == 0, (redacted, count))

    try:
        test_rotation_takes_effect_without_restart()
        test_cache_still_avoids_rederiving_scrypt()
        test_cache_bounded_across_many_rotations()
        test_new_vendor_patterns_redact_secrets()
        test_ordinary_config_lines_are_untouched()
        reset_rotation()
    finally:
        ss._salt_path = original_salt_path
        shutil.rmtree(tmp_dir, ignore_errors=True)


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
    test_foreign_owned_passphrase_file_refused()
    test_foreign_owned_check_is_skipped_off_posix()
    test_missing_passphrase_file_refused()
    test_empty_passphrase_file_refused()
    test_nonce_never_repeats()
    test_scrypt_parameters_recorded_in_blob()
    credential_review_fixes_checks()
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

"""4.50.0's credential review, item by item — two CONFIRMED defects, fixed
in `netpath/secretstore.py` and `netpath/configrx_redact.py`.

**Rotating the passphrase had no effect until restart.** `_keys_for()`
cached derived keys on the `(n, r, p)` triple alone, and `protect()` always
calls it with this build's own three scrypt constants — the same three
every time. So once any key had been derived in a process, the cache
always hit and the passphrase source was never read again in that
process's lifetime. An operator who believed a passphrase had leaked,
rewrote the passphrase file, and re-entered every stored credential
through the UI was silently re-encrypting all of them under the OLD,
leaked key. The fix folds a digest of the *current* passphrase into the
cache key, so a changed passphrase source misses the cache and re-derives
— see `_keys_for`'s own docstring in `secretstore.py` for the full
account. The first section here proves the rotation takes effect within
one process (no restart, no manual cache clear) and that the cache still
does its actual job (scrypt runs once per distinct passphrase, not once
per `protect()`/`unprotect()` call).

**Redaction was fail-open for most shipped vendors.** Every pattern in
`configrx_redact.PATTERNS` was anchored on Cisco-IOS or FortiOS directive
syntax, but `configrx_vendors.VENDORS` ships backup support for juniper,
mikrotik, hp and aruba too (among others) — for those, `redact()` matched
nothing and returned the config unchanged. The fix adds patterns for the
secret-bearing lines those vendors actually emit, plus a bare Cisco
`password [<enc-type>] <secret>` line (as found inside `line vty 0 4` /
`line con 0` blocks), which no existing pattern covered either — every
password-shaped entry required a leading keyword (`enable`, `username
...`, `neighbor ...`) that a bare line doesn't have. The second section
here proves one representative secret-bearing line per newly-covered
vendor is actually redacted, and that ordinary configuration is not.

Stdlib only, no pytest, following test_secretstore.py's and
test_configrx_search_compliance.py's own conventions (this suite is not a
copy of either — it exercises only the specific defects the review found,
not the modules' whole surface, which those two suites already cover).
"""
import os
import shutil

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("credential_review_fixes_")

import netpath.secretstore as ss  # noqa: E402
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
# Mirrors test_secretstore.py's own fixtures exactly (a throwaway salt file,
# a clean key cache, hand-managed passphrase environment variables) — this
# suite exercises the same real secretstore implementation, not a fake
# stand-in, so it has to behave like the one real install it is standing in
# for, one test at a time.

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


# ------------------------------------------------- (a) rotation takes effect

def test_rotation_takes_effect_without_restart():
    reset()
    path = passphrase_file("rotation-first-passphrase, not typed anywhere else\n")
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

    # The behavioural proof the review actually cared about: ciphertext
    # made under the OLD passphrase must stop decrypting once the file has
    # been rotated in this same process -- if the bug were still present,
    # protect()/unprotect() would still be using the FIRST key this process
    # ever derived, and this would silently keep working.
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
    reset()
    path = passphrase_file("cache-still-works-passphrase\n")
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
    reset()
    for i in range(ss._MAX_CACHE_ENTRIES + 5):
        path = passphrase_file(f"rotation-bound-passphrase-{i}\n")
        os.environ[ss.ENV_PASSPHRASE_FILE] = path
        ss.protect(b"probe value")
    check(f"the key cache never grows past its {ss._MAX_CACHE_ENTRIES}-entry "
          f"bound, even after {ss._MAX_CACHE_ENTRIES + 5} distinct "
          "passphrase rotations in this one process",
          len(ss._key_cache) <= ss._MAX_CACHE_ENTRIES,
          f"cache has {len(ss._key_cache)} entries")


# --------------------------------------------------- (b) vendor redaction

def test_new_vendor_patterns_redact_secrets():
    # One representative secret-bearing line per newly-covered vendor, plus
    # the bare Cisco `password 7 ...` line the review called out by name.
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


# --------------------------------------------------------------------- main

def main() -> int:
    test_rotation_takes_effect_without_restart()
    test_cache_still_avoids_rederiving_scrypt()
    test_cache_bounded_across_many_rotations()
    test_new_vendor_patterns_redact_secrets()
    test_ordinary_config_lines_are_untouched()
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

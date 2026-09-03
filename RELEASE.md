# Publishing a SappiWhere release

The **Check for updates** button in Settings (`netpath/selfupdate.py`) installs
a *published tag*, and refuses to install anything whose tarball does not match
a SHA-256 the release published separately from it. A release that skips the
steps below is simply never offered to any install; nothing breaks, and nothing
unverified is ever installed.

Self-update is off by default (`updates_enabled`, in Settings). An install that
leaves it off never contacts GitHub at all, and is updated by replacing the
`netpath` directory by hand.

## What the updater does

1. `GET /repos/<owner>/<repo>/tags` — the newest tag by version order (the run
   of numbers in the name, so `v4.39.0` beats `v4.36.1` and `v4.9.0`). Branch
   tips are never consulted: a branch moves, a tag is something a person
   published.
2. If that tag is already recorded in `update_installed_tag` (app.db), it stops.
3. `GET /repos/<owner>/<repo>/releases/tags/<tag>` — the release for that tag,
   and in its asset list a file called exactly **`SHA256SUMS`**. No asset, no
   install: the refusal names this file.
4. It downloads `https://codeload.github.com/<owner>/<repo>/tar.gz/refs/tags/<tag>`,
   capped at 64 MiB, hashing as it reads, and compares that digest against the
   line in `SHA256SUMS` whose filename is `<repo>-<tag>.tar.gz`.
5. Only then does it unpack (discarding the archive's own mode bits), stop the
   listener and every worker, replace the `netpath` package, record the tag, and
   re-exec.

## Cutting a release

```sh
# 1. Tag the commit you intend to ship, and push the tag.
git tag -a v4.39.0 -m "SappiWhere 4.39.0"
git push origin v4.39.0

# 2. Take the tarball GitHub serves for that tag — the same URL the updater
#    uses — and hash it. Do not build your own tarball: the digest has to be
#    of the bytes the updater will actually receive.
TAG=v4.39.0
curl -fsSL -o "magicalbeans-$TAG.tar.gz" \
  "https://codeload.github.com/thawkins5555/magicalbeans/tar.gz/refs/tags/$TAG"
sha256sum "magicalbeans-$TAG.tar.gz" > SHA256SUMS
cat SHA256SUMS      # <64 hex chars>  magicalbeans-v4.39.0.tar.gz

# 3. Create the release for that tag and attach SHA256SUMS as an asset.
gh release create "$TAG" SHA256SUMS --title "SappiWhere 4.39.0" --notes-file -
```

`SHA256SUMS` is `sha256sum`'s own format — `<digest>  <filename>` — so it can be
checked by hand with `sha256sum -c SHA256SUMS`. Extra lines for other files are
ignored; only the source tarball's entry is read.

Attach it as a **release asset**, not as a file committed in the repository. A
digest that travels inside the archive it describes proves nothing: anyone who
can replace the archive can replace the digest with it.

## What this does and does not prove

It proves the tarball is byte-for-byte the one the release named, and that the
named thing is a tag rather than whatever a branch pointed at this morning. It
does **not** prove who named it: there is no signature, and anyone who can
publish a release for this repository can publish a matching pair. An
installation that needs more than that should leave `updates_enabled` off and
install releases through its own change process — which is exactly why the
setting exists and why it is off to begin with.

## Checklist

- [ ] `CHANGELOG.md` has the release's section, and `netpath/__init__.py` carries
      the version being tagged.
- [ ] `python3 tests/run_all.py` is green.
- [ ] Tag pushed.
- [ ] `SHA256SUMS` generated from the codeload tarball for that tag.
- [ ] Release created for the tag with `SHA256SUMS` attached.
- [ ] `sha256sum -c SHA256SUMS` passes against a freshly downloaded tarball.

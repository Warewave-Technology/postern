# Releasing postern

For whoever cuts the release. The process is deliberately short, and the
parts that are automated are automated because a human doing them by
hand gets them wrong on the release where it matters.

## Before the tag

1. **Write the changelog entry.** `CHANGELOG.md`, following the policy
   in its header. The *Needs action* section is the one people will
   actually read — a setting that silently stops being honoured belongs
   there, and so does anything that changes how long a restart takes.

2. **Check the configuration builds a release.**

   ```bash
   make release-check      # validates .goreleaser.yaml
   make release-snapshot   # builds all four targets into dist/, publishes nothing
   ```

   `release-snapshot` is the only way to find a mistake in
   `.goreleaser.yaml` before a tag exists, and a tag is not something you
   want to be un-doing. It skips signing, which needs an OIDC identity
   that only CI has.

   `release-check` needs a git remote — without one it stops at
   `no remote configured to list refs from`, which is a statement about
   the clone and not about the file. `release-snapshot` works either way.

   **Do not ship what it produces.** `go run` upgrades the Go toolchain
   to satisfy goreleaser itself, so a snapshot binary is built with a
   different Go than the one in `go.mod`. The real release is built in
   CI with `setup-go` reading `go.mod`.

3. **Green CI on the commit you are about to tag.** The release workflow
   runs `make ci` again before it builds anything, so this is belt and
   braces rather than the only check — but finding out on the tag is a
   slower way to learn it.

## The tag

```bash
git tag -a v1.0.0 -m "postern v1.0.0"
git push origin v1.0.0
```

Annotated, not lightweight: `git describe` and goreleaser both read
annotated tags, and the message is where the tag itself says what it is.

## What happens then

`.github/workflows/release.yml` runs on any `v*` tag:

1. `make ci` — the whole suite, including the integration tests and the
   panel's tests. A tag pointing at a broken commit stops here.
2. goreleaser builds four static binaries (`linux` and `darwin`,
   `amd64` and `arm64`) with the version stamped from the tag, archives
   them with `LICENSE`, `README.md`, `CHANGELOG.md` and the systemd
   unit, and writes `checksums.txt`.
3. cosign signs `checksums.txt` with a keyless signature bound to this
   repository and this workflow. There is no signing key to store, lose
   or rotate — which is the same reasoning that keeps the CA key off the
   panel.
4. A **draft** release appears. Read it, then publish it by hand.

The draft is deliberate. Publishing automatically turns a mistaken tag
into "I deleted it, hopefully nobody pulled it" — and for a bastion,
somebody's automation might have.

## After publishing

Open a new `## Unreleased` section at the top of `CHANGELOG.md`, above
the version you just shipped.

## What is not in the pipeline, and why

- **No container image.** The deployment story here is a systemd unit
  with a long list of sandboxing directives that is itself a security
  boundary (`deploy/systemd/postern.service`). A container image is a
  second supported surface — base image updates, a non-root user, a
  volume for recordings — and adding one should be a decision, not a
  side effect of setting up releases.

- **No SBOM.** For a Go binary, `go version -m ./postern` already lists
  every module and version it was built from, which is what an advisory
  actually sends you looking for. An SBOM would add a tool to the
  release path that nothing else here needs; worth adding when someone
  asks for a specific format, not before.

- **No Homebrew tap, no `.deb`/`.rpm`.** Nobody has asked, and each is a
  channel that has to be kept working.

# Changelog

What changed, for the person running it.

Entries are written from the operator's side: what is different on your
bastion, and what you have to do about it. An entry that only makes
sense with the diff open does not belong here — that is what the commit
message is for, and this project's commit messages are long on purpose.

Three rules the sections encode:

- **Security first, always.** Advisory IDs, whether postern's own code
  reached the vulnerable path, and the version that fixes it. A reader
  scanning for "am I affected" should not have to read past the top.
- **"Needs action" is its own section.** A change that silently stops
  honouring a setting you wrote is worse than one that refuses to start,
  and it belongs where nobody can miss it.
- **Removals are listed.** A capability that quietly disappears sends
  someone looking for a button that is no longer there.

Versions follow [semantic versioning](https://semver.org). The schema
has its own number: `postern db migrate` moves it, and the bastion
refuses to start against a schema it does not match rather than writing
audit rows into a shape it does not understand.

<!--
  Open an "## Unreleased" section above the 1.0.0 heading on the first
  commit after the tag — RELEASING.md says the same thing at the end.
-->

## 1.0.2 — 2026-09-04

### Needs action if you are running a 1.0.1 binary

- **The published 1.0.1 binaries mark themselves `MODIFIED`, and it is a
  false alarm.** `postern version` on an official 1.0.1 download prints
  `commit 0a069427d1c6 (MODIFIED — this is not the source of any commit)`,
  and `go version -m` reports `v1.0.1+dirty`. The source is not modified:
  the binary reproduces from a clean clone of the `v1.0.1` tag. What was
  dirty was the release runner's working tree.

  `web/tsconfig.tsbuildinfo` — TypeScript's incremental build cache — was
  tracked in git. The release rebuilds the panel before building, CI's Node
  writes a different cache file than the machine that committed it, and Go
  stamps `vcs.modified=true` whenever the tree is not clean. goreleaser
  cannot catch this on its own: its git cleanliness check runs *before* the
  build hooks that dirty the tree.

  The binary itself is unaffected and its signature and checksum verify
  normally — a 1.0.1 download whose `checksums.txt` signature says
  `Verified OK` is genuine despite what it says about itself. But the
  version stamp exists precisely to answer "is the fix really in the thing
  I am running", so it gets a real release rather than a footnote.

### Fixed

- **A release can no longer be built from a dirty tree.** The build cache is
  untracked and ignored, and the release runs a cleanliness gate as its last
  step before building. A hook that rewrites a tracked file now stops the
  release loudly instead of shipping binaries that misreport themselves.

### Changed

- **The install instructions verify the signature before installing.** The
  documented order was: check the archive against `checksums.txt`, install
  it, then verify that `checksums.txt` was signed. An unverified checksums
  file only proves the archive and its checksum arrived together — whoever
  replaced one could replace the other — so the signature check now comes
  first. The four published platforms are named as well; previously only
  `linux_amd64` appeared in the commands, though `linux_arm64`,
  `darwin_amd64` and `darwin_arm64` are built and signed alongside it.

- **The documentation says which Go version building from source needs.**
  It described the clone-and-`make build` path without naming one. With
  the default `GOTOOLCHAIN=auto` that never shows; with
  `GOTOOLCHAIN=local`, or a network that refuses a toolchain download, you
  got a bare version error and nothing saying whether the floor was
  deliberate. It is: the standard library is compiled in, so the `go`
  directive decides which standard-library fixes your binary carries.

## 1.0.1 — 2026-09-04

### Needs action when upgrading a pre-release build

- **Verifying a release takes one file now, and cosign v3.** The
  signature ships as a single sigstore bundle, `checksums.txt.bundle`,
  instead of a separate `.sig` and `.pem`:

  ```
  cosign verify-blob checksums.txt \
    --bundle checksums.txt.bundle \
    --certificate-identity-regexp '^https://github\.com/Warewave-Technology/postern/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

  This is not a preference. cosign v3 turns the bundle format on by
  default and then ignores `--output-signature` and
  `--output-certificate`, which is what the 1.0.0 tag failed on — after
  the whole test suite had already run. Insisting on the two-file form
  would not have helped either: `verify-blob` carries the same default,
  so anyone installing cosign today would have found the documented
  verification command failing against a genuine release. That is the
  worst way for a verification step to fail, so the artifact moved
  rather than the instructions.

### Fixed

- **A build made after a release tag no longer claims to be that
  release.** Go embeds a different pseudo-version once a tag exists —
  `v1.0.1-0.<timestamp>-<commit>` rather than `v0.0.0-<timestamp>-<commit>`
  — and the check that recognises one only matched the shape a repository
  with no tags produces. So `postern version` on any build between
  releases would have printed a version-shaped string with no "not built
  from a release tag" warning: wrong exactly when people ask which build
  they are running, right after a release. It could not have appeared
  before 1.0.0, because until then there was no tag for Go to base the
  other form on.

- **1.0.0 was tagged but never released.** The tag exists and the module
  is resolvable — `go install
  github.com/Warewave-Technology/postern/cmd/postern@v1.0.0` works and
  is byte-identical to 1.0.1's source — but the release workflow failed
  at the signing step, so there are no archives, no checksums and no
  signature for it. The tag is deliberately left where it is: the Go
  module proxy and sum.golang.org have already recorded v1.0.0 against
  that commit, and moving a tag they have pinned makes every
  `go install` of it fail with a checksum mismatch. Download 1.0.1.

## 1.0.0 — 2026-09-04

The first release. postern is an SSH bastion that mints a short-lived
certificate per session and records what happens: targets hold no
`authorized_keys`, users land as themselves, and a session that cannot
be recorded does not start.

What 1.0 covers, and what it deliberately does not, is written up in
[the documentation](site/docs/index.html#limits) — read that section
before deploying. The short version: SSH and SFTP only, one node, TOTP
as the only second factor, no port forwarding, and no integrity seal on
recordings.

### Security

- **`golang.org/x/crypto` upgraded to v0.56.0** for
  [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) and
  [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354), two
  denial-of-service bugs in `x/crypto/ssh` channel handling. Both were
  reachable from postern's own call graph rather than sitting in unused
  code — `sshd.Server.handleConn` and `upstream.ScanHostKey`, which are
  the front door and the host-key scanner. To check a binary you already
  have: `go version -m ./postern | grep x/crypto` — anything below
  v0.56.0 is affected.

- **The public-key door no longer admits an account it cannot check.**
  The account-state lookup was written so that a database error skipped
  the check and fell through to accept, which meant a directory-disabled
  account could sign in with its key during any lookup failure. It now
  refuses.

- **SFTP auditing starts earlier, though not yet at the first possible
  byte.** It used to be armed only after the `subsystem sftp` request had
  been forwarded to the target and answered, so a client that sent its
  first packets without waiting for the reply could open and read a file
  before anything was watching. Those operations ran on the target and
  left no row, and — because the parser reads a length-prefixed stream
  with no handshake state — everything after them parsed cleanly and the
  file list presented itself as complete.

  Auditing is now armed before the request is forwarded. One gap is
  measured and remains: arming happens when the bastion picks the request
  off its queue, so a client that sends another request first (an
  ordinary `env` will do) still has a window while that one is answered.
  If you have relied on file history from a pre-release build, treat it
  as a floor rather than a full account for sessions from scripted
  clients.

- **A panel session is now bound to the account it signed in as, not
  just the name.** Purging a username releases it for reuse, and the
  sessions held against it were left alone — so once the name was given
  to somebody new, the previous holder's open tab resolved to the new
  account, with their roles, their targets, and audit rows under their
  name. The panel purge dropped the in-memory sessions, but `postern user
  purge` is a separate process and could not. Every panel request now
  checks the account id behind the session, which the purged row keeps,
  so the old session is refused however the account was purged.

- **A target that stops responding mid-handshake can no longer hold a
  session open.** The handshake had no time limit — the one that was
  configured applies only to the TCP connect — so a target that accepted
  the connection and then went silent kept a goroutine, a socket and a
  channel slot for as long as the user stayed connected, repeatable per
  channel. It is now bounded at 20 seconds.

- **An established SSH connection is now re-checked on every channel.**
  Identity was verified only during the handshake, and an SSH connection
  can stay open indefinitely — `ssh -N`, or ControlMaster, which many
  corporate ssh_configs turn on by default. Two consequences, both
  measured against a real client and a real target. Setting an account
  to `deleted` — the only offboarding lever for anyone with recorded
  sessions, since deletion refuses those — did not end SSH: the same
  connection kept opening channels and getting freshly signed
  certificates. And once `postern user purge` released a username, the
  departed person's connection resolved to whoever took the name next,
  running with their OS account and roles and writing sessions into the
  ledger under their name. The connection now carries the account id and
  proxy.Open verifies it per channel. If you offboarded anyone on a
  pre-release build, their SSH connections were not closed by it.

- **The guessing delay is no longer reset by changing the letter case
  of a username.** Every lookup behind it folds case, but the delay was
  keyed on the raw string the caller typed, so one account owned as many
  independent ladders as its name has spellings. Measured: rotating the
  spelling took a fixed-spelling run of 10 password checks per ten
  minutes to 100, and put 10 wrong binds against one directory account
  where 4 had got through before — above a typical AD lockout threshold,
  which is the remote lockout lever this control exists to remove.

- **Recordings are no longer written off for a fixable archive error.**
  A wrong secret, a mistyped bucket or the wrong region made the upload
  fail permanently rather than transiently, and those rows were taken
  out of the queue for good: fixing the configuration drained nothing,
  and the panel reported nothing waiting. Only a recording whose file is
  actually gone is abandoned now. See *Needs action* below.

- **Targets created through the panel or API are checked against the
  same host-key rules as the CLI.** A host *certificate* line or an
  `sk-*` line was accepted with 200 and audited as created, and the
  target was then permanently undialable — every session to it failed
  before a TCP attempt. Existing targets are not re-validated; if one
  has never connected, this is worth checking.

- **The target probe is audited for every run, not only successful
  ones.** With `target_probe.enabled`, postern runs commands on the
  target under the connecting person's identity, and the feature's
  justification for that is that every run is recorded. Runs that
  produced no usable output wrote no row at all, so the `via = probe`
  filter under-reported exactly the machines that behaved unusually. A
  timed-out probe could not even record its own timeout, because the
  audit write shared the probe's deadline.

- **`postern discover --apply` writes its grants to the audit ledger,
  and stops if it cannot.** It is the one path that hands out target
  access, and re-tagging a machine — the case the grant re-runs for —
  left no row at all, so "who gave prod access to web01?" had no answer.
  Re-running an unchanged discovery still writes nothing. Discovery also
  used to swallow a failed ledger write; now that the row that records
  access goes through the same helper, swallowing it would mean "access
  granted, no trace" — the very thing above. A run that cannot write to
  the ledger now stops with an error. Every write it does is
  re-runnable, so re-running finishes the job once the database is
  healthy.

- **The bulk-revocation ceilings can no longer be raised from the
  panel.** See *Needs action* below.

### Needs action when upgrading a pre-release build

- **Browser terminal sessions record the user's address, not the
  proxy's — `trusted_proxies` is now an audit setting.** A panel-opened
  session took its source address straight from the connection, so
  behind a TLS terminator every one of them was filed under the proxy,
  and two people behind it could not be told apart afterwards. SSH
  sessions in that same column always carried the real address, which
  is what made the mismatch easy to miss.

  If `trusted_proxies` is empty — the default — nothing changes. If it
  lists your terminator, `src_ip` for web sessions starts showing the
  browser instead: **rows written before the upgrade say the proxy and
  rows after say the user, with nothing in the schema marking the
  boundary**, so note your deploy time if you query that column
  historically. The same value flows into the SFTP file history, the
  target page, and the log line written when a session is closed.

  Read the setting's own note before widening it: a range listed there
  is a range whose members can now choose what a permanent audit row
  says about them.

- **SHA-1 and DSA no longer authenticate at the front door — check for
  DSA keys before upgrading.** The transport already refused SHA-1, but
  the signature on the identity proof is negotiated separately and had
  been left at the library default, which accepts `ssh-rsa` (SHA-1) and
  `ssh-dss`. Measured: the bastion authenticated with both.

  **RSA keys are not affected** — the same key signs with
  `rsa-sha2-256`/`rsa-sha2-512` and still works. DSA keys stop working
  outright; the algorithm has no SHA-2 variant, so there is nothing to
  fall back to. Find them before you restart:

  ```sql
  SELECT u.username, k.comment
  FROM user_public_keys k JOIN users u ON u.id = k.user_id
  WHERE k.key_blob LIKE 'AAAAB3NzaC1kc3M%';
  ```

  Every row is an account that will be locked out. Have those people
  add an ed25519 key first. New DSA keys are now refused at the point
  they are added, with the reason, rather than accepted and silently
  useless.

  A client that can only sign `ssh-rsa` also stops working. Modern
  OpenSSH says so itself (`corresponding algorithm not supported by
  server`); older automation clients may only report "permission
  denied", so check anything that has not been updated in a while.

- **Targets pinned with an RSA host key are reachable again**, and no
  longer verified over SHA-1. No action needed unless a target's sshd
  offers *only* `ssh-rsa` for its host key — OpenSSH older than 7.2, or
  one configured that way by hand. Those are now refused with a stated
  reason instead of connecting over SHA-1. To find them:

  ```sql
  SELECT t.name, t.host, COALESCE(f.server_version, '(never connected)')
  FROM targets t LEFT JOIN target_facts f ON f.target_id = t.id
  WHERE t.host_key LIKE 'ssh-rsa %';
  ```

  A row here is a target with an RSA host key pinned; only the ones on
  pre-7.2 sshd are at risk, and `server_version` tells you which. Rows
  showing `(never connected)` are ones postern has not successfully
  reached yet, so it has no banner for them — check those by hand.

  The query reads the pin rather than the recorded banner deliberately:
  `host_key_type` is only written after a *successful* connection, so a
  query driven off it silently skips exactly the targets most likely to
  be broken.

- **Run `postern db migrate`.** The schema is at 32. The bastion refuses
  to start against an older one, so this is a failed start rather than a
  silent problem — but it is still a step your deploy has to take. If you
  script the upgrade, run migrate before starting the new binary.

- **Four sync settings moved out of the panel and back to the config
  file:** `sync.max_zero_fraction`, `sync.min_zero_floor`,
  `sync.max_unknown_fraction` and `sync.max_revoke_per_run`. They are the
  ceilings on how much one directory-sync run may revoke, and raising one
  should require reaching the host — the same reason the admin flag can
  only be granted from the CLI. If you set any of them from the panel,
  **put them in `postern.yaml` now**: the stored value is no longer read.
  It is not ignored silently — the sync loop logs each one it found and
  where the real setting lives — but the ceiling in force until you move
  it is the default, not what you chose.

- **Re-install `deploy/systemd/postern.service`.** The restart limit was
  written in `[Service]`, and systemd has kept that counter on the unit
  since v229 — it did not recognise the keys and ignored them. Measured
  on the shipped file with `systemd-analyze verify` (Debian 12, systemd
  252): *Unknown key 'StartLimitIntervalSec' in section [Service],
  ignoring*. The effect is the opposite of what the file says: a bastion
  that cannot start — a bad DSN, a rejected `min_free`, a schema behind
  — restarted every five seconds forever instead of going to `failed`,
  so `systemctl status` showed `activating` and a monitor watching for
  failed units saw nothing. Copy the new unit and
  `systemctl daemon-reload`.

- **Recordings marked permanently lost by a pre-release build stay
  marked.** The fix above stops new ones being written off, but it does
  not revisit rows already flagged. If you ran a pre-release build with
  a wrong archive credential, bucket or region, look at the panel's
  Overview: the storage tile now names recordings that will never be
  archived. A non-zero count there is recordings still sitting on disk
  that will not upload on their own. There is no CLI command that
  reports it and no command that clears the flag; the rows are in
  `session_archives` with `permanent = true`.

- **`recording.min_free` takes binary suffixes only.** The documented
  example said `5GB`, which the parser refuses, so an install that
  followed the page ended with a bastion that would not start at the
  last step. Write `5GiB` (or `MiB`, `TiB`, or a plain number of bytes).
  Nothing changed in the parser; the documentation was wrong.

- **An untagged build says so again.** On a tree with no reachable tag,
  the version fallback accepted Go's pseudo-version as a release, so
  `postern version` and the startup log printed something like
  `v0.0.0-20260903172313-67c66c03fa77` with no warning —
  indistinguishable at a glance from a release binary. If you are
  answering "which build is this, is it patched" from a pre-release
  binary, re-check it: the warning line is the one that tells you it did
  not come from a tag.

- **`shutdown.drain_timeout` is new**, defaulting to 30 seconds. No
  action needed unless your sessions are long-lived and your init system
  is impatient: postern now waits this long for open sessions to finish
  before closing them, so a restart takes up to that much longer than it
  used to. Keep it under your `TimeoutStopSec` (systemd's default is 90s).

### Added

- **A security policy** (`SECURITY.md`, and in the release archive).
  Private vulnerability reporting through GitHub, what is in scope and
  what is not, and a schedule we can keep rather than a flattering one.

- **Recordings can no longer be silently stranded from the archive
  queue.** A recording left open by an unclean exit (SIGKILL, OOM, power
  loss) is now queued for archiving on the next restart, instead of being
  closed but left out of the queue where it was never uploaded and never
  counted as waiting. And a recording whose file is gone — pruned before
  archiving was turned on, or deleted by hand — is now marked lost and
  taken out of the queue, instead of being retried forever and keeping
  the "disk will fill" warning stuck on. The panel and the logs report
  those as *lost*, separately from *waiting*.

- **Recording archive.** Finished recordings are copied to an
  S3-compatible bucket and only then may be pruned locally. The upload
  never sits on the session path, a PUT is verified with a HEAD before
  anything is marked archived, and nothing unarchived is ever deleted.
  The panel holds the credential; the destination stays in the config
  file, because a panel session must not be able to redirect the audit
  trail. `postern archive check` reports what the bucket says about its
  own configuration — and says plainly that it is a misconfiguration
  detector, not a security control.

- **File history.** "Who touched `/etc/shadow`" is now a question the
  panel can answer, searchable by path, by person, by machine, or any
  combination, and by a whole directory tree rather than one exact path.
  It names the person rather than a session id, marks files that arrived
  somewhere by rename, and says on every screen that it covers SFTP
  events only — a file read inside a shell leaves no row there.

- **Closing a live session** from the panel, with the reason reaching
  both the user's terminal and the recording.

- **`postern log`** reads the administrative audit trail from the host.
  Both the panel and the CLI write to it; this is the only way to read it
  without the panel.

- **`postern user unbind-directory`** detaches an account from a
  directory identity that no longer exists. A person deleted and
  re-created in the directory gets a new stable identity and was
  previously locked out of their own account with no way back except
  editing the database by hand.

- **`postern version`** reports the tag, the commit, whether the tree was
  modified when it was built, the Go version and the platform. A build
  that did not come from a release tag says so rather than inventing a
  number.

- **`/healthz` and `/readyz`.** The first touches nothing; the second
  checks the database behind a one-second cache so an unauthenticated
  endpoint cannot be used to load it. Neither reports a version, a
  hostname, or a reason.

- **CLI role management** — `postern role list`, `role revoke-target`,
  `user grant-role`, `user revoke-role` — including a warning when a
  manual grant takes over a role that came from a directory group, since
  directory sync will no longer take it away.

- **A production checklist and an Ansible role** for the one line each
  target needs. The role validates with `sshd -t` before installing and
  reloads rather than restarts, so nobody's session dies for it.

### Changed

- **The CLI's administrator lever now writes to the audit log.**
  `postern settings set --key ldap.admin_group`, which revokes
  administrator from the previous group and grants it to the next, and
  `postern mapping add`/`remove`, which grant and revoke a role to a
  whole directory group, wrote nothing to the ledger — so an
  administrator change made from the host left no trace. They now record
  it, with the same action names the panel uses.

- **Retention deletions are always audited, even with archiving off.**
  The recording.prune audit row was written only when an object store
  was configured, so the ordinary retention-without-archive deployment
  deleted recordings and recorded nothing — while the panel points the
  auditor at the admin log for the reason. It is written on every path
  now, and a recording whose session is still open is no longer pruned
  mid-session.

- **Sign-in lookups are case-insensitive everywhere.** The account row,
  its state, its credential, its TOTP enrolment and its directory binding
  were looked up case-sensitively although usernames are
  case-insensitively unique — so the same account could be found by one
  path and reported missing by another, and the break-glass door refused
  a correct secret when the name's case differed.

- **Shutdown waits for open sessions** instead of cutting them
  mid-flight. Beyond the interruption, the old behaviour meant
  `Session.Close` never ran: the audit row stayed "running" forever, the
  recording closed half-written, and the session never reached the
  archive queue — where, since nothing unarchived is pruned, it then sat
  on disk unable to be uploaded or removed.

- **A command that ran no longer reaches the user as a dropped
  connection.** On a session that ended the instant its command did —
  `ssh host echo hello`, and the scripted checks built on that shape —
  the bastion could close the user's channel while the reply to their
  own request was still on the way. The command had run and its output
  was already written; what the user saw was an unexplained
  disconnection, so retrying was the natural response. Rare in
  practice and never reproduced by running it, but it needed a
  recording write and a log line to land in the window, which is to
  say: more likely on a busy bastion than on an idle one.

- **Screens no longer report a failed query as an empty result.** Six of
  them did: two target pages, two CLI listings, the session count on the
  overview, and the recordings-on-disk figure. An audit tool that answers
  "nothing happened" when it means "I could not look" is worse than one
  that says nothing at all.

- **Failed archive uploads back off exponentially** instead of retrying
  a misspelled bucket name on every pass, and rows that keep failing are
  counted separately from rows that are merely waiting. Nothing is marked
  permanently dead, so fixing the bucket lets the queue drain without a
  new command.

- **`make ci` runs the panel's tests.** It described itself as
  "everything CI runs" while leaving out `web-test` and `web-check`, so a
  green local run did not cover 320 tests or the check that catches a
  commit editing `web/src` without rebuilding the embedded bundle.

### Release engineering

- **Releases are built, checksummed and signed by CI** on a `v*` tag.
  Four static binaries (`linux`/`darwin`, `amd64`/`arm64`) with the panel
  compiled in, the version stamped from the tag, and `checksums.txt`
  signed with a cosign keyless signature bound to this repository and
  workflow — there is no signing key to store or rotate. The release is
  left as a draft for a human to publish. Verification steps are in the
  release notes and in the install documentation.

- **The import path is `github.com/Warewave-Technology/postern`.** It
  was `github.com/warewave/postern`, which is not a namespace we hold —
  and a module path is a claim on one. Nothing outside this repository
  could have depended on it, since it never resolved to anywhere. Three
  things it quietly broke: `go install` could not find the module; the
  Makefile's `-X` flag named a package path that no longer existed, and
  a `-X` whose path does not match does nothing and says nothing, so the
  version stamp would have stopped landing; and the cosign identity
  below pinned the old organisation.

- **The published verification command changed with it.** The
  `--certificate-identity-regexp` in the install documentation must name
  the repository that ran the workflow. If you copied the command from
  the documentation site before this release, take it again from the
  release notes — the old one rejects a genuine signature, which is the
  worst way for a verification step to fail.

- **The release workflow pins its actions to commit SHAs, and one of
  them never resolved at all.** `sigstore/cosign-installer@v4` does not
  exist — that project publishes full versions only — so the first tag
  would have run the entire test suite and then failed at the signing
  step. Pinning is the wider fix: this is the job that mints the signed
  binary, so a hijacked tag there means a substituted binary reaching
  everyone with a valid signature.

### Legal

- **The `LICENSE` file was a truncated copy of Apache-2.0** and is now
  the upstream text verbatim. It ended at section 9, missing
  `END OF TERMS AND CONDITIONS` and the appendix — the part that tells a
  reader how to apply the licence to their own work. Nothing about the
  terms changed; the file simply stopped early.

### Removed

- **`store.ActiveUser`**, **`store.HasDirectoryIdentity`** and
  **`store.PendingWaitingCount`** — written, tested, and called from
  nowhere. The first was the more dangerous of the three: it refused any
  account that was not `active`, which is stricter than the session
  middleware deliberately is, and leaving the wrong option next to the
  right one was an invitation to pick it.

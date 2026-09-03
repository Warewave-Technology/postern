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
  There is no "Unreleased" section yet: 1.0.0 is not out, so everything
  below is unreleased. Open one above the 1.0.0 heading on the first
  commit after the tag.
-->

## 1.0.0 — unreleased

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

- **Purging a username now drops that name's panel sessions.** Purging
  releases the name for reuse; the sessions held against it were left
  alone. Once the name was given to somebody new, the previous holder's
  open tab resolved to the new account — their roles, their targets, and
  audit rows written under their name. Deleting an account and setting
  one to `deleted` drop sessions too now, rather than waiting for the
  account's next request.

- **A target that stops responding mid-handshake can no longer hold a
  session open.** The handshake had no time limit — the one that was
  configured applies only to the TCP connect — so a target that accepted
  the connection and then went silent kept a goroutine, a socket and a
  channel slot for as long as the user stayed connected, repeatable per
  channel. It is now bounded at 20 seconds.

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

- **`shutdown.drain_timeout` is new**, defaulting to 30 seconds. No
  action needed unless your sessions are long-lived and your init system
  is impatient: postern now waits this long for open sessions to finish
  before closing them, so a restart takes up to that much longer than it
  used to. Keep it under your `TimeoutStopSec` (systemd's default is 90s).

### Added

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

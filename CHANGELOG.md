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

## Unreleased

### Needs action if you rely on recordings as evidence

- **Recordings now carry a tamper-evident chain, and four schema migrations
  land with this release (034–037).** Run `postern db migrate` before starting
  the new binary; the bastion refuses to start against a schema it does not
  match rather than writing audit rows into a shape it does not understand.

  Sessions that closed **before** migration 034 have no chain, and
  `postern session verify` reports them as *cannot be verified* — not as
  failures. That distinction is deliberate and load-bearing: collapsing it
  would either accuse old recordings of tampering or quietly bless them.

- **What was written down as a limit is no longer true, and the new limit is
  narrower.** Earlier releases stated plainly that there was no integrity seal
  on recordings. There is one now — but what it proves on its own is that a
  file was not altered after it was written. Someone with root on the bastion
  can rewrite the file *and* the head stored beside it. The copy that closes
  that gap is the head each archived recording carries as object metadata, and
  `postern session verify` now reads it, and the panel shows chain state on
  each session (both below).

### Added

- **The panel's file browser fetches a whole folder.** Tick a folder in the
  remote pane and press Download; postern walks the tree over the same SFTP
  channel a shell session uses and hands you one `.zip`. Every file in it was
  read the way any SSH client reads a file — through the path policy, into
  the session's file journal, and into the chain that seals the recording.
  There is still no server-side helper holding an SFTP client of its own.

  **What it does not do, and says so.** Symbolic links inside the tree are
  not followed — a link is a loop waiting to happen, and following one means
  fetching what you did not point at. Entries the target refuses to type
  (no permission bits in its reply) are skipped rather than guessed at:
  guessing is how a link would walk back in through the front door. FIFOs
  and device nodes are skipped; opening one blocks until somebody writes to
  it. Everything left out is counted on the transfer row **and written into
  the archive** as `POSTERN-NOT-INCLUDED.txt`, because the panel closes and
  the archive is what you still have in six months.

  **Hidden files are included** — a folder download is meant to be a faithful
  copy — and the panel says so before you press the button, since the list
  above it hides them by default.

  **A folder of more than 4,000 entries, or more than 2 GiB, is refused
  rather than half-fetched**, and the refusal names a smaller folder or an
  SFTP client as the way through. Every entry costs rows in the session's
  file journal and lines in its recording — one per directory, two per file
  — so a session that fetches a large tree is a session whose audit trail
  grows with it. There is a **Stop** on every running transfer; stopping a
  download saves nothing, and stopping an upload leaves on the target
  whatever had already been written.

  Names coming from the target are neutralised before they enter the
  archive: path separators, `..`, control bytes and right-to-left overrides,
  which make a name read as something other than what it is. Two names that
  differ only in case or in Unicode normalisation are separated, because
  they would land on one file when the archive is extracted on macOS or
  Windows.

- **A folder that could not be listed no longer appears in the archive as an
  empty one.** Found by running the feature against a live target: a directory
  the path policy refuses was written into the archive before its listing was
  attempted, so `.ssh/` arrived as an empty folder. Six months later "refused"
  and "was empty" look the same to whoever opens the archive, and only one of
  them is evidence. Refused directories are now named in
  `POSTERN-NOT-INCLUDED.txt` and nowhere else; genuinely empty ones still
  arrive as empty.

- **Recordings drop right-to-left overrides from names, as they already dropped
  escape sequences.** A recording is replayed into a terminal. An escape
  sequence repaints the screen, which the sanitiser already caught; a
  bidirectional control does something quieter — the line stays intact and
  *reads* as something else. A file named with `U+202E` produced a recording
  line reading `fatura exe.png`, so an auditor scanning it would believe an
  image had been fetched. Names in the journal are untouched: that is the
  target's real name, and the journal is queried rather than rendered.

- **Downloads are checked against the size the target listed.** A file
  delivered short now fails with both numbers instead of being saved quietly
  truncated, and a reply that stops mid-file no longer leaves a hole: the
  client used to keep asking at fixed offsets, so a short reply anywhere but
  at the end silently spliced the bytes after it onto the bytes before it.
  This affected single-file downloads before this release and would have
  reached folder downloads as a valid-looking archive over corrupted bytes.

- **SFTP sessions are recorded and sealed.** Until now the `.cast` file for
  an SFTP session held its header and nothing else: transfer bytes never
  enter a terminal recording, which is what kept the channel shut in the
  first place, and the chain therefore sealed an empty file. What records
  the session now is the decoded narrative:

  ```
  postern: subsystem sftp
  postern sftp: opendir /home/dev
  postern sftp: get rapor.pdf (1.2 MiB)
  postern sftp: denied opendir /etc — path is not allowed by your role
  postern sftp: 4 events, digest sha256:…
  ```

  File contents are still never recorded. The chain now covers what the
  session did, an SFTP session replays in the same player as a shell, and
  `postern session verify` answers for both. Filenames and the target's own
  error text are stripped of control bytes on the way in: a recording is
  replayed into a terminal, and a filename carrying an escape sequence
  could otherwise repaint an auditor's screen.

  **Nothing changes for shell sessions**, and there is a test that compares
  a shell recording made with SFTP enabled against one made with it
  disabled, event for event.

  Recordings of SFTP sessions are no longer near-empty, so they now take
  space in proportion to how much the session did — a few hundred bytes per
  directory opened or file transferred. If you prune recordings by size,
  that assumption has changed.

- **The file journal is now checked against the recording that sealed it, and
  a journal that lost events says so.** Two things were wrong, and they were
  the same thing seen from either end.

  When the write buffer for file events overflowed — a database too slow or
  gone, a client moving thousands of small files — postern dropped the event
  and ended the session. Ending it was right. Dropping it silently was not:
  the drop was written nowhere, and because the session is only killed once,
  every drop after the first left no trace at all. The event was already in
  the recording by then, so what remained was a recording that counted an
  event the journal had no row for, and nothing that compared the two.

  Now every drop is counted, the count is written to the session when it
  closes, and the bastion's log says the journal is incomplete rather than
  only that the audit failed. One case cannot reach that count and says so
  instead: an event arriving *after* the journal has closed is refused and
  logged, because the number it would belong to was written when the
  session closed. It is no longer swallowed — it used to go into a buffer
  nobody would read again. The recording's seal line — its event count
  **and** the digest of the lines it counted — is stored with the session
  as well, so it finally has a reader:

  ```
  JOURNAL  ROWS MISSING
    3 events in the recording's seal, 1 row in the journal
    the journal has no row for 2 events the recording's seal counts
  ```

  **The digest catches what a count cannot.** Deleting a row leaves a gap;
  changing one — an `UPDATE` that turns `/etc/shadow` into `/tmp/notes` —
  leaves a journal that counts correctly and reads like a complete audit
  trail. The rows are turned back into the lines they were written as and
  their digest is recomputed, so that edit is reported as **rows altered**
  rather than passing as intact. The digest is order-independent, because
  the journal returns rows in its own order; the price is that an even
  number of identical lines cancel out, which is what the count is still
  there for.

  The output says which of the two it checked: sessions sealed before the
  digest existed can be reported as counting correctly, never as having
  contents that match.

  `postern session verify` prints that block on every path and exits
  non-zero when the two disagree, with an error separate from a changed
  recording — the file can be intact while the journal is not. The panel's
  session view says it above the file list, including when that list is
  **empty**, which is exactly the case that used to read as "this session
  touched no files".

  **What it separates.** *Incomplete* is postern's own loss, reported with
  the number it lost. *Rows missing* is a journal shorter than postern can
  account for — what deleting rows looks like. *Rows altered* is a journal
  of the right length whose contents no longer match. *Not checked* covers every
  session that closed before this release and every session that was never
  recorded; there is no seal to compare against, and treating that as "fine"
  would be the same mistake as calling an unchained recording verified. On
  your first upgrade that is every session you already have, and no alarm is
  raised for any of them.

  **What it does not prove.** The rows, the count and the digest all live in
  this host's database and root here can rewrite them together, the same
  limit the chain has. What it closes is narrower and real: a `DELETE` or an
  `UPDATE` against `session_files` used to leave a recording that still
  verified and a file list that looked complete. Editing a row is far
  cheaper than rewriting a recording and recomputing its chain, and until
  now nothing looked at it at all.

- **The panel shows the recording chain.** Opening a session in the audit
  view gives its chain its own card, with a **Verify** button. Migration 034
  asked for this: until now a verified recording and one that had never been
  checked looked identical.

  Before you press it, the card says only what is known — whether a chain
  was stored when the session closed. That is deliberately not drawn as a
  green tick: a stored head is not a file that still matches it, and only
  recomputing the chain can say which. Pressing Verify reports two separate
  lines, the local result and what the archived copy says, and they are
  never merged — "the file matches this host but the archive disagrees" is
  the pair's most important answer and a single badge would bury it.

  Sessions with no chain — everything that closed before this release, and
  everything still running — read as neutral rather than as an alarm.

  Verifying writes an audit line (`session.verify`) before it reads
  anything, and if that line cannot be written the verification does not
  run: the same rule replaying a recording already follows. Three
  verifications run at once; a fourth is told to try again rather than
  queued, and the archive lookup gets a short timeout of its own instead of
  the uploader's thirty seconds.

- **`postern session verify` now reads the archived copy of the chain
  head.** The head has been travelling to the bucket as object metadata
  since 1.1; nothing read it back, so the chain's strongest claim needed a
  person to make it by hand. Verify now answers four states — the archived
  copy CONFIRMS, DISAGREES, carries NO CHAIN, or was NOT CHECKED.

  **DISAGREES is the case this exists for.** A file that matches this
  host's database while the archived head differs means both were
  rewritten together, which takes root here and which the bucket does not
  follow while its retention lasts. The command exits non-zero and names
  the archived head as the one to trust.

  Not being able to check is not a failure — an unreachable bucket is not
  evidence of tampering — but it never reads as confirmation either. For
  scripts that must distinguish them, `--require-archive` turns
  "not checked" into a non-zero exit.

  **A recording that was archived and then pruned still gets an answer.**
  Verify used to fail on the missing file before it ever looked at the
  bucket — which is precisely the case where the archived copy is the only
  evidence left. It now reports `NO LOCAL COPY` and says what the archived
  head shows. That is deliberately not called "verified": the heads
  agreeing means the database was not rewritten, and the bytes were not
  checked, because they are not on this host.

- **Recordings are chained as they are written.** Each line extends a SHA-256
  chain; the head and link count are stored with the session, and the head
  travels to the archive as object metadata.

  ```bash
  postern session verify <session-id>
  ```

  Answers verified, failed, or cannot-be-verified.

- **Roles carry SFTP path rules.** A role can be granted or refused a path
  prefix, read-only or read-write:

  ```bash
  postern role path set --role dev --prefix /home/dev --write
  postern role path set --role dev --prefix /home/dev/.ssh --deny
  postern role path list --role dev
  ```

  Rules from all of a user's roles are pooled and the longest matching prefix
  decides; at equal length a denial wins. **A role with no rules is
  unrestricted, and one such role among a user's roles switches every rule
  off** — writing rules restricts a role, not a person. Refused requests are
  answered by postern with the reason on stderr, so the user sees why rather
  than a bare failure, and each refusal is recorded.

- **`postern admin unlock`.** Wrong authenticator codes now lock an account
  (see below); this clears the lock and the counter without forcing a
  re-enrolment. `postern admin reset-totp` remains the answer for a lost phone.

- **File transfer in the panel.** Open a shell and press **Files**: a
  two-pane view opens over it — your computer on the left, the host on the
  right — with drag-and-drop between them, per-file progress, and a
  completed-or-why-not line for each transfer. It needs both
  `session.sftp` and the new `session.sftp_panel`, and both are off by
  default:

  ```yaml
  session:
    sftp: true
    sftp_panel: true
  ```

  The panel speaks SFTP itself over a websocket; there is no server-side
  SFTP client, and no second route to the files. Every packet goes through
  the broker an SSH client's packets go through, so browsing writes the
  same `session_files` rows and obeys the same role path rules, and closing
  the tab ends the session.

  A browsing session is recorded and sealed like any other — see below.

  **It will refuse to open on an account whose roles carry no path rules,
  and this is deliberate.** A role without rules is unrestricted; a fresh
  install has none. Run `postern role path set` for the roles that should
  reach files, and the button starts working for their holders. Until
  then the panel says so instead of opening.

  **Uploading is a third setting, `session.sftp_panel_write`, also off by
  default.** Leaving it off keeps the channel read-only on the server, so
  browsing and downloading work and nothing can be written. Turning it on
  lifts that lock only: where a file may be written is still the role's
  path rules, and every write is checked against the path behind the
  handle rather than inferred from how the file was opened.

  The transfer view lives in the shell window rather than on its own page,
  which also means one session instead of two for what a person thinks of
  as one piece of work.

  **The local pane is a tray, not a file manager.** A page can browse your
  disk only through the File System Access API, which WebKit closed as
  "oppose" and Firefox does not ship; downloads go to the browser's own
  download folder. Files over 2 GiB are refused with a sentence naming an
  SFTP client, because a browser holds a download in memory until it is
  saved.

- **Role path rules are editable from the panel.** Roles now carry a
  `Paths` button opening the SFTP rules for that role: add a prefix as
  read-only, read-write or a denial, and remove one. They were CLI-only
  (`postern role path set`), which meant the file browser could send an
  administrator to a wall the panel had no way to take down.

  The screen says what an empty list means — **a role with no rules is
  unrestricted** — and removing the last rule asks about that specifically
  rather than about the line being removed. Both are the direction the
  mistake falls in: a table that reads as "reaches nothing" would let
  somebody believe they had written a restriction they had not.

### Changed

- **The code prompt at sign-in is bounded, counted, and locks.** The prompt
  lives for two minutes. Wrong or expired attempts are counted, and at three
  the account locks for fifteen minutes. All three are settings, and the
  defaults are what a fresh install gets:

  ```yaml
  auth:
    totp_window: 2m
    totp_max_failures: 3
    totp_lock_for: 15m
  ```

  The lock expires on its own, so nobody is stranded; `postern admin unlock`
  lifts it now. The first successful sign-in after failures says how many
  there were, which is the point of counting them. Attempts refused by the
  per-IP rate limit are deliberately **not** counted — the code was never
  checked, and counting them would let anyone lock an account by burning its
  quota.

- **The sign-in credential is called a password everywhere.** It used to be
  "sign-in secret", which stopped being accurate once local accounts chose
  their own. Internal names describing the *generated* value's shape were
  left alone on purpose.

- **A denied SFTP request now gets an answer.** postern used to drop refused
  requests, and the client waited for a reply that was never coming; it now
  writes its own status packet, at a packet boundary.

- **`/api/me` reports `files_enabled`.** Separate from `terminal_enabled`,
  because a bastion can have the terminal on and the file browser off. No
  action needed; the panel reads it to decide whether to draw the button.

### Fixed

- **A single file could empty a session's whole file record.** The audit
  ledger indexes `session_files.path`, and PostgreSQL refuses a b-tree key
  past 2704 bytes; postern kept paths up to 4096. A path in between —
  ordinary nested directories, no exotic client needed — made the `INSERT`
  fail. Because a flush is one transaction, what was lost was not that row
  but **every file event buffered with it**, `/etc/shadow` included; the
  session was then killed, and the rejected row was put back at the *head*
  of the buffer, so every later flush hit the same wall. The same failure
  had a second, easier trigger: a filename that is not valid UTF-8 —
  latin-1 names are common on real servers, and POSIX permits them — or one
  carrying a NUL byte.

  Paths are now cut to what the ledger holds and marked ` (truncated)`;
  bytes PostgreSQL cannot store are removed and marked
  ` (invalid bytes removed)`. Both words are postern's, not the file's. The
  path is cut rather than the row dropped so that searching the parent
  directory still finds it — the question investigations actually ask.

  **Pre-flight.** The ledger cannot tell you whether you were hit: the rows
  were never written. The log can, and it is the only place the loss was
  recorded:

  ```
  grep -e 'sftp audit rows could not be written' -e 'exceeds btree' postern.log
  ```

  How close your own environment runs to the wall, and — from this release
  on — whether anything was dropped:

  ```sql
  SELECT max(octet_length(path)) AS longest_path FROM session_files;
  SELECT at, op, path, detail FROM session_files WHERE op LIKE 'dropped.%';
  ```

- **A refused request can no longer erase its own audit row.** postern
  writes its own denials to `session_files`, with the SSH request type in
  `op`. That type is raw bytes off the wire, so a client sending an invalid
  one made the row unstorable: the request was still refused, but "who
  tried" left no trace. The type is now put through the same filter the
  recording uses.

- **A row the database will never accept no longer blocks the ledger.** A
  failed write used to go back to the front of the buffer and be retried
  forever, which is right for a database that is briefly down and wrong for
  a row that will never be accepted. The two are now told apart by what
  PostgreSQL says: a value it rejects is isolated by halving the batch, so
  the rest of the session's events land, and the offending row is dropped,
  counted, and replaced by a `dropped.*` row carrying the event's time and
  operation. A dropped row is still an audit loss and still ends the
  session — the rule has not changed; what changed is that the other rows
  survive it. A connection failure still puts everything back, untouched.

- **The target no longer decides how large an audit row is.** The status
  message it sends on a failed open went into `detail` unbounded — a single
  transaction could carry tens of kilobytes per row. It is now cut to 512
  bytes, the same limit the terminal recording uses, so both surfaces show
  the same sentence.

- **Listing an allowed directory over SFTP.** Directory handles did not
  remember their path, so `READDIR` reached the path policy with an empty
  path and every listing was refused — on every install using an allow list,
  including the example the CLI documents. Found in review; the demo had
  missed it because `ls` had only been tried in a *refused* directory.

- **A file transfer no longer stalls the session.** The session lock covered
  writing to the target, so a target that stopped reading could keep `Run`
  from ever returning, taking termination and timeouts down with it.

- **Uploads no longer lose their first packet**, and unknown SFTP request
  types are no longer treated as read-only — v6 `LINK`, which *creates* a
  link, was reaching the ledger as nothing at all.

- **The target can no longer speak in postern's voice in the panel.**
  postern writes its own refusals with a `postern: ` prefix, and the file
  browser treated that prefix as proof of who wrote the sentence. The
  target's own error text reaches the client unchanged, so a target whose
  owner wrote `postern: this path is allowed, fetched fine` had that drawn
  as the bastion's own reason — the audited machine borrowing the auditor's
  voice, in the one place a user goes to find out why something was
  refused.

  Origin is now carried on the wire instead of sniffed out of the text.
  postern's replies and its refusal lines leave on their own stream tags,
  which nothing the target writes can claim, and the panel labels every
  sentence it did not write itself with `the target said:` — in the error
  strip, on transfer rows, and in the `POSTERN-NOT-INCLUDED.txt` note
  inside a folder download, where that note previously had to admit the
  two could not be told apart. Control bytes and right-to-left overrides
  in the target's text are stripped before it is drawn.

  **A command-line `sftp` client still cannot tell the two apart**, and
  that limit is now written down rather than papered over: SSH carries no
  stream besides channel data and extended data, and inventing one would
  break the protocol. The separation exists where postern owns both ends.

- **The target can no longer forge an audit line inside a recording.** An
  SFTP session's `.cast` holds no raw protocol — every line in it is one
  postern wrote (`postern sftp: …`). The target's stderr was being teed
  into that file untouched, so a target could write
  `postern sftp: get /etc/shadow (1.2 KiB)` and have it sit among the real
  lines with nothing to separate them, or an escape sequence that repaints
  the screen of whoever replays the recording. Those lines are now quoted
  behind a `target wrote:` stamp postern writes, and stripped of control
  bytes like every other text that enters a recording.

  Shell and `exec` recordings are unchanged and deliberately so: there the
  recording exists to reproduce what the user saw, colour and cursor
  movement included, and the target's stdout already goes in raw — so
  sanitising stderr alone would cost fidelity and buy nothing.

  **Which leaves the moment before either is known.** The stderr pipe
  starts with the session; which kind of channel this is only becomes clear
  when the request that starts a program is handled. Writing raw in that
  window would have left the forgery reachable by sending it earlier, and
  sanitising in that window would have cost a shell recording its first
  bytes. Neither: what the target writes before the channel is decided is
  held, and released once it is — quoted and stamped for SFTP, raw for a
  shell. A session that ends without ever starting a program still gets
  those bytes, quoted, and the stamp says `postern:` rather than
  `postern sftp:`, because that channel never became one.

## 1.1.0 — 2026-09-05

### Needs action if you unpacked a 1.0.2 archive

- **The `README.md` inside the 1.0.2 archives gives a download command that
  returns 404.** It names `postern_1.0.1_linux_amd64.tar.gz` and fetches it
  through `releases/latest/download/`, so it broke the moment 1.0.2 became
  latest. The fix was committed after the tag was cut, which is why it
  missed the archives. Nothing else in the archive is affected — the binary,
  the checksums and the signature are the ones 1.0.2 published. Use the
  commands on [the install page](https://postern.warewave.tech/docs/#install)
  — that copy pins the tag in the identity it checks, which is the point
  of checking it.

### Needs action if you never set a secret key

- **Enrolling an authenticator now requires one.** postern seals the TOTP
  secret at rest with the same key that already seals stored settings
  (`secret_key_file`, `internal/secret`). Installs that skipped
  `postern secret init` could enrol before and cannot now: the enrolment is
  refused rather than writing the seed in plain text, and the log names the
  fix. The documented install has always included that step, so most
  installs are unaffected.

  **Nobody loses an authenticator.** Enrolments made before this release
  keep working exactly as they did, and each one is sealed in place the
  first time its owner enters a correct code — no operator action, no
  re-enrolment, no window where the second factor is unavailable.

  Why now: the seed used to gate one thing — adding a second SSH key. From
  1.1 it gates every local sign-in, so what a leaked database row is worth
  changed, and the old note in migration 028 ("the secret is stored in the
  clear and there is no other way") was half right. A TOTP seed cannot be
  *hashed* — verification has to generate codes from it — but it can be
  sealed, which is what the settings table has always done with the LDAP
  bind password for the same reason. Sealing does not defend against
  somebody holding root on the bastion; it defends against the database
  contents alone being enough — a dump that left the box, a stale replica,
  a table pasted into a ticket.

### Needs action for every local account

- **Signing in locally asks for the authenticator code.** TOTP was a
  step-up factor — asked only when adding a second SSH key. It is a
  sign-in factor now: password, then code, on every local sign-in.

  The code is asked only of accounts that have a confirmed authenticator,
  and that is not a gap. An account without one signs in and immediately
  meets the enrolment gate, which lets it do nothing else. Demanding a
  code from an account that has none would be a lock with no key: you
  could not sign in, so you could not enrol, so you could not sign in.

  **The session is created after the code, not before.** Getting this
  backwards would leave somebody who does not know the code holding a
  valid session, and what that session could reach would then depend on
  every other gate being right. Nothing exists until the second factor is
  proven.

  Codes are single-use here as everywhere else: the same code cannot open
  a second session inside its thirty-second window.

  Guessing is bounded by the sign-in rate limit, which a coded attempt
  spends twice — once for the password check and once for the code — so a
  single source gets five attempts a minute. The escalating backoff shares
  its counter with the password door and no longer resets when the
  password is right and the code is wrong, but be clear about which of the
  two is doing the work: measured, the per-minute limit binds first at
  this door, and the backoff is what remains if that limit is ever
  loosened.

- **A local sign-in now reaches nothing until an authenticator is
  enrolled.** postern stands between people and their servers, so a
  password on its own is not a sufficient answer to "who is this". The
  panel shows the enrolment screen immediately after the password screen
  and nothing else until it is finished.

  Who this affects: accounts that sign in through the local password door.
  Directory and identity-provider sign-ins are untouched — their second
  factor belongs to the identity provider, and postern adding a second
  requirement on top would be overriding a decision your organisation has
  already made. SSH is untouched as well; local credentials were never
  read there.

  What stays open while enrolling: reading your own account, the three
  enrolment endpoints, and changing your password. That last one is
  deliberate — somebody who thinks their password has leaked should be
  able to change it *before* setting up a second factor on top of it, not
  after. Adding an SSH key stays shut, because the first key on an account
  is added with no verification and would otherwise be a way straight past
  the requirement.

- **`postern serve` refuses to start when local accounts exist and no
  `secret_key_file` is configured.** The two changes in this release
  combine into a lock otherwise: the gate requires enrolment, enrolment
  requires sealing, sealing requires the key, and there is no way out from
  inside the panel. For an installation with a single administrator that
  is the end of access to the bastion. The refusal names the fix, and it
  happens while starting the service rather than at somebody's login
  screen.

### Added

- **`postern admin reset-totp --name <user>` clears an authenticator from
  the host.** The panel could already do this — Users → the account →
  Reset authenticator — and on most days that is the right door. It stops
  working in one case, and it is the case that matters: once a second
  factor is required to sign in, the administrator who lost their phone
  cannot reach the panel to reset anybody, including themselves. The panel
  path has no base case; this one does.

  It grants nothing new. Whoever can run it can already edit the row with
  `psql`, and `postern admin bootstrap` runs from the same place with the
  same authority. What it adds is the audit line — removing a second
  factor by hand leaves none, and a second factor disappearing should
  never be untraceable.

  Still no recovery codes, for the reason the code has always given: a
  second secret the user writes down moves the protection onto that piece
  of paper. Recovery stays with a party that can already establish
  identity. This release only adds the case where that party is whoever
  holds the host rather than whoever can reach the panel.

### Changed

- **Verifying a release now pins the tag, not just the repository.** The
  documented `--certificate-identity-regexp` ended at
  `release.yml@`, which proves an artifact came from this repository's
  release workflow but not *which release* — the same command verified any
  version's `checksums.txt`. It now ends `@refs/tags/<version>$`, so a
  signed checksums file from a different release no longer satisfies it.

- **The release notes verify before they checksum.** They listed the
  `sha256sum` step first and the signature afterwards. A checksum read out
  of an unverified file only proves the archive and the checksum arrived
  together, so the order is now signature, then checksum — matching what
  the install docs already say.

- **`README.md` stops pretending to follow the latest release.** Its
  download URL went through `releases/latest/download/` with the version
  written into the filename, which cannot work: the filename changes every
  release. It pins the tag explicitly now, the way the install docs do.

### Fixed

- **A release whose documentation still names the previous version stops
  before it ships.** `make release-docs-check` compares the version strings
  in `README.md` and the install docs against the tag being built, and runs
  as a release before-hook. This is the check that would have caught the
  README above.

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

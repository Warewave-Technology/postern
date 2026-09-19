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

### The panel moved some things

**Adding a discovery source is on its own screen.** Sources and the
machines they found were two tables under one heading, and which was which
did not read — the more so because one of the buttons on that page removes
a source along with every machine it found. They are two entries under
Infrastructure now: **Discovery sources** for what postern reads,
**Discovery** for what it found.

**The machine list shows what is waiting for a decision.** It used to show
six states at once; four of them had nothing to do on that screen, and on
a cluster where twenty-two of twenty-four machines were in those states
the two that needed an answer were lost among them. The rest are one click
away, each with a sentence saying what the state means — `blocked` in
particular reads as a decision postern made, and it is the machine's
state.

**Notifications have a page.** The bell opened a dropdown that cut its own
sentences and left nothing behind when it closed, so there was no such
thing as having seen something. It opens a page now and marks everything
seen; the badge counts only what started waiting since *you* last looked,
and that stamp is per person, so one admin reading does not clear a
colleague's badge. Nothing is stored but that timestamp — the list is
still derived, so a line disappears when its work is done.

**A session record says which door it came through** — an SSH client, the
panel's terminal, or the panel's file browser. Opening the file browser on
a host somebody is already in creates a second session, and those two rows
used to be identical in every column the panel shows.

**Dialog and form buttons are at the bottom right**, where they are in
almost every other interface. A destructive action still sits apart from
the primary one rather than next to it.

### The home screen groups by application and environment

**Targets carrying an `app` label are grouped under it, and split by
`env` inside it.** A fleet is not read alphabetically: the question is
almost always which application first, then which environment, and the
screen carries that order now. `application` and `environment` work as
well, and the key is matched without regard to case — discovery copies
Proxmox and vCenter tags verbatim, so `App` and `ENV` are what some
estates actually have.

A machine with an environment but no application is not lost: **Others**
opens at the end and holds it under its own environment name, with
**Other env** for the ones carrying neither. The two leftover buckets
always sort last, so the eye learns where to find them.

**A fleet with none of these labels keeps the flat grid it has today.**
Putting everything under a single "Others → Other env" heading would add
two lines of noise and separate nothing. Grouping starts on its own the
first time an `app` or `env` label exists.

### Needs action if you manage accounts with something else

**postern can now own the OS accounts of the people it lets in, and it is
off until you say otherwise.** With `manage.propagate_accounts: true` (it
requires `manage.enabled`, and postern refuses to start if you set one
without the other), the first time somebody opens a session on a target
postern creates their account there, puts them in a `postern-<group>`
group for each group that grants that target, and writes that group's sudo
rule. When the last group granting a target goes away, a loop expires and
locks the account on the host.

There is a **Locked accounts** screen under Access for the decision that
follows. An account postern locked is waiting for a person to say whether
it goes for good, and every row says who opened it — postern, or something
that was there first. Deleting one postern opened takes back what postern
made; deleting one it adopted destroys something another tool owns, and
postern cannot put it back, so the two are confirmed with different words.
Keeping an account locked asks nothing: it is not destructive, and a
confirmation on every button is a confirmation nobody reads. The bell
counts these too.

A deletion still needs proof on the machine, not in the database. An
account postern created joins a `postern-managed` group when it is made,
and that membership is what permits a delete — the row in postern's
database can disagree with the host after a rebuild or a restore, and the
account being deleted is the one on the host.

This changes a sentence that used to be true: postern only wrote to a
machine when you asked it to open a temporary account. It still installs
nothing — no agent, sshd and sudo only — but with this on it writes as
people connect. Leave the key unset and nothing changes.

Two things it deliberately does not do. An account that already exists is
**adopted**, not recreated: UID, shell and home are left alone, and which
of the two happened is recorded, because a deletion has to know. And a
failure to prepare an account **never refuses the session** — a host
postern cannot manage behaves exactly as it does today, and the reason
travels in the dial error instead of a log on the far machine.

Everyone carries one number. If your directory publishes `uidNumber`,
postern uses it; otherwise it takes the lowest free number from
`manage.uid_pool_min`–`manage.uid_pool_max` (60000–64999 by default, above
the range a distribution's own `useradd` uses and below `nobody`) and keeps
it for that person on every machine. A number that is already taken on a
target is **never forced**: the account is created with the target's own
number and the clash is written to the audit log with the name of whoever
holds it, because forcing it would hand that account's home, logs and keys
to the new person.

**A sweep, for what nothing else can see.** The connect-time path runs
only when somebody connects and skips the target when nothing postern
knows about has changed; the lock loop reads postern's own records.
Neither sees a change made by hand on the machine. Set
`manage.sweep_interval` (unset by default, and it needs
`manage.propagate_accounts`) and postern walks the fleet on a timer — one
management connection per target, everyone on that machine reconciled in a
single pass. It puts back a sudoers file somebody deleted, and it takes
any account out of its own `postern-*` groups when nothing in postern
puts them there: that account was holding the sudo rule postern wrote for the
group while appearing in none of postern's records. Only the membership
goes; the account, its home and its other groups are untouched, and every
removal is written to the audit log. If one target would lose more than
ten memberships in a pass, none of them go and the reason is logged.
`postern-managed` and `postern-jit` are never enforced — they are what
permits a delete, and removing one by mistake would strand an account
postern created.

`manage.precreate_accounts` makes the same pass open accounts before
anybody connects. Off by default on purpose — the account exists where it
is used — and postern refuses to start if you set it without
`sweep_interval`. An account somebody decided should go is never reopened.

**Fixed: only the first person on a machine got an account.** The second
person's run tried to create the `postern-managed` group again, the target
refused because it already existed, and the whole preparation failed —
every time, with backoff, so it never recovered. Nobody hit this in a
release; it is fixed before the feature ships.

**A path rule can say `~`, meaning each person's own home.** A rule naming
one person's home is a rule for one person: a group allowing `/home/ayse`
sends every other member of that group to a refusal, which is what the
demo did. `postern group path set --group dev --prefix ~ --write` is one
rule that is right for all of them, and `~/.ssh --deny` still carves out
of it. The token is resolved per session from the home the **target**
reports — postern asks with `getent passwd` over the person's own
connection, no sudo, rather than assuming `/home/<name>`. If a rule uses
`~` and the home cannot be read, SFTP is refused for that session and says
why; the shell is untouched. Ignoring the rule instead would leave a
`~/.ssh` denial silently open.

**A session now records how it ended, and who ended it.** postern knew
both — an administrator cutting a live session, an idle timeout, the
maximum session length, a recording that could not be written — and wrote
them only to its log and the live event stream. Logs rotate and a stream
is gone once you look away, so the audit screen showed a session an admin
cut and a session the person exited as the same row. The Sessions list
marks a cut one, and the record says who did it.

Run `postern db migrate` before starting this version.

### Needs action if you call the API or use the CLI

**`role` is now `group` everywhere.** postern's own authorisation object —
the thing that holds targets and carries a sudo rule — is called a group,
because that is what it already is at both ends of the chain: a directory
group maps to it, and it becomes a Unix group on the host. Calling the
middle one a role gave the same thing three names.

What changed:

- `/api/admin/roles` → `/api/admin/groups`, including `/targets`, `/paths`
  and `/sudo` under it.
- The `roles` field on `/api/me` and on a user object → `groups`.
- The mapping endpoints now take `directory_group` and `group`, where they
  took `group` and `role`. That pair was the reason the rename could not
  be mechanical: both ends were already called a group in some places.
- The `role` command group is now `postern group …`. Under `postern user`,
  the `grant-role` and `revoke-role` subcommands are `grant-group` and
  `revoke-group`. The `--role` flag is `--group` everywhere, and
  `postern mapping add` takes `--directory-group X --group Y` where it took
  a `--group` and a `--role`.
- Audit actions are named `group.*` where they were `role.*`. Rows already
  in the ledger keep the action name they were written with — a filter on
  `role.grant` still finds the old ones, and nothing rewrites history.

Run `postern db migrate` before starting this version: the schema renames
the tables that carried the old word. **Nothing changes on a managed
host** — the sudoers file is named after the group's own name
(`/etc/sudoers.d/postern-dba`), never after the word for its type.

Three different things are now called a group, and the screens say which
is which: a **directory group** is what your IdP or LDAP sends, a
**group** is postern's object, and a **host group** is a Unix group that
already exists on a target.

### Fixed

- **A session's SFTP list hid the two columns an auditor reads.** A path
  is one unbroken run of characters, and the column holding it could not
  break anywhere: a single release path held that column open at 641
  pixels of the 958 a 1280-wide panel has, pushed the table to 1204, and
  put "Wrote" and "Result" — the bytes that actually crossed, and the
  reason a transfer was denied — behind a horizontal scrollbar. The path
  column now wraps the way the panel's other long-value columns already
  do, and the table fits without scrolling.

- **The LDAP screen could say every step was done and still refuse to use
  the directory, without saying why.** A configuration that reads groups
  from `memberOf` and has a leftover group filter is rejected — the filter
  has no `%s`, so it cannot be run — and postern keeps falling back to
  whatever the token carries. All four wizard steps showed a tick, the
  screen stayed in setup mode, and the one sentence explaining it was
  inside the last step, which nobody had a reason to open. The reason is
  now stated above the steps, the step holding the broken field is marked,
  and the wording says what it costs: stored, but not in use yet. Nothing
  is shown on a fresh install, where "nothing is stored" is the whole
  story and the first step already says it.

- **The LDAP fields were laid out for prose, not for what they hold.** The
  form was capped at a comfortable reading width, which is right for
  sentences and wrong for a bind DN: in a 960-pixel panel the inputs were
  544 wide, half the panel sat empty, and a real DN ran past the edge of
  the box. Fields now fill the panel, the short ones share a row, and each
  field's "stored / Clear" pair moved onto its label line instead of
  adding a fourth row under every one of the nine fields.

## 1.3.0 — 2026-09-16

### Security

- **A sudo rule edited through the panel in 1.2.0 could have been silently
  escalated to root.** The rule editor was a box of lines, and a command that
  ran as a non-root account carried that account as a `(postgres) ` prefix in
  front of it. Retyping such a line without the prefix sent the command as
  **root** — no warning, and in the direction that matters, from the screen
  whose whole job is to make a grant legible.

  **Are you affected:** only if you have a role whose sudo rule names a
  non-root account, and someone edited that rule in the panel. Check with

  ```bash
  postern role sudo show --role <role>
  ```

  and compare the "runs as" column against what you intended. The database is
  the source of truth; a host that postern has not touched since still has
  whatever it had.

  Each command is now edited on its own row, with its account as a separate
  field rather than text inside the command, so there is no prefix left to
  drop. The bulk editor is gone.

  **The same hole existed in the CLI** and is closed the same way.
  `postern role sudo set` replaces the whole rule and can only name one
  account for all of it, so writing from the terminal over a rule that gave
  a command to `postgres` moved that command to root without a word. It now
  stops, names the commands that would move and where they run today, and
  asks for `--run-as` if that really is what you mean — the emergency path
  stays open, its silence does not. `postern role sudo show` also prints
  each command's account, which it did not do when accounts became
  per-command.

### Added

- **The config file is readable from the panel, and the archive card moved
  there.** What a bastion is running with — where it listens, how long a
  session may idle, where recordings go — lived only in a file on the host,
  so answering "what is this thing configured to do" meant an SSH session
  and a `cat`. There is now a Configuration screen under Audit that shows
  those values read-only: the file's path, every setting grouped by area,
  and one line each on what it does. Nothing can be changed from it. That
  is deliberate — a panel session that could move the listen address, the
  recording destination or the trust chain would be a panel session that
  could redirect the audit trail.

  Two settings are named but never shown: the database connection string
  and the OIDC client secret. Their values do not reach the browser at all,
  and they are listed by name with the reason, since a setting that is
  simply absent reads as one nobody wrote. The screen works off an
  allow-list rather than dumping the config, and a test fails if a new
  config field is added without being classified as shown or withheld —
  otherwise the day someone adds `smtp.password`, the panel starts printing
  it and no one notices.

  The recording archive card — where the archive's key is rotated — sat at
  the bottom of the LDAP screen. Its own comment said it was shown
  independently of the identity source, but the screen it sat on meant an
  install using local accounts never saw it at all. It is on the
  Configuration screen now, next to the archive destination it belongs to.

- **A bell in the top bar lists everything waiting for an administrator.**
  Work that nobody is looking at piles up in three different screens:
  machines discovery found and nobody registered, people who signed in and
  are waiting for an account, and temporary accounts postern could not
  remove from a host. The bell carries the total wherever you are, and
  opening it shows each one with what it is, why it matters and how long it
  has been waiting — clicking a line goes to the screen that settles it.
  An earlier version jumped straight to the discovery screen, which made
  two thirds of the count invisible.

  The list is derived on every request rather than stored, so there is no
  "mark as read": a line disappears when the work is done. It also survives
  a broken source — if one of the three queries fails, its failure is one
  line in the list instead of silently shortening it, because a list that
  quietly drops a source reads as "nothing is waiting".

- **A role now has its own page, and the list only counts.** Every role's
  targets were drawn in its row, one chip per host, next to a target picker
  and two buttons that opened modals. At a hundred targets that row buries
  the table, and the table exists to answer which role reaches where. The
  list now shows the name, how many hosts the role reaches and how many
  sudo commands it hands out; the name opens a page with the targets in a
  searchable table, the sudo rule, the SFTP path rules and the delete
  button — the same shape a target already had. Searching still matches
  target names and sudo commands, so "which role reaches db-01" is still
  one box away even though the names are no longer printed in the row.

  On that page all three lists are tables with their own search, because
  each of them is the one that grows: a role can carry a hundred targets,
  a couple of hundred sudo commands and as many path rules, and a list you
  cannot search is a list you scroll past. Granting targets moved into a
  dialog with the multi-select the temporary-access wizard uses, so several
  hosts go in at once and an already-granted host is not offered again;
  sudo commands are added one at a time or edited in bulk, and removing the
  last one removes the rule, which is what the server does with a rule that
  has no commands left.

- **Each sudo command names the account it runs as.** A rule carried one
  account for all of its commands, so "test nginx as root, reload postgres
  as postgres" needed two rules — and on a target a group has one sudoers
  file, so the two would have had to be merged back into it. sudoers already
  writes this per command, and postern now does too: the file reads
  `%dba ALL=(root) NOPASSWD: /usr/sbin/nginx -t, (postgres) NOPASSWD:
  /usr/bin/pg_ctl reload`, with the commands in the order they were written
  rather than regrouped. The account is a column in the panel's table, a
  field beside the command when one is added, and a `(account)` prefix on
  the line when the rule is edited in bulk. An account that carries sudoers
  syntax is refused, because that value lands inside the parentheses and
  could comment out the rest of the file. A rule written before this keeps
  working: its commands inherit the rule's account.

- **A temporary grant can now name the account each sudo command runs as.**
  The wizard took commands as free text and the request carried no account
  field, so the only thing it could hand out was **root** — "reload
  postgres as postgres" was not expressible on the screen whose whole
  purpose is a narrow, short-lived grant. It is a table now, the same shape
  the role's rule uses: one row per command with its own "Runs as", a row
  that appears as the last one is filled, and a line underneath spelling out
  what will be granted, including that a blank account means root. The
  warning listing what the chosen roles already grant reads
  `command (as postgres)`; copying such a line into the old box sent `(as`
  and `postgres)` as arguments of a command granted to root, which is
  neither the command nor the account anyone meant.

### Changed

- **The top right is one control instead of five.** The bell, the theme
  switch, the name, the admin badge and a Sign out button sat side by side
  in the same weight, so nothing said which of them were buttons. Identity
  and the actions that belong to it are now a single menu; Profile moved
  into it, since it is the account rather than a place you work. The bell
  and the theme switch stayed outside: one carries a number that would be
  invisible inside a menu, the other is a three-state control whose state
  should be readable at a glance. On a phone the button drops to its icon
  and the name moves into the menu — at 390px the full name pushed the
  whole page sideways.

- **The acknowledgement for a risky sudo command is only asked when there is
  something to acknowledge.** The checkbox sat under every sudo form,
  whether or not the rule held anything risky, and its text talked about
  opening a root shell — which reads as a statement about running as root,
  and every command runs as root by default. So the box appeared to ask
  people to accept the obvious, and a box that always appears is a box
  nobody reads. It now appears only after the server refuses a rule for a
  command that can start another program, directly under the reason, and
  says what is actually being accepted: the role gets that account in full,
  not just the command written down. A refusal that acknowledging cannot
  fix — a wildcard, a relative path, ALL — shows no box, and the server
  says which kind of refusal it is rather than leaving the screen to guess
  from the wording.

- **The risky command in a sudo rule is marked on its own row.** A rule that
  had been accepted despite an escape risk carried one line under the table
  saying a command in it was a way out to a root shell. In a rule with six
  commands that names none of them, so the reader either suspects all of
  them or none. The command that can start another program now carries a red
  exclamation mark beside it, with the reason in its tooltip and in the text
  a screen reader gets, and the line under the table explains the mark
  rather than announcing an anonymous risk. Searching the table matches the
  reason too, so "which commands here are a way out" is one box away.

- **Powered-off machines are counted on the discovery screen, not listed.**
  A machine that is off has no host key to read, so it cannot be
  registered; in a cluster where most machines are off, those rows were
  most of the table and each carried the same sentence about the host key.
  The list now says how many are off and offers to show them; the sentence
  is not repeated on every row; and a machine with no address shows a dash
  rather than repeating its own name.

- **The registration wizard no longer asks for a role the machine already
  names.** The role its tag points at comes selected, as a chip that can be
  removed. It also stops listing that role twice in the summary when it was
  picked by hand as well — the server never granted it twice, the summary
  said so. The summary now shows the machine's platform tags beside it, so
  the tag the role came from is visible where the decision is made, and the
  labels step says what it will attach rather than leaving that to the
  final screen.

- **Labels in the registration wizard are a table, not a text box.** The box
  took one `key=value` per line, so its rules had to be learned before the
  first label: a line missing the equals sign was dropped without a word,
  and a line that looked like the placeholder was read as one. Keys and
  values are now two columns, an empty row appears as soon as the last one
  is filled — so there is no Add button to forget — and a row can be
  removed. A key the server would refuse is named with the reason while it
  is being typed, and the step will not advance until it is fixed, instead
  of failing at registration. The count under the table says how many labels
  each machine will carry.

- **Section labels are orange.** The uppercase labels that hold the panel
  together — ACCESS, INFRASTRUCTURE, AUDIT in the sidebar, ACCOUNT in the
  user menu — now carry the palette's orange rather than the muted grey
  they shared with body text. They have their own token: they are
  typographic, not functional, and the accent that marks buttons, links and
  the current tab is a different job. Both are measured against their own
  background rather than eyeballed, since the colour these labels had
  before this one sat below the readability threshold.

  The accent itself did not move to orange. Orange sits between the amber
  of a warning and the red of a danger state, and in the light theme a
  soft orange accent background is nearly the same colour as the one behind
  a destructive action. Three meanings need three colours more than a
  palette needs to be pretty.

### Fixed

- **Two colours were never applied at all.** `--bg` is not a token in this
  palette, and two rules asked for it: the notification count (so its text
  fell back to the bell's own muted colour — sage on sage, which is why the
  number could not be read) and the box that shows a freshly issued
  password (so it was drawn transparent). A CSS reference to a token that
  does not exist is not an error: the declaration is dropped and the
  element inherits. The stylesheet test now fails on any such reference,
  and the notification badge has its own token with its contrast measured
  rather than eyeballed.

- **The pills listing a user's roles are no longer lopsided.** They were
  padded for a remove button on their right — 0.5rem of room on the left,
  0.18rem on the right. That button moved to the role's own page when the
  roles list became a summary, so the padding was left describing a control
  that no longer exists and the text sat against the left edge of the pill.
  The padding is even now, the pill's height no longer depends on the line
  height of whatever table it sits in, and the rules for the button that is
  gone went with it.

## 1.2.0 — 2026-09-14

### Security

- **A postern username could forge lines in a target's sshd log.** A
  certificate's key ID is written verbatim into the target's log, and postern
  set it from the username without checking for control characters. A key ID
  of `evil\nAccepted publickey for root from 6.6.6.6` wrote a separate,
  genuine-looking root login line into a test target's log. The person who
  reads that log — usually the machine's owner — often cannot see postern's
  audit trail.

  postern's own code reached this in 1.1.0. Usernames are not checked for
  control characters anywhere, and an identity provider's
  `preferred_username`, which many providers let people edit, is copied as is
  into the pending queue; approving that account created a name every
  certificate carried into the log. Accounts created by an administrator could
  carry one too. Signing now refuses any key ID or principal with a control
  character, at the one point every certificate passes through. No advisory ID
  has been assigned.

  **Needs action if such an account exists:** it can no longer open sessions,
  by design — the alternative was to keep forging log lines. Find them with

  ```sql
  SELECT username FROM users WHERE username ~ '[[:cntrl:]]';
  ```

  and recreate them under a clean name.

  Such a name can also no longer be **written**. The refusal now sits in the
  store, beside the one that already guards target account names: every path
  that writes a username goes through it — an administrator creating an
  account from the panel or the CLI, `admin bootstrap`, the approval queue,
  an identity provider provisioning one at the panel or over SSH, and a
  directory account created on first sign-in. Putting the check at the call
  sites instead was tried and measured: the SSH sign-in path and
  `admin bootstrap` were left out, which are precisely the paths that end in
  a certificate. The rule is the same one signing uses, defined once and
  shared, because a write rule looser than the signing rule would create
  accounts that can be opened but never given a certificate. It also covers
  the C1 range, which the byte-level check at signing time does not see.

  A refused name is written to the server log, not to the admin log: the
  name is attacker-chosen text, and carrying it into the audit table is the
  thing being prevented.

### Needs action if you installed the binary by hand

- **The systemd unit now runs `/usr/bin/postern`, not `/usr/local/bin/postern`.**
  This release adds `.deb`, `.rpm` and `.apk` packages, and a packaged binary
  belongs in `/usr/bin` — Debian policy reserves `/usr/local` for the local
  administrator, so a package writing there would silently overwrite a binary
  you put there yourself. Rather than ship two unit files that would drift
  apart, there is one, and it points at the packaged path.

  If you installed from the tarball and copied the unit, either move the
  binary or leave the unit alone:

  ```bash
  sudo install -o root -g root -m 0755 /usr/local/bin/postern /usr/bin/postern
  sudo systemctl daemon-reload && sudo systemctl restart postern
  ```

  The failure is loud if you miss it — systemd refuses to start a unit whose
  `ExecStart` does not exist — but it is a restart away from being noticed, so
  it is here rather than in a footnote.

### Needs action if you rely on recordings as evidence

- **Recordings now carry a tamper-evident chain, and thirteen schema
  migrations land with this release (034–046).** Run `postern db migrate`
  before starting the new binary; the bastion refuses to start against a
  schema it does not match rather than writing audit rows into a shape it
  does not understand. Besides the chain, they carry the panel's path rules,
  the authenticator lockout, security keys, temporary access and what it
  cleans up, discovery sources and the machines they find, and the sudo rule
  a role carries.

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

- **A role can carry a sudo rule, and the people in it draw that rule from
  the group.** Until now a sudo rule could only be written per grant, into
  the account's own file on the target, so the same rule was retyped for
  every person and drifted between them. A role's rule is written once and
  lands on a target as `%<role> ALL=(runas) NOPASSWD: ...` in
  `/etc/sudoers.d/postern-<role>`; membership in the role's group is what
  grants it. What a grant adds on top still goes into the account's own
  file and leaves with the account, so a grant can widen a person's rights
  for four hours without widening the role's.

  Two consequences worth stating plainly. A role now grants sudo as well as
  reach, so adding someone to a role gives them more than it used to, and
  the screen says so. And the rule reaches a machine when postern next
  touches it — opening a temporary account there, for now — rather than
  being pushed to every target the role can reach.

  The marker group deliberately carries no rule: `postern-jit` holds every
  temporary account on the host, so a rule written there would hand one
  person's rights to all of them. A rule that `sudoers.Validate` reads as a
  way out to a root shell is refused at the point it is written rather than
  when it reaches a target, so a saved rule is one that can actually be
  applied; writing one anyway takes an explicit acceptance, which the audit
  line records. Migration 046 adds the table.

  Write it from the panel on the Roles screen, where the Sudo column shows
  what each role hands out, or with `postern role sudo set --role dba
  --command '/usr/bin/pg_ctl reload'`. Removing a rule removes it from
  postern; machines that already have the file keep it until postern next
  works on them, and both the panel and the command say so rather than
  reporting that the rights are gone.

- **The Ansible role that prepares a target is now covered by a test.** It
  had none: the role writes the CA, the principals files and the management
  account's sudo rule, and nothing checked that a change to it still
  produced a host postern can manage. The test starts a container, runs
  `ansible-playbook` against it for real (apply, not a dry run) and then
  reads the result off the host: the sudoers file at 0440 root:root, the
  principals files at 0644, their directory at 0755, and sshd's own answer
  for which principals file it will use for the management account. The
  role asks sshd that last question itself now, in the management
  account's context rather than globally, for the same reason the bastion
  does. A caller with no service manager — a container, a chroot, an image
  build — can turn the sshd reload off with `postern_reload_sshd=false`;
  it stays on and loud everywhere else, because a reload that silently
  does nothing leaves a host that looks configured and is not.

- **postern can manage the accounts on a target, not just broker access to
  them.** The Ansible role gained an opt-in management account
  (`postern_manage_host`, off by default): a `postern` system account that
  signs in with a certificate from postern's own CA — no key is stored on the
  target — and holds passwordless sudo.

  The sudo grant is deliberately broad and written **once**. A narrow grant
  would mean that every change to what postern does requires a playbook run
  across the whole fleet, which is a versioned component on every machine —
  an agent by another name. The narrowing happens on postern's side instead,
  where it can be changed by upgrading one binary.

  Two things had to be measured rather than assumed. The account's password
  field is `*`, not `!`: a locked account is refused by OpenSSH even with a
  valid certificate. And the role does not believe its own success — it runs
  `sudo -n -l -U postern` and fails unless sudo itself reports the grant,
  because `sudoers.d` is only read when the main file includes it.

  The role also asks sshd whether the principals file is in effect, and fails
  if it is not. That check exists because of a measurement: with
  `AuthorizedPrincipalsFile` absent, sshd looks for the login name among a
  certificate's principals, and a certificate with the principal `postern`
  opened the management account. On hosts whose sshd does not read
  `sshd_config.d` — Amazon Linux 2's OpenSSH 7.4 does not know `Include` at
  all, and RHEL 8's stock file has no Include line — the role now writes the
  two directives into `sshd_config` itself, at the top, where the first value
  wins. The Include repair that used to be there had never run: its probe
  matched `trustedusercakeys none`, and on 7.4 the line it would have written
  is refused by `sshd -t` anyway.

- **The panel can check whether postern can manage a target** — behind a new
  setting, `manage.enabled`, off by default. With it on, the target page has a
  **Management** card: postern signs a two-minute certificate in memory, signs
  in as `postern`, and reports which account and sudo tools the host has. It
  changes nothing. The attempt is written to the admin log *before* connecting,
  and postern does not connect if that write fails; the certificate's key ID
  names the administrator, so the target's own sshd log says who pressed the
  button. A refusal says where the check stopped and why — the target does not
  trust this CA (the card shows the fingerprint to compare), the host key
  changed, the host cannot be reached, the handshake did not finish, the host
  did not report whether the checks ran, or tools are missing — because each
  has a different fix. `postern serve` logs a warning at every startup while this
  is on.

  **No command gives a person a management certificate.** One was considered
  and rejected: signing has no lifetime ceiling and there is no revocation
  list, so such a certificate would be root on the fleet until it expired,
  with nothing recording what it was used for. The names `postern` and
  `postern-manage` are refused as a person's OS user when an account is
  created, modified, approved from the pending queue, or provisioned from an
  identity provider or a directory, and again by policy and by the ordinary
  connection.

- **Discovery from the panel: hypervisors as sources, machines as a
  queue, registration as a decision.** `postern discover` stays, but it
  is a command an operator runs by hand and it writes targets and role
  grants directly, after that operator has read the preview. A schedule
  has no reader, so the panel's version works differently. Under
  **Settings → Discovery** an administrator saves a *source* — a Proxmox
  cluster or a vCenter, with its address, a read-only API token or
  account (sealed with the bastion's secret key and never returned by
  the API), the tag key that names the role, an optional name pattern
  and node, the SSH port, and a schedule between five minutes and a week
  or "only when asked". postern runs each source on its schedule, or on
  **Run now**, and every run leaves a row: what it saw, how many
  machines were new, missing, unreachable, or answering with a different
  host key than the target they are linked to.

  What a run finds lands in a list of *machines*, keyed by the
  platform's own identity (`qemu/101`, `vsphere/vm-42`) rather than by
  name, so a VM renamed or migrated to another node stays one row. Each
  row carries the host key postern read from the machine and the role
  its tag names. Nothing becomes a target on its own: automation may
  grow the inventory, never the set of machines people can reach, and a
  hypervisor account that can create a VM with the right tag must not be
  a way to create a host that a role's members can sign in to. An
  administrator ticks machines and registers them through three steps —
  the roles to grant (existing ones, and optionally the one the tag
  names, created if missing), labels, and a summary that shows each
  machine's host key fingerprint — and only the last step writes: the
  target is created with exactly the key shown, granted to those roles,
  labelled, and every step goes to the admin log with the
  administrator's name.

  Three things a run never does: it never changes a registered target's
  host key (a machine answering with a different key is reported as a
  finding on its row and counted on the run, and the target is left
  untouched), it never deletes a machine the platform stopped reporting
  (the row is marked missing and any target keeps its session history),
  and it never treats an empty answer from the platform as "everything
  is gone" (an API token whose permissions were narrowed returns an
  empty list, not an error; such a run fails and marks nothing).
  Machines can be ignored, which also stops postern from scanning them.
  The source form has a **Test connection** button: it signs in with the
  values in the form (for a saved source, with the stored credentials
  when the secret field is left empty) and reports how many machines the
  platform lists, how many are running and have an address, how many
  match the name pattern and carry the tag key, and which roles the tags
  name — so a wrong tag key shows up before the source is saved, as "not
  one machine carries that key, the tags seen were …", rather than
  afterwards as a silent pile of untagged machines. A test writes
  nothing. A source's credentials need the bastion's `secret_key_file`;
  without it the screen says so and no source can be saved. Migration
  045 adds the three tables.

- **Temporary access: postern opens an account on a target for a fixed time
  and removes it when the time is up.** On a host with the management
  account, an administrator can grant one person an account on that host
  for between five minutes and thirty days, in named groups, optionally
  with a sudo rule written for that account alone. When the grant expires —
  or when an administrator ends it early — postern closes the person's open
  sessions on that host, kills what the account is still running, deletes
  the account and its home, removes its sudo rule, and reports what it left
  behind elsewhere on the machine rather than deleting it. Every grant and
  every revocation is in the admin log, before the target is touched.

  Three refusals are worth knowing about. A grant never takes over an
  account that already exists on the host: only accounts in the
  `postern-jit` group, which postern itself creates, are ever deleted, and
  an existing account of the same name stops the grant before anything is
  written. A grant that could only be half applied falls due at once, so
  the sweeper cleans it up on its next pass instead of leaving an unapproved
  account for the requested hours. And a revocation that cannot complete
  keeps its reason on the grant and is retried at growing intervals capped
  at an hour — the grant stays visible as *not revoked* until it is.

  `useradd -e` is written as a backstop for the day postern is not there:
  the host itself disables the account the day after the grant ends.

  In the panel this is its own **Temporary access** tab, shown to
  administrators when management is on. One dialog picks the person, one
  or more hosts, the groups and the duration; a grant is opened on each
  host in turn and each host answers on its own line, so two hosts that
  worked are not hidden behind a third that did not. Hosts and groups are
  searchable multi-select boxes — type to filter, the chosen entries sit
  in the box as tags, one click selects everything that matches — built
  in the panel's own code rather than pulled from a UI framework, because
  the panel ships none. Groups come from two
  places: postern's roles are always offered (a role's name becomes a
  group on the host, created if missing), and one button reads the groups
  of the selected hosts over the management connection — only the groups
  present on every selected host are offered, and no group below GID 1000
  ever is: `docker`, `wheel`, `shadow` and the rest are system groups, and
  membership in one is root without a sudo rule. The server refuses those
  regardless of what the panel sent. The list below the button covers
  every host, newest first; open grants can be ticked — all of a search's
  matches at once — and revoked together, each host answering on its own
  line, so a hundred hosts do not mean a hundred clicks and one host
  that cannot be reached does not hide the ninety-nine that were.

  The person who received the grant sees the host on their own home
  screen for as long as it lasts, marked *temporary until …*, and the
  host's page says who granted it and in which groups; the grant is also
  what lets them through the bastion — no role is needed for that host,
  and when the grant ends the host leaves their list. On the host itself
  the account is created with its principals file (from the pattern sshd
  reports, never a shared file), unlocked for certificate sign-in without
  ever having a password, and with a shell the host actually has; the
  integration test now signs in as the temporary account with a
  certificate and proves the door closes again after revocation.

  What a grant created, its revocation removes: a group postern had to
  create for the grant is deleted when the grant ends, provided nothing
  else uses it — no member left, no account with it as primary group —
  and never a group that existed before the grant or the `postern-jit`
  marker itself. The dialog has a box to keep such groups instead
  (`cleanup_groups`, default on). Every account postern creates,
  temporary or not, now gets its principals file when the host's sshd
  asks for one. And a session admitted by a grant rather than a role is
  marked *temporary* in the session list and in the session's header;
  the mark is written when the session opens, not derived later from
  what the grant table says. Migrations 043 (created groups, cleanup
  flag) and 044 (session mark).

  Migration 041 adds the grant table. The setting is the same
  `manage.enabled`; there is no second switch, because a bastion that can
  open temporary accounts but not close them would make "temporary" a lie.

  `POST /api/admin/targets/{name}/grants` creates a grant,
  `GET /api/admin/targets/{name}/grants` lists them,
  `POST /api/admin/grants/{id}/revoke` ends one early.

  The target page has the same three things as a **Temporary access** card:
  a form (person, groups, duration, optional sudo commands), the list of
  grants on that host with their state — active, expired and being revoked,
  not fully applied, or *revocation failing* with the reason — and a button
  to end one early.

  Deleting a user who still has an open temporary account is refused, with
  the count, until those accounts are gone: a record without an owner would
  leave "who is on this machine" unanswerable in the panel. Deleting with
  `revoke_grants=true` removes the accounts first, and stops — without
  deleting the user — if any of them cannot be removed.

- **postern refuses to manage a machine it does not understand.** A capability
  probe reports which tools a target actually has and names what is missing
  rather than guessing. On Alpine it finds busybox's `adduser` but no
  `usermod`, no `visudo` and no sudo, and reports the target as not
  manageable — a half-configured machine is worse than an untouched one,
  because the panel looks green and nobody looks again.

  `command -v` takes one name: dash prints only the first of several, busybox
  prints nothing. Both were measured; the probe uses a loop.

  A loop exits with the status of its last command, so on a host without
  `visudo` the whole check exits non-zero. That is treated as an answer: the
  tools found before the missing one are kept and named. A host that stops
  answering is reported as *not checked*, never as *not manageable* — the
  first version returned the second with no error, which is a verdict nobody
  measured.

- **Sudo rules are checked for what they mean, not just for whether they
  parse.** `visudo` says a file will not break sudo. It does not say the rule
  is narrow, and the difference is usually root:

  ```
  denetci ALL=(root) NOPASSWD: /usr/bin/find /var/log *
  ```

  That rule was written on a Debian 13 machine, `visudo` accepted it, and the
  account it was written for got `uid=0(root)` through `find -exec`. postern
  now refuses rules with wildcards, relative paths, `ALL`, negations,
  sudoers tags, or line breaks outright, and refuses known shell-escape
  binaries unless an operator explicitly acknowledges the risk — which is then
  recorded rather than silently assumed.

- **Propagation plans are computed before anything is touched.** Given what a
  target has and what it should have, postern produces an ordered, stable,
  idempotent list of steps; a second run produces none. A target that cannot
  be managed gets no steps at all rather than a partial application. Names
  that would become a second shell command are refused before they reach a
  command line, and sudo rule text is passed on stdin rather than interpolated
  into one. Sudo files are staged, checked with the target's own `visudo`, and
  only then installed — writing directly would let an invalid file take sudo
  away from everyone on that machine, postern's own account included.

- **Security keys for the panel (WebAuthn).** An account can register one or
  more hardware keys and use them as its second factor. The panel is postern's
  control plane, and a code is the part of it that can be phished: a page
  pretending to be your bastion can ask for the six digits and replay them
  within thirty seconds. A security key signs a challenge bound to the address
  it was asked for, so the same page gets nothing it can use.

  **While both are enabled, the account is as phishable as its code** — an
  attacker with the password simply asks for the code and never touches the
  key. The panel says exactly that rather than implying the key protects what
  it does not, and the account can switch codes off once a key is registered.

  Turning codes off cannot lock the account out by accident: it is refused
  unless a key is already registered, and removing the last key switches codes
  back on by itself. Losing every key is still an administrator reset from the
  host — `postern admin reset-webauthn` — because there are still no recovery
  codes, for the reason there never were: a second secret written down moves
  the protection onto that piece of paper.

  Registering and removing a key both need a fresh sign-in, the same gate the
  authenticator already used: a stolen session cookie must not be able to
  attach an attacker's key and take the account permanently.

  **If you registered a key against a build from `main` before 040, register
  it again.** The specification says a credential's "backup eligible" flag
  must never change, and postern now records it and checks every signature
  against it. Earlier builds did not record it, so the check ran against a
  blank value and every synced passkey — Touch ID, iCloud and Android keys —
  was refused at sign-in. Keys enrolled by those builds keep working: the
  first successful signature adopts the flag they report, and it is enforced
  from then on. Only an account that had already turned codes off is stuck,
  and `postern admin reset-webauthn --name <account>` on the host is the way
  back in.

  **This brings the panel to where SSH already was.** Hardware-backed SSH keys
  (`sk-ssh-ed25519`, `sk-ecdsa-sha2-nistp256`) have been accepted since 1.0;
  the browser side was the half that was missing.

  Two notes for operators. `http.external_url` must name a host, not an IP
  address — browsers accept `localhost` as a special case but not `127.0.0.1`,
  and postern refuses to start a ceremony rather than producing a key that
  will not work later. And if that setting is wrong on an account that has
  keys, sign-in fails loudly instead of quietly falling back to a code:
  weakening a second factor because a URL changed is not something that should
  happen silently.

- **One command brings up a working bastion.** `./scripts/quickstart.sh` builds
  the binary, generates its own CA, host key and master key, migrates the
  schema, starts two target machines that trust the CA, registers them by
  their real host keys, and seeds a user, a role and a path rule. It prints a
  panel link, an administrator password and the `ssh`/`sftp` commands to try.
  `--down` removes all of it, database volume included.

  The seeded role allows SFTP under the demo user's home and denies everything
  else **on purpose**: without a rule, nothing is ever refused, and the first
  ten minutes would show a bastion that records sessions without showing the
  part that makes the recording worth anything — the journal, the refusals and
  the counts the Evidence column reads.

  It is not production shape and says so:
  [deploy/quickstart](deploy/quickstart/README.md) lists what changes.

- **Linux packages: `.deb`, `.rpm` and `.apk`.** They install the binary and
  the systemd unit, create the `postern` system account, and make
  `/var/lib/postern/recordings` and `/etc/postern` with the ownership the unit
  expects. They do **not** start the service — postern needs a configuration, a
  CA key, a master key and a database first, so the package prints the five
  commands that come next instead of leaving a failed unit behind.

  Removing the package stops the service and leaves recordings, keys,
  configuration and the database untouched. Uninstalling a bastion is not the
  same as deleting its evidence, and a package manager is the wrong place to
  make that decision.

- **The session list says which sessions have something to look at.** Two
  counts now travel with every row and are drawn in an **Evidence** column:
  events postern could not write to the file journal, and requests postern
  refused. Until now a session in which `/etc/shadow` was refused looked
  exactly like a session in which nothing happened; the difference only
  appeared after opening the row and reading its file events. On a
  200-session list that is 200 clicks, which in practice means nobody looks.

  **The column never says a session is fine.** It draws at most one badge and
  has nothing to say about a clean row — the cell stays empty, and the note
  under the table says what empty does *not* mean. Whether the journal
  actually matches the recording is a question about the rows themselves;
  the server answers it when you open a session and press **Verify**, and
  putting a green tick in the list would be crediting a check nobody ran.

  A refusal is drawn as a plain badge, not a red one. Red is reserved in this
  panel for a contradiction — a recording that is sealed but does not match —
  and a refused request is also the rule *working*.

  **The count is refused requests, not journal rows, and it can be much
  larger than the number of rows you then see.** Consecutive identical
  refusals are folded into one row on purpose: a client pushing 300 MB at a
  path it may not write produces over ten thousand refusals in 32 KiB
  chunks, and a row each would exceed the journal ceiling and kill the
  session. Counting rows would have reported that session as *2 refused* —
  the most persistent session in the list carrying the smallest number,
  which is the opposite of what the column is for. The folded row says how
  many it stands for.

  **Sessions that closed before this release are not counted, and the field
  is absent rather than zero.** Zero would read as "nothing was refused here",
  which is a claim about the past that postern cannot make. The same
  distinction is already in the schema for `sftp_events` (037).

  Two columns left the table to make room: **OS user** and **Src**. Neither
  answers "which session should I open", both answer the question after it,
  and both are still there — in the header of the opened session, and in
  search, so an auditor typing an address still finds the row.

  **`postern session list` grew the same column.** It is the only list the
  auditor working on the bastion host has, and answering the same question
  differently depending on where you stand is worse than not answering it.

- **A target that stops answering no longer hangs the panel.** The browser's
  SFTP client had no deadline of any kind: a target that went silent left a
  listing or a transfer waiting forever, and the only way out was closing the
  Files window, which took the whole channel down with it.

  What is measured is **silence, not how long a request takes**. A download
  keeps sixteen requests in flight, so a per-request deadline would have killed
  slow-but-working transfers; the clock is reset by every reply instead, and
  only a target that says nothing at all for sixty seconds trips it. The
  handshake is covered too — a target that never sends its version left the
  panel on "Connecting…".

  A timeout does not close the channel. Silence can be a passing state of the
  target or the path between; marking the session dead would force the reopen
  this change exists to avoid. The outstanding requests fail with a sentence
  saying what happened, and the next request is sent normally.

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

- **An account can no longer be auto-provisioned under the name of the
  temporary-access marker group.** `postern-jit` is a group, and the sweeper
  recognises a temporary account by membership in it; a directory account
  carrying that name would sit inside the distinction. It joins the reserved
  names, beside the management account. An account of that name created
  before this release keeps working; only automatic provisioning refuses it.

- **The principals file postern writes is created with the mode postern
  chose.** It was written with a bare `tee`, which leaves the mode to the
  target's umask; the file says which certificate may open the account, and
  a root shell opened with `umask 000` would have left it world-writable.

- **The quickstart's demo machines are set up the way the Ansible role sets up
  a real target**, so *Check management access* can be tried from the panel
  right after `./scripts/quickstart.sh`. They now have per-account principals
  files and a `postern` management account. Their host keys are kept under
  `deploy/quickstart/.state/hostkeys`: the panel pins those keys, and the demo
  machines used to generate new ones at every start, so any change to their
  image would have broken every session with a host key mismatch.
  `./scripts/quickstart.sh --refresh` now rebuilds the demo machines too, and
  on a demo created before this change it first copies their current keys out
  of the running containers.

  The demo accounts were unlocked with busybox `passwd -u`, which left their
  password field empty — "no password required" rather than "no password".
  `su` is not setuid in that image, so it could not be used, but it was the
  opposite of what the image claimed. They use `*` now, like the management
  account.

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

- **A temporary account now gets its principals file where that host's sshd
  actually looks for it.** postern read `AuthorizedPrincipalsFile` from
  `sshd -T`, which reports the merged global configuration and ignores
  `Match` blocks. Measured on a demo target: with

  ```
  Match User jitayse
    AuthorizedPrincipalsFile /etc/ssh/jit_principals/%u
  ```

  in `sshd_config`, the plain read still answered
  `/etc/ssh/auth_principals/%u` while a read in the account's own context
  answered `/etc/ssh/jit_principals/%u`. postern wrote the file to the first
  path, so the grant reported success and the person could not open a
  session. Both granting and revoking now read the directive with
  `-C user=<account>`, and revoking therefore removes the file it wrote
  rather than leaving one behind for the next account of the same name. A
  target that cannot answer keeps today's behaviour instead of falling back
  to an empty path, which would have skipped writing the file at all.

- **A session cut short keeps its last bytes in the recording.** When a
  session was ended by postern rather than by the two sides hanging up
  — an administrator closing it, a temporary grant expiring, the
  bastion shutting down — the broker closed the channels and returned
  while its data pipes could still be mid-write: the last chunk read
  from the target had reached the client but not yet the recording,
  and the recording was closed underneath it. The window is a few
  microseconds; the CI runner hit it. The broker now waits for writes
  already in flight before it returns, and refuses writes that arrive
  after that, so what the client saw is on the tape or was never
  delivered — never delivered and unrecorded.

- **The sign-in value issued from the panel is shown again.** Since the
  server started calling it `password` (1.1.0's "call the credential a
  password"), the panel kept reading the old `secret` field, so
  **Reset sign-in** and **Add user** drew the box that says "this is the
  only time it is shown" — with nothing in it. The panel's own tests did
  not notice because they answered themselves with the old name. The
  server's test now reads the panel's type from `web/src/api.ts` and
  fails when a response key has no field there. The value's box also
  has its border back.

- **Panel tables no longer scroll sideways at laptop width just because
  one value is long.** Every table cell was set not to wrap, so a single
  55-character hostname, a JSON detail in the admin log or a deep file
  path pushed the whole table — and its action column — behind a
  horizontal scrollbar even on a 1280-pixel screen; measured, the admin
  log wanted 1727 pixels of 958. Cells now wrap; identifiers stay whole,
  and the columns that carry long single tokens (paths, details,
  hostnames, addresses) may break inside them. The role table's target
  picker no longer grows to the width of its longest option, cell padding
  is a little tighter, and the overview's six counters fit one row. The
  panel now writes every timestamp one way — `Sep 13, 12:12:00`, with the
  exact value in the tooltip — where the user list, user page, pending
  list, authenticator card, key lists, sync runs, group mappings, the
  target page and the security-key list each had their own (the browser's
  locale string, the raw ISO value, or its first ten characters); those
  two tables sit in the same scroll wrapper as every other table (on a phone
  they used to scroll the page itself), the authenticator-enrolment screen
  uses the ordinary page heading, and four CSS classes that had been
  written but never defined (`btn-ghost`, `btn-sm`, `data`, `pathrules`)
  are either defined or gone — the class check that used to tolerate them
  now tolerates nothing. An opened session's identity card sat directly
  in the card and lost its first letters to the card's clipping; it now
  has the card's padding and shows the person, target, start and end as
  well, the page scrolls to it when a session is opened, and its Close
  button moved out of the player into the page bar next to Refresh, where
  it closes everything the open session showed. A page-level visual harness
  (`web/test-node/pages.visual.test.tsx`) renders every screen with long,
  crowded data so this can be measured again.

- **Retention deletions were never written to the admin log.** The pruner
  has recorded every deletion it makes under `via = system` since it
  started doing so, and every one of those rows was refused by the
  `admin_log` check constraint, which listed every door a person can come
  through and not the bastion acting on its own. The panel's promise that
  "the admin log explains" a missing recording was therefore never kept.
  Migration 042 admits the value; the rows that were refused are gone and
  cannot be reconstructed. Found when the temporary-access sweeper, which
  also acts on its own, hit the same constraint.

- **A session the bastion is no longer streaming is no longer drawn as
  running.** The green *running* badge in the session list came from the
  session having no end time, and a session whose end postern never got to
  write — because it was killed — keeps that shape forever. The overview
  screen already had this right and called those sessions unattended; the
  audit table showed the same session as healthy. It now says **open, not
  streaming**, which is what the server has been reporting all along.

  `postern session list` and `session show` made the same claim from the same
  place and said `running` in the duration column. They cannot know: they are
  a separate process reading the database, and only the running bastion knows
  whether anything is still flowing. Both now say `open`.

  **Pre-flight.** Nothing was lost and there is nothing to repair — the
  badge was wrong, the rows were not. The sessions that will now carry the
  new wording are the ones whose end was never written, minus whatever is
  genuinely connected right now:

  ```sql
  SELECT id, started_at FROM sessions WHERE ended_at IS NULL ORDER BY started_at;
  ```

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

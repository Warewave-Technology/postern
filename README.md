# postern

> *A postern is the small, guarded side gate in a castle wall — not the main
> gate; the one a few people pass through, under watch.*

Certificate-based, session-recording SSH bastion in a single Go binary. A
deliberately minimal take on the Teleport idea: one protocol, one node, one
binary.

**Status: in development.** The proxy, certificate model, persistence, RBAC,
session recording, the admin panel, OIDC and LDAP sign-in, and directory-backed
identity are built and exercised against real OpenSSH, Keycloak and OpenLDAP.
The roadmap lives in
[postern-PLAN.md](postern-PLAN.md) (Turkish).

## What it does today

- Proxies SSH sessions and records them as
  [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/), replayable
  with `asciinema play`
- Reaches targets with **short-lived, per-session certificates**: an ephemeral
  key is minted per connection, signed by postern's CA for a single principal,
  and never written to disk. Users land on targets as *themselves* — real
  `loginuid`, clean audit trail — and no target holds a static key in
  `authorized_keys`
- Decides access from roles and refuses by default, recording the reason
- Pins every target's host key; `InsecureIgnoreHostKey` appears nowhere
- Relays only the session requests it can account for, and logs the rest
- Audits **file transfer per file** when SFTP is enabled: who opened what, how
  many bytes actually crossed, what was renamed or deleted, and what the target
  refused — without the transfer ever entering the terminal recording
- Lets people **manage their own keys** with a one-time code app, instead of
  queueing behind an administrator



### Watching a session back

Recordings were written from the first release and readable by nobody:
the audit file existed, the audit did not. The admin panel now replays
them.

Two things about how it is served. The path in `sessions.recording_path`
is a *database column*, and treating a database value as a filesystem
path would turn any future write into that column — an injection
elsewhere, a hand-edited row, a restored dump — into arbitrary file read
over an authenticated admin session, with `ca.key_file` the obvious
target. So the file is opened through the recordings store, which proves
the resolved path stays under the recordings root and refuses otherwise;
symlinks are resolved on both sides, which also stops a link planted
inside the root from pointing out of it.

And watching is itself audited, before a single byte is served: a
recording contains what someone else typed and saw. If the audit row
cannot be written, the recording is not served — a read nobody can trace
should not happen.

Playback replays into xterm.js rather than embedding asciinema-player.
That is a deliberate deviation from the plan, which called the player a
free win. It is not free: every 3.x release ships its terminal emulator
as inlined WebAssembly and calls `WebAssembly.instantiate`, which the
`script-src 'self'` policy blocks outright. Loading it would mean
relaxing the CSP of a bastion's admin panel to get a nicer scrubber.
xterm.js is already a dependency and interprets the same escape
sequences.

### What crosses the bridge

A session channel carries more than keystrokes, and postern forwards only
the request types it can account for. Anything else is refused and logged
— including types SSH gains after this was written, since the list is an
allowlist rather than a blocklist.

Refused today, and why:

| Request | Why not |
|---|---|
| `subsystem` other than `sftp` | postern can only audit a protocol it can read. Relaying a subsystem whose wire format is unknown would mean claiming an audit that does not exist. |
| `subsystem sftp`, unless `session.sftp` is on | Off by default so that upgrading does not hand an operator a new data-egress path they never asked for. When on, every file event is recorded (see below). |
| `x11-req` | Opens a second channel that bypasses the bastion. |
| `auth-agent-req@openssh.com` | Hands the user's private key to the target. A compromised target becomes a compromised key. |

`env` is relayed only for names on an allowlist, `LANG` and `LC_*` by
default. Variables like `PATH`, `LD_PRELOAD` and `BASH_ENV` change *what
runs* on the target, which is not something a bastion should carry:

```yaml
session:
  accept_env: ["LANG", "LC_*", "TZ"]
```

An empty list relays nothing; omitting the key keeps the default.

### Who you are, and how postern knows

An OIDC identity is joined to a postern account by `(iss, sub)`, not by
`preferred_username`. That distinction is the whole point: `sub` is
stable and never reassigned, while `preferred_username` is editable by
the user themselves in Keycloak, Auth0 and most brokered setups. Joining
on the name meant anyone who could set their username to `yigit.basalma`
inherited that account — its roles, its `os_user`, and its `is_admin`
flag, routing straight around the rule that only the host CLI grants
admin. It also happened with no attacker at all, the first time an
organisation recycled a departed employee's login name.

An account that is already bound to one identity refuses a second. An
account with no binding yet — one the CLI created — is claimed by the
first matching sign-in and that claim is written to the audit log, since
it is the one moment the door is open.

Browser login for SSH shows the verification code **in the browser** and
asks for it **in the terminal**. The obvious arrangement is the other way
round, and it was, and it did not work: the attacker starts the SSH
connection, so the attacker's own terminal prints the code, and sending
a victim "click this link and type ABCD-EFGH" was enough to get an SSH
session as them. Reversing it means the code exists only on the victim's
screen, so the attack now needs them to read it back — the ask people
actually notice. The page also names the source address of the waiting
connection and says postern will never ask for the code to be sent
anywhere.

### Two legs, two credentials

These get confused, so plainly: there are two SSH connections.

On the **inbound** leg a user proves who they are *to postern* — either
through the browser and your identity provider, or with their own public
key. On the **outbound** leg postern proves *to the target* that it may
open a session as that person, using a per-session certificate that is
minted, used and thrown away. The certificate is why no target holds a
static key; it says nothing about how the user reached postern.

So a user's `authorized_keys` entries are not redundant with
certificates. They are the other leg.

They are also the leg that does not consult your identity provider. An
account disabled in the IdP still has its key, which is why accounts
provisioned through SSO are marked `sso_only` and refused at the key
door outright. Keys therefore only work for accounts an operator created
deliberately — service accounts, automation, break-glass.

If a deployment has none of those, that door is open and unused:

```yaml
auth:
  # Default true. Set false only where browser sign-in is configured.
  public_key_login: false
```

With it off, postern does not *offer* publickey during the handshake at
all, rather than offering it and refusing — a client would otherwise burn
its auth attempts on keys that can never work. The panel stops managing
keys, and the API refuses to add one (removing stays allowed, so leftover
keys can still be cleaned up). Turning it off with no browser login
configured is refused at startup: that combination locks everybody out.

### Keeping authorization fresh

Group membership was resolved only at login, so a user deleted in the
directory kept their roles until they next tried to sign in — which,
having been deleted, they never would. `sync.enabled` turns on a
background pass that re-resolves them.

This is the most dangerous feature in the codebase, because the naive
version of it is catastrophic. `Groups` returns an empty list both for
"this person is not in the directory" and for a directory that answers
badly, and a loop that treats an empty list as "revoke" will, during an
LDAP outage, revoke everyone in the company. So:

- The directory answers a **three-valued** question. Only a search the
  server answered successfully with zero entries counts as *absent*.
  A bind failure, any LDAP result code — including `32 NoSuchObject`
  from a mistyped base DN, which would otherwise make every user look
  deleted — and an ambiguous multi-entry result all count as *unknown*,
  and unknown users are never touched.
- Before touching anything, a run **probes** the directory: a directory
  returning no users at all is an outage or a restore in progress, never
  a company where everyone left.
- A **blast-radius ceiling** aborts the whole run rather than applying
  it. Users who are absent and users who are present but suddenly map to
  no roles are counted *together*, because a half-restored directory
  produces the second, not the first — a guard watching only absences
  would happily empty the company.
- A **grace window** means a user must be missing across runs, not once.
- Manually granted roles survive, and the report lists those users
  separately: reading "revoked" and assuming access is gone would be the
  easy mistake.

Runs are recorded. An abort nobody sees is the same failure as no sync
at all — the operator believes revocation is happening while the
directory has been unreachable for a week — so `postern sync status`
leads with the last successful run.

```bash
postern sync run --dry-run --config postern.yaml
```

Triggering a run is deliberately CLI-only. A panel button that starts a
mass revocation is a lever a stolen admin session should not have, and
the timer covers the legitimate case. Scope is `sso_only` users only, so
service accounts and CI users are never revoked; `postern user modify
--sso-only=true` opts someone in.

An OIDC-claim-only deployment cannot be synchronised at all — a claim
arrives only when someone logs in, so there is nothing to ask. `sync`
requires a directory and says so at startup rather than pretending.

Sync is a directory feature, so it is configured on the panel's **LDAP**
page, next to the directory it reads: enabled, dry run, the interval and
every blast-radius ceiling. The `sync:` block in the config file is still
read and still works — it is the **default** for anything the panel has
not overridden, so an existing deployment loses nothing on upgrade — and
the panel shows, per setting, whether the value came from the file or
from the panel.

Runtime beats a restart here for one setting in particular. Dry run
exists to watch a loop that revokes access before letting it write, and
"edit a file and restart the bastion" is the wrong cost for the switch
you reach for when something looks wrong. The loop re-reads its settings
every few seconds, independently of the sync interval — turning it on at
a 15-minute interval must not mean fifteen minutes of wondering whether
it worked.

A stored value that cannot be parsed does not fall back to the default:
the run is skipped and the reason is logged. `max_revoke_per_run: 2O`
with a letter O, silently becoming 25 again, would mean a ceiling running
at a number nobody chose — in a loop that takes access away, that is the
worst place to be quietly wrong.

### Closing a live session

An administrator can close a session this bastion is carrying, from the
panel's Active-sessions card. It cancels the session: the connection to
the target is dropped, the person is shown one line saying who closed
it, that same line goes into the recording so a later reviewer is not
left with a transcript that just stops, in-flight SFTP transfers are
recorded as interrupted with the bytes that crossed, and the audit row
is finalised.

Who pressed it is written to `admin_log` **before** anything is closed.
If that write fails, nothing is closed and the operator is told — an
administrator who can end sessions without leaving a trace is not an
administrator this design allows.

**Closing is not revoking.** Roles and account state are read at connect
time; closing touches neither, so the person can reconnect immediately.
The card says so, and the confirmation deliberately names no remedy:
deactivating an account does not reliably help either, because all four
sign-in paths call `ConfirmAccount` and that flips `inactive` back to
`active`.

An open row is not proof of a running session. `ended_at` being empty
means "we never recorded an end" — which is also what a crash leaves
behind. Startup closes those leftovers and logs how many, since their
recorded duration reads longer than the real one, and the panel offers
Close only where the process confirms traffic is flowing. None of this
crosses processes: a second postern on the same database is not asked,
and the endpoint answers "not running on this instance" rather than
claiming success.

### Changing someone's roles

```bash
postern role list --config postern.yaml
postern user grant-role  --name suleyman --role ops --config postern.yaml
postern user revoke-role --name suleyman --role ops --config postern.yaml
postern role revoke-target --name ops --target web-01 --config postern.yaml
```

These exist because the CLI is the path that has to work when the panel
does not, and until now it could only set roles while creating an
account.

Three things the commands say out loud, because each is a way an
operator would otherwise be misled:

- Revoking a role the user never held reports *held no active grant*,
  not *revoked*. A mistyped role name should not read as success.
- Revoking a role that came from a directory group lasts until that
  person's next sign-in — `SyncRoles` rewrites the IdP's list on every
  SSO login. Removing the group mapping is what makes it stick.
- Granting a role they **already have from a directory group** converts
  it to a manual grant, and synchronisation can no longer take it away:
  the role survives them leaving the group. The command is not blocked —
  break-glass must never lock you out — but it says so.

Granting a role to a deleted account is allowed: restoring roles before
reactivating is a legitimate order, and `postern user state` exists so no
state is a dead end. The command says the account cannot sign in yet.

### Registering a target

A target is pinned to its host key, so registering one means deciding
which key is the right key. The panel can fetch it: **Fetch host key**
reads what the machine offers at that address right now, shows the
SHA256 fingerprint, and will not let the form be submitted until the
fingerprint is explicitly confirmed.

That is trust on first use and the screen says so. It is not weaker than
pasting: an operator running `ssh-keyscan` was almost always running it
over the same network. What it removes is the typo and the temptation to
leave the field for later. What it cannot do is verify — compare the
fingerprint against the host's own `ssh-keygen -lf`, from the console or
from whatever built the machine.

If another target is already registered at the same address with a
different key, the scan says so. That is either a rebuilt host or not
the machine you think it is, and both are worth stopping for.

### Knowing what a target is

postern records what a target says while connecting: the SSH banner it
offers unprompted (`SSH-2.0-OpenSSH_9.6p1 Debian-3`, the most reliable
single hint at distribution and patch level), the pinned key's type, how
long the handshake took, when it last worked, and — separately — when and
why it last failed. None of this touches the machine: it all falls out of
the handshake, and the target page says so.

That is the default and it is deliberate. Reading `uname` or
`/etc/os-release` would say much more, and it would mean running commands
on a machine outside anyone's session — which is the line a bastion
should not cross on its own.

Some organisations are happy to cross it on their own hosts. For them:

```yaml
# ⚠️ DEFAULT OFF. Switching this on changes what postern does on your
# machines. Read the whole block before enabling it.
target_probe:
  enabled: true
  refresh: 24h   # how long before the same host is asked again
  timeout: 5s    # ceiling for the whole probe
```

With it on, postern opens an extra exec channel **on the connecting
user's own connection** and runs a fixed, read-only command set —
`uname -srm` and `cat /etc/os-release`. Three consequences, stated
plainly because they are the reason this is off by default:

- The commands run **as the user who connected**, so they appear in that
  target's own logs under that person's account. They did not type them.
- Every run is written to the admin log with `via = probe`, naming the
  user, the target and the commands. "Which machines has postern touched"
  has to be answerable with one filter.
- The **command list is not configurable**. Anyone who can edit the
  config would otherwise have remote command execution on every machine
  under audit — the bastion would become the thing it exists to prevent.
  The list lives in `upstream.ProbeCommands`, in the source, reviewable.

A session never waits for a probe: it runs in the background, bounded by
`timeout`, and a failure is logged and dropped. The result appears on the
target's page under **Identified**, kept apart from the handshake facts
so it is always clear which answers cost a command and which did not.

`postern serve` logs a warning at every startup while this is on.

### Sending recordings off the bastion

Until now the audit trail lived only on the machine being audited:
whoever took the bastion took the recordings, a retention obligation
longer than the disk had no answer, and backup was left to the operator.

```yaml
recording:
  dir: /var/lib/postern/recordings
  retain: 90d
  archive:
    endpoint: https://minio.internal:9000   # empty = archiving is off
    bucket: postern-recordings
    region: us-east-1
    prefix: postern/production
    ca_file: /etc/postern/minio-ca.pem      # for a private root
    access_key_id: AKIA...
    secret_key_file: /etc/postern/archive.key   # 0600, or POSTERN_ARCHIVE_SECRET_KEY
```

**The network is never on the session path.** Recordings are written
locally exactly as before; a separate loop uploads them afterwards. An
object-store outage therefore cannot refuse a session — postern is not
chained to a provider's uptime. What an outage *does* cost is pruning:
a recording that is not safely elsewhere is never deleted, so a long
outage fills the disk and `min_free` starts refusing sessions. That is
the correct trade and the pruner logs the backlog long before it bites.

**The order is upload, verify, mark, then permit deletion.** A 200 from
PUT is not proof; postern asks the store itself with a HEAD before
writing `archived_at`, and only that timestamp lets the pruner delete
the local copy. Anything else keeps the file.

**Write-only, deliberately.** The panel shows the bucket and key for an
archived recording and does not fetch it. Holding a read credential on
the bastion would turn one compromise into exfiltration of the entire
archive; an auditor fetches the object with their own credentials.

⚠️ **`PutObject` without `DeleteObject` is not append-only** — a PUT to
an existing key overwrites it. If the archive has to survive someone who
owns the bastion, that comes from the bucket: versioning enabled, Object
Lock in compliance mode with a default retention period, and an identity
with neither delete nor lock-configuration rights. postern deliberately
sends no Object Lock headers, because an attacker holding the credential
could set the retention to zero. postern cannot verify any of this and
does not claim to.

No AWS SDK: the signing is ~250 lines of standard library pinned to
AWS's own SigV4 test vectors, so postern works with any S3-compatible
store and carries no vendor dependency. Single PUT only — measured, a
recording is about the size of the terminal output it captured, so the
5 GB limit is not reachable by realistic sessions; one that exceeds it
is kept locally and reported rather than silently dropped.

### Limits

Nothing bounded the listener until recently: it accepted in an unbounded
loop, and the SSH version string is read one byte at a time with no
deadline — so a client sending a byte an hour held a goroutine and a file
descriptor without ever authenticating. Worse, when file descriptors ran
out, `Accept` returned an error that propagated all the way out and
stopped the process. Exhaustion caused an outage rather than backpressure.

Every limit defaults to something usable; `0` means "use the default" and
`-1` means "deliberately unlimited".

```yaml
listen:
  max_conns: 256              # concurrent connections
  max_conns_per_ip: 8         # concurrent connections from one source
  handshake_timeout: 30s      # time to authenticate
  max_auth_tries: 4           # auth attempts per connection
  max_channels_per_conn: 10   # concurrent sessions on one connection
  max_pending_logins: 32      # browser logins awaiting approval

session:
  idle_timeout: 30m           # off by default
  max_lifetime: 12h           # off by default
```

**What these do not do.** They do not stop a distributed attacker. A
per-IP cap means nothing to a botnet, and once the global cap is reached
you are refusing legitimate users too. What they buy you is degradation
instead of an outage.

**`max_conns_per_ip` behind a proxy.** postern does not speak the PROXY
protocol, so behind an L4 load balancer every connection appears to come
from the balancer and this limit collapses everyone onto one counter —
your ninth user is refused. Set it to `-1` in that deployment. The
refusal is logged with the address and the count so the cause is one grep
away.

**`max_auth_tries` and your ssh agent.** OpenSSH offers every key in the
agent before the right one, so a developer with five keys hits the limit
at four. This is the same tension OpenSSH resolves with its own default
of 6; the fix on the client side is `IdentitiesOnly=yes`.

**LDAP group scope.** `group_base` is required, and it applies to the
`memberOf` path as well as the group-search path. Without it, group
identity collapses to a bare CN matched across the whole directory:
anyone who can create a group anywhere the bind account can see —
self-service group creation, a delegated OU, a contractor subtree,
another domain in the forest — could name it after a mapped role and
receive it. Plain `ldap://` is refused off loopback, and the check is a
scheme allowlist: it used to match the lowercase prefix only, so
`LDAP://` sent the bind password over the wire in cleartext.

**SSH transport.** Key exchanges, ciphers and MACs are pinned explicitly
in both directions. x/crypto's defaults are chosen for compatibility and
include `diffie-hellman-group14-sha1` and `hmac-sha1`; a bastion's
transport is tuned to protect traffic to every machine behind it, not to
accommodate clients that have not moved on.

**Browser login outlives the handshake timeout.** Approval is awaited
*inside* the handshake, so a flat deadline shorter than the approval
window would break every OIDC login — as a mid-login disconnect that
looks like a network fault. The deadline is extended once the client
selects the interactive method, which keeps the anonymous path cheap.
`TestOOBLoginSurvivesShortHandshakeTimeout` runs a real Keycloak login
with a 6s handshake deadline and a 60s approval window; removing the
extension makes it fail.

**`session.idle_timeout` is off by default, on purpose.** Idle means *no
bytes in either direction*, not "nobody is typing" — otherwise an
hour-long `make -j` that prints nothing gets killed mid-build. It is also
not crash detection; TCP keepalive already notices a dead peer in about
two and a half minutes. Its real justification is the root shell someone
forgot on a production box. `max_lifetime` exists because time-limited
role grants are never re-checked mid-session, so a session opened a
minute before a grant expires currently outlives its own authorization.

This was not a theoretical gap. Before the filter existed, `sftp` worked
end to end through postern, and the transfer landed in the `.cast` file
as binary SFTP protocol under an `80x24` header that no terminal ever
had.

### File transfer, and what makes it auditable

`sftp` is relayed when `session.sftp` is on, and only then:

```yaml
session:
  sftp: true                  # off by default
```

postern does not put an SFTP server in the middle. Bytes reach the target
unchanged; a copy is decoded on the way past, and what comes out is a
file-level record — one row per open, transfer, rename, delete and
permission change, written to `session_files` and shown under the session
in the panel.

Three details decide whether that record is worth anything:

- **Events are written from the reply, not the request.** A delete that
  came back "permission denied" is recorded as a denied delete. Recording
  the request would tell an investigator a file was gone when it is still
  there.
- **Byte counts are what crossed, not what was asked for.** A read that
  requests 4 KB and receives 100 bytes at end-of-file counts 100.
- **Failed operations are kept.** "Nobody tried" and "they tried and were
  refused" are different findings, and only one of them means the target
  is configured correctly.

If the stream cannot be decoded, or the events cannot be written, the
session ends. That is the same rule recording already follows: a channel
that cannot be audited does not get to carry data. The raw transfer never
enters the terminal recording — that shape is what kept the channel shut
in the first place.

### Large Active Directory groups

AD stops sending `member` once a group passes about 1500 entries, and sends
`member;range=0-1499` instead. A client that only reads `member` sees such a
group as *empty*.

That mattered here more than it looks. The member list feeds the admin-group
confirmation screen — the one that says "these people will become
administrators" before you agree to it. Unhandled, it showed the largest and
therefore most dangerous groups as having nobody in them, and an administrator
would approve a grant that then landed on several thousand people at their next
sign-in. postern now follows the ranges, stopping once it has enough for the
preview and saying so rather than trimming quietly.

Real OpenLDAP cannot produce that reply, so no integration test could have
caught it. `internal/ldap/ldaptest` is a small LDAP server that can — it also
produces the referral that AD returns for a wrong base DN, which is the other
answer that reads as "no such user" if you take it at face value.

### Adding a second key without asking anyone

Adding a *further* SSH key is exactly the move someone makes to keep access
after taking over an account, so postern re-checks who you are first. It could
only ever check a local password — which directory-backed and OIDC accounts do
not have. In the deployments postern is actually built for, that made "ask an
administrator" the answer for everyone.

An authenticator app closes that. Enrol one from your own page, and a code
authorises adding a key.

Two things about it are deliberate:

- **Enrolling is not a way around the check.** If any session could enrol,
  someone with a stolen session would enrol first and add a key second — with
  the account now *looking* better protected. So enrolling asks for the same
  proof adding a key does: the local password if the account has one, and
  otherwise a sign-in from the last ten minutes. A stolen long-lived session
  cannot produce that.
- **A code is spent when it is used.** The same code stays valid for 30
  seconds, and in this context using it twice means adding a second key. The
  step is consumed in one compare-and-set, so two requests carrying the same
  code cannot both win — measured under a 16-way race, not assumed. Confirming
  the enrolment spends a code too, so the next key needs the next code.

The setup key is shown as a QR code and as text. The encoder is ours
(`internal/qr`), and the reason it is trustworthy is not that it looks right:
its output is compared module for module against Apple CoreImage's encoder
across all 40 versions and all four correction levels. A hand-written QR
encoder's likely failure is not an unreadable code but a *scannable and wrong*
one, which surfaces days later as "my codes never work" — with the person
locked out of their own account. Goldens generated from our own output would
have caught none of that; a wrong encoder agrees with itself perfectly.

**Enrolling one takes over the check.** An account that had a password and then
enrols an authenticator is asked for a code from that point on, not the
password. That is the point of enrolling — otherwise the password would still
be enough on its own and the authenticator would protect nothing. It does mean
losing the phone means losing this ability until it is reset.

There are no recovery codes, on purpose: a second secret for you to write down
moves the security of the account onto that piece of paper. Lost your phone? An
administrator resets the authenticator, and the reset is in the admin log.

The codes themselves are RFC 6238, checked against the RFC's own published
vectors — so what postern computes is what your phone computes, not merely what
postern's own tests expect.

## Setting up

Generate the certificate authority:

```bash
postern ca init --key ca_ed25519
```

That prints the CA's public key. On **every target**, trust it and say which
principal may use which account:

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/postern_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

```bash
# /etc/ssh/auth_principals/yigit
yigit
```

`test/integration/testdata/certtarget/Dockerfile` is the same setup as a
runnable file, and is what the certificate tests run against.
[`deploy/ansible/`](deploy/) does it across a fleet, and refuses to install
a configuration `sshd -t` rejects — an invalid `sshd_config` takes the host
away at its next restart, and you cannot SSH in to fix it.
[`deploy/systemd/`](deploy/) runs the bastion itself.

postern keeps users, roles, targets and the session audit trail in
PostgreSQL. Create a database and a role for it:

```sql
CREATE ROLE postern LOGIN PASSWORD 'choose-one';
CREATE DATABASE postern OWNER postern;
```

Put the connection string in the config (see `testdata/valid.yaml`), or
keep the password out of the file with `POSTERN_DATABASE_DSN` — it
overrides `database.dsn` when set. If the string names no `sslmode`,
postern uses `verify-full`: libpq's own default silently falls back to
plaintext when TLS is unavailable, which is not a trade a bastion should
make on your behalf.

Create the schema, then start the server:

```bash
postern db migrate --config postern.yaml
```

```bash
postern serve --config postern.yaml
```

`db migrate` takes a PostgreSQL advisory lock, so running it from two
places at once is safe: the second waits and then finds nothing to do.

### The panel, and the proxy in front of it

postern serves the panel over **plain HTTP**. There is no
`ListenAndServeTLS` and no certificate field: terminating TLS is a
reverse proxy's job, or you bind `addr` to localhost and reach it through
an SSH tunnel.

```yaml
http:
  addr: "127.0.0.1:8088"
  external_url: "https://bastion.example.com"
  trusted_proxies: ["10.0.0.9"]
  terminal_enabled: false
```

`external_url` is not decorative and cannot be derived from `addr`:
sign-in links and the OIDC `redirect_url` are built from it, and a
bastion behind NAT has no idea what `:8088` means outside. Its scheme
also decides whether the session cookie carries `Secure`.

`trusted_proxies` is what makes the sign-in rate limit survive that
proxy. Attempts are counted per *(account, source address)* so an
attacker can only slow themselves down — but behind a proxy every
request arrives from the proxy's address, the pair collapses onto the
account, and an unauthenticated stranger can hold your administrator at
the door indefinitely with one request every five minutes. (`admin` is
the default name from `postern admin bootstrap`, so nothing has to be
guessed.) List the addresses the proxy actually connects from; only for
those is `X-Forwarded-For` read, and the chain is walked from the right
so a client cannot claim someone else's bucket by prepending an address.
Empty — the default — means the header is never read, which is correct
for a directly exposed bastion. A malformed entry stops startup rather
than leaving you believing you configured something you did not.

`terminal_enabled` is **off by default** and that is a security
decision, not an oversight: the browser terminal turns any XSS in the
panel into command execution on your targets, where the same XSS could
otherwise only reach the API. An installation that does not need it
should not carry the surface.

## Development

```bash
make build          # → bin/postern
make test           # unit tests; needs Docker (see below)
make test-race      # the one that catches the interesting bugs
make test-integration   # against real OpenSSH containers; needs Docker
make lint vet
make audit          # gosec + govulncheck
make ci             # everything CI runs, in the same order
```

`make ci` is what `.github/workflows/ci.yml` runs, so a green run locally
means a green run there. CI additionally re-runs `govulncheck` weekly:
its input changes without the code changing, and a vulnerability
published on a quiet Tuesday should not wait for the next commit.

`make sec` excludes gosec's G104 (unhandled errors), because all 22 hits
are `Close()`/`Reject()` in cleanup paths where there is nothing to do
with the error. Every other rule stays on, and the remaining false
positives are marked in the code one at a time with `#nosec <rule> --
reason` — so a genuine finding tomorrow is not silenced by yesterday's
blanket.

`make web-test` runs the panel's own tests (vitest + jsdom). They pin the
things that were quietly wrong rather than merely ugly: that a loading
list is not rendered as an empty one, that a failed delete cannot render
a blank error and pass for a success, that a 403 does not reload the page
into a loop, and that a 500 during sign-in shows "postern is unreachable"
instead of sending you back to the identity provider that cannot help.

`make fuzz` runs the fuzz campaign — 15 targets, one invocation each,
since `-fuzz` takes exactly one target and one package. It is not in
`make ci`: the seed corpora already run as ordinary tests on every
`go test`, so `make test-race` exercises every target under the race
detector, and a timed nondeterministic job on a PR gate only teaches
people to ignore red. The campaign runs weekly in CI alongside
`govulncheck`.

Each target asserts a property, not the absence of a panic — differential
agreement with a reference parser, losslessness, chunk invariance,
accept-set containment. "It didn't crash" would have found none of the
five defects these turned up.

The Go version lives in `go.mod` and CI reads it from there. Keep it
current: six of the seven vulnerabilities `govulncheck` first reported
here were standard-library issues, fixed by moving from 1.26.5 to
1.26.6.

**The unit tests need Docker too.** Anything touching the store runs
against a real PostgreSQL started by testcontainers — one container per
test binary, a separate schema per test. Testing the store against a fake
would be testing the wrong thing: the bugs worth catching there (conflict
targets, constraint violation codes, case-insensitive indexes) only show
up on a real server. Without Docker those tests fail rather than skip, so
that a green run always means the store was actually exercised. Use
`go test -short ./...` to skip them deliberately.

The integration tests build their own targets and generate their own keys —
nothing under `testdata/keys/` is committed, so regenerate host and CA keys
after a fresh clone.

### Troubleshooting

**`no route to host` when connecting to a LAN target, while `ssh` to the same
host works.** On macOS 15 and later, reaching a local-network address requires
the Local Network permission, granted to the application that launched the
process. Apple-signed binaries like `/usr/bin/ssh` are exempt, a locally built
one is not — and the kernel reports the refusal as `EHOSTUNREACH`, which Go
surfaces as "no route to host". Enable the terminal or editor under System
Settings → Privacy & Security → Local Network, then fully quit and reopen it;
permission state is read at process start.

**A certificate is refused and the reason is unclear.** Ask the target rather
than guessing — `journalctl -u sshd` with `LogLevel VERBOSE` names the cause
directly ("account is locked", "principal not in list", and so on).

**Nobody can sign in after configuring LDAP.** A directory that cannot be
reached is not the same as a user with no groups, so postern refuses the login
rather than admitting someone with nothing. That is the right call for SSH and
it applies to the panel too — which means a wrong URL or an unreachable
directory locks out the person who has to fix it. The reason is in the server
log (`group lookup failed`, with the underlying error); the browser only says
"login failed", deliberately, since that page is unauthenticated.

Recover from the host:

```bash
postern settings set --key ldap.url --value ""
```

Then **restart postern**. Clearing the setting alone is not enough: the running
process holds the directory source in memory and only rebuilds it when the
panel writes a setting — which is exactly what you cannot reach. Group
membership falls back to the IdP claim on the next start.

**The connection test says `no such host` for a name that works on my
machine.** postern dials from the bastion, not from your browser — the test
runs on the server and the name is resolved there. Container names, split-horizon
DNS and VPN-only names commonly resolve on a laptop and not on the host running
postern. Use a name the bastion can resolve, or an address. The same is true of
the host key scan when registering a target.

## License

Apache-2.0 — see [LICENSE](LICENSE).

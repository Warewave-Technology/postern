# postern

> *A postern is the small, guarded side gate in a castle wall — not the main
> gate; the one a few people pass through, under watch.*

Certificate-based, session-recording SSH bastion in a single Go binary. A
deliberately minimal take on the Teleport idea: one protocol, one node, one
binary.

**Status: in development.** Stages S1 (SSH proxy core) and S2 (certificate
model) are done and exercised against real OpenSSH servers; OIDC, persistence
and RBAC storage (S3) are next. Not production-ready. The roadmap lives in
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

Still ahead: TOTP and an SFTP relay.

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
| `subsystem` (`sftp`, `scp`) | Transfers would be recorded as raw protocol bytes in a terminal recording: unplayable, and no answer to "who took which file". The SFTP relay is a planned feature that needs per-file audit, not a side effect. |
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

## License

Apache-2.0 — see [LICENSE](LICENSE).

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

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

Still ahead: OIDC login, TOTP, SQLite-backed users and sessions, a web
terminal, SFTP relay.

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

Then point a config at it (see `testdata/valid.yaml`) and run:

```bash
postern serve --config postern.yaml
```

## Development

```bash
make build          # → bin/postern
make test           # unit tests
make test-race      # the one that catches the interesting bugs
make test-integration   # against real OpenSSH containers; needs Docker
make vet
```

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

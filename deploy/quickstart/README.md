# Quickstart

One command brings up a bastion, a PostgreSQL, and two target machines
that trust its certificate authority:

```bash
./scripts/quickstart.sh
```

It prints a panel URL, an administrator password, and the two commands
that open a recorded SSH session and an SFTP transfer. Everything it
creates lives under `deploy/quickstart/.state` and in one Docker volume;
`./scripts/quickstart.sh --down` removes all of it.

## What it sets up

| | |
| --- | --- |
| `demo-a`, `demo-b` | Alpine containers running `sshd`, trusting the CA. No `authorized_keys` file, no passwords — a postern certificate is the only way in. |
| `ayse` | A user with the `developer` role, landing on the targets as `ayse`. |
| `developer` | Reaches both machines. SFTP is allowed under `/home/ayse` and **denied everywhere else**, so the file journal has something to refuse. |
| `admin` | The break-glass administrator for the panel. |

## What is deliberately not production shape

- **The panel is HTTP on loopback.** The browser terminal is switched on,
  which is only defensible because nothing leaves the machine. Over a
  network this needs TLS; without it the whole session crosses in clear.
- **Recordings are not archived.** There is no object store, so the chain
  head lives only in this host's database. The copy that makes
  `postern session verify` meaningful against a compromised host is the
  one written outside it.
- **One node, one container each.** No replicas, no backups.
- **The database is not published.** Nothing outside the compose network
  can reach it, and that is the only thing protecting a throwaway password.

## Ports

Defaults are `8088` for the panel and `2222` for SSH, both bound to
loopback. Open the panel as `http://localhost:8088`, not by IP: security
keys bind to the address you visit, and the WebAuthn spec accepts
`localhost` as a special case but not `127.0.0.1`.

Override before running:

```bash
POSTERN_HTTP_PORT=9090 POSTERN_SSH_PORT=2200 ./scripts/quickstart.sh
```

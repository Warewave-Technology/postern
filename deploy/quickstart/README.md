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
| `developer` | Reaches both machines. SFTP is allowed under `~` — each person's own home, resolved from the host — and **denied everywhere else**, so the file journal has something to refuse. |
| `admin` | The break-glass administrator for the panel. |
| account propagation | On, so the demo shows what postern now is. See below — it is off by default in a real install. |

## postern owns the accounts here

`manage.propagate_accounts` and `manage.sweep_interval` are on in this
demo's config, and both are **off by default in a real install**. With them
on, the first time somebody opens a session on a target postern creates
their account there — or adopts it, if it already exists, leaving its UID,
shell and home alone — puts them in a `postern-<group>` group for each
group that grants that target, and writes that group's sudo rule. Open the
demo session and look: `ayse` already existed on `demo-a`, so the panel
records her account as **adopted**, and she gains `postern-developer` with
the role's sudo rule behind it.

The sweep runs hourly and is the only thing that can see a change made by
hand on a machine. It repairs what drifted and takes any account out of
postern's own `postern-*` groups when nothing in postern puts it there —
that account would otherwise hold the sudo rule postern wrote while
appearing in none of its records.

Turning these on in production makes postern the source of the OS accounts
on your fleet. That is the point of the feature and it is not a switch to
flip without reading [the README](../../README.md#accounts-when-postern-owns-them).

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

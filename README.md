# postern

> *A postern is the small, guarded side gate in a castle wall — not the main
> gate; the one a few people pass through, under watch.*

Certificate-based, OIDC-authenticated, session-recording SSH bastion in a
single Go binary. A deliberately minimal take on the Teleport idea: one
protocol, one node, one binary.

**Status: early development.** Stage S1 (SSH proxy core) is in progress;
nothing here is production-ready. The full roadmap lives in
[postern-PLAN.md](postern-PLAN.md) (Turkish).

## What it will do

- Proxy SSH sessions to upstream targets and record them as
  [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/)
- Reach targets with short-lived, per-session SSH certificates — users land
  on targets as *themselves* (real `loginuid`, clean audit trail), no shared
  accounts, no static keys in `authorized_keys`
- OIDC login (Keycloak or any provider), TOTP, role-based access control
- Web terminal (xterm.js), SFTP relay

## Development

```bash
make build   # → bin/postern
make test    # unit tests
make vet
```

Test data placeholders under `testdata/` and `internal/config/testdata/` are
not real keys.

## License

Apache-2.0 — see [LICENSE](LICENSE).

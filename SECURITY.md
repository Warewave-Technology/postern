# Security policy

postern sits between people and the servers they administer. A flaw here is
not a flaw in one application — it is a flaw in the door to all of them. We
would much rather hear about it from you than read about it later.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**
[Report a vulnerability](https://github.com/Warewave-Technology/postern/security/advisories/new).

That opens a private thread visible only to you and the maintainers. Please do
not open a public issue for a security problem, and please do not post it to
social media before we have had a chance to answer.

If that link does not work for you — it needs the repository to be public and
the feature enabled — open an issue that says only "security report, please
get in touch" with no detail in it, and we will take it from there.

Helpful things to include, roughly in order of how much they help:

- the version — `postern version` prints the tag, the commit, and whether the
  tree it was built from was clean
- what an attacker gains, concretely: whose session, whose target, which audit
  row
- the smallest reproduction you have, ideally commands and their output
- whether it needs a non-default setting (`session.sftp`, `target_probe`,
  `http.terminal_enabled`, `trusted_proxies`), and which

You do not need a working exploit. A precise description of the reachable path
is enough to start.

## What to expect

We are a small team, so here is an honest schedule rather than a flattering one:

| | |
|---|---|
| First human reply | within 5 working days |
| Assessment: is it real, how bad | within 10 working days |
| Fix for a confirmed high-severity issue | as fast as we can, and we will tell you the date we are working toward |

If a week passes with no reply, assume the message went astray and ping the
thread — that is not rudeness, it is help.

We will tell you what we decided and why, including when we decide something is
not a vulnerability. You will be credited in the advisory and the changelog
unless you would rather not be.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| pre-1.0 builds | No — upgrade to 1.0 |

There is one release line. Fixes land on it; there are no long-term branches.

## Scope

**In scope** — this is postern's own code and the guarantees it claims:

- the SSH front door: authentication, the certificate it mints, what that
  certificate is allowed to do
- authorisation: roles, target access, the administrator flag
- session recording and the audit trail — including anything that makes a
  recording or an audit row absent, incomplete, or untrue
- the SFTP file audit
- the admin panel and its API, and the browser terminal
- the archive path and its credentials
- the release artifacts: the binary, the checksums, the signature

**Out of scope** — real problems, but not ours to fix:

- the target's own `sshd`, and anything the operator's OS lets a user do once
  postern has correctly landed them there
- PostgreSQL, the operator's identity provider or directory, and their TLS
  terminator
- anything that requires already holding the CA key, the database credentials,
  or root on the bastion — those are the trust roots, not a boundary
- the limits postern states plainly in
  [the documentation](https://postern.warewave.tech/docs/#limits): no port
  forwarding, no clustering, TOTP as the only second factor, no integrity seal
  on recordings. Telling us that recordings can be edited by someone with root
  on the bastion is telling us something we wrote down first. Telling us how to
  do it *without* root is very much in scope.

## Safe harbour

If you are researching in good faith, stay within scope, and give us a
reasonable chance to fix things before going public, we will not pursue or
support legal action against you. Test against your own installation. Do not
access other people's data, degrade a running service, or use a finding to keep
access you would not otherwise have.

## One thing worth saying plainly

1.0 means "we think this is right", not "this has run in twenty companies for
three years". The proxy, certificates, recording, RBAC, the panel, OIDC and
LDAP are exercised against real OpenSSH, Keycloak and OpenLDAP on every change,
and six adversarial review passes have been run against the code. That is a
floor, not a guarantee. If you find something, you are probably the first —
please tell us.

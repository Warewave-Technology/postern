# History

These are the documents the project was planned with, kept because they
record *why* things were built the way they were. They are in Turkish,
they were written before most of the code existed, and **they are not
current process.**

| | |
|---|---|
| `postern-PLAN.md` | The original build plan: stages S1–S5, interfaces, protocol notes |
| `postern-PLAN-ldap.md` | The directory work, planned alongside it |
| `postern-PLAN-web.md` | The admin panel, planned alongside it |
| `postern-EKSIKLER-1.0.md` | A review from 1–2 September 2026: what was found, what was fixed, what was deliberately left |

## Read them as history, not as instructions

Two things in particular have moved on since they were written.

`postern-PLAN.md` §0 divides the work between a person and an assistant
and names three files the assistant must not write — certificate
signing, incoming authentication, the authorisation decision. That was
the rule at the start. It is not how the code was actually produced, and
saying so plainly is better than leaving a document that implies
otherwise: the project is written with AI assistance throughout,
including those files, and the compensating control is not who typed it
but what is measured. Every security-relevant behaviour in this
repository is held down by a test that fails when the behaviour is
removed — that is checked by deleting the fix and watching the test go
red, not by assertion. Six adversarial review passes have been run
against the code, each one measuring on running software rather than
reading it.

The stage numbering (S1.7, S3.3, and so on) is still referenced from a
few code comments, because those references are genuinely useful for
finding the reasoning behind a decision. The plan's *schedule* is not.

For what postern does today, read
[the documentation](https://postern.warewave.tech/docs/). For what it
deliberately does not do, read
[Limits of 1.0](https://postern.warewave.tech/docs/#limits).

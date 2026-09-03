# deploy/

Two things, for two different machines.

## `systemd/` — the bastion

`postern.service` runs postern as its own user with almost nothing else.
It holds the CA key, the secret key and every session recording, so the
unit is a security boundary rather than a start script: read-only
filesystem except the recordings directory, no capabilities at all, and
a syscall filter.

```bash
# The unit runs /usr/local/bin/postern — put the binary there first.
# Nothing else in the documentation does this step, and without it
# systemd reports status=203/EXEC, which reads like a permissions
# problem rather than a missing file.
tar xzf postern_1.0.0_linux_amd64.tar.gz
install -o root -g root -m 0755 postern /usr/local/bin/postern

useradd --system --home /var/lib/postern --shell /usr/sbin/nologin postern
install -d -o postern -g postern -m 0700 /var/lib/postern/recordings
install -d -o root -g postern -m 0750 /etc/postern

install -o root -g root -m 0644 systemd/postern.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now postern
```

The unit expects `/etc/postern/postern.yaml` and the keys it names to
exist already — `ssh-keygen` for the host key, `postern ca init`,
`postern secret init`, and `postern db migrate` against the database.
[Setting up](../README.md#setting-up) is that list; run it as `postern`
so the files it writes are owned by the account the unit runs as.

The database password goes in `/etc/postern/postern.env` (owned by
`postern`, mode `0600`) rather than on the command line, where every user
on the box could read it with `ps`:

```
POSTERN_DATABASE_DSN=postgres://postern:...@127.0.0.1/postern?sslmode=require
```

postern listens on 2222 and the unit grants no capabilities, so it cannot
bind port 22. Put a redirect in front of it if you want 22 — giving an SSH
server `CAP_NET_BIND_SERVICE` buys a port number and costs a boundary.

## `ansible/` — the targets

`postern_target` makes a host trust postern's certificates. It does not
install postern.

```yaml
- hosts: managed
  become: true
  roles:
    - role: postern_target
      vars:
        postern_ca_pubkey: "{{ lookup('file', 'postern_ca.pub') }}"
        postern_principals:
          yigit: [yigit]
          deploy: [yigit, suheda]
```

`postern_principals` says which certificate principal may open which local
account. postern signs the user's `os_user` as the principal, so this map
is the answer to "who may become this account on this host".

Two refusals are deliberate:

- **An empty CA key stops the run.** Continuing would leave the host
  trusting no CA — which looks like success and is not.
- **A configuration `sshd -t` rejects is never installed.** An invalid
  `sshd_config` takes the host away at its next restart, and you cannot SSH
  in to fix it.

The handler reloads sshd rather than restarting it: a restart drops open
sessions, so somebody working through postern would lose their work because
a target's configuration was updated.

`test/integration/testdata/certtarget/Dockerfile` is the same setup as a
runnable file, and is what the certificate tests run against.

**On OpenSSH older than 8.2 the role adds the `Include` line itself.**
`sshd_config.d` is only read when the main file includes it, and that
line arrived in 8.2 — RHEL 8 derivatives (Alma, Rocky, Oracle) and
Amazon Linux 2 ship without it. Measured on `almalinux:8`: writing the
drop-in alone passes `sshd -t -f <file>` and `sshd -t`, the play reports
`changed, failed=0`, and `sshd -T` still says `trustedusercakeys none` —
the host trusts nothing and the first person to connect is refused. The
role now asks sshd itself whether the drop-in took effect, adds a
validated `Include` at the top of `sshd_config` when it did not, and
fails the play if `sshd -T` still does not name the CA. Nothing is
written to the main file on hosts that already include the directory.

## A worked example

`example/inventory.ini` and `example/targets.yml` are a two-host run of the
role, ready to fill in. Everything you must supply is left as `CHANGE_ME`: the
host addresses, the account Ansible connects as (it needs sudo — it is not the
account postern opens on the target), and the CA public key from `postern ca
init` on the bastion. Nothing here points at a real machine, because this file
ships inside the release archive.

```bash
ansible-playbook -i example/inventory.ini example/targets.yml --check
```

Run from `deploy/ansible/` — the `ansible.cfg` there is what points Ansible at
`roles/`, since Ansible resolves roles against the playbook's directory and the
example playbook lives one level down.

Run it with `--check` first. The role's first task is an assert and the play
gathers no facts, so a forgotten `CHANGE_ME` stops the play at `ok=0 failed=1`
without connecting to anything — rather than leaving a host that trusts no CA,
which looks like a successful run and is not. Measured on the shipped files:

```
target-01  : ok=0  changed=0  unreachable=0  failed=1
```

`postern_principals` maps an OS account to the principals it will accept.
postern signs the user's `os_user` as the principal, so an account whose
`os_user` is `sidinak` needs `sidinak: [sidinak]` here _and_ needs that account
to exist on the target. Leaving the map empty opens no account at all, which is
the safe side to fail on.

-- Discovery sources, their runs, and the machines they found.
--
-- Until now discovery was a command an operator ran by hand and it wrote
-- targets and role grants directly, after a person had read the preview.
-- A schedule has no such reader. So what a scheduled run finds lands in
-- discovered_machines first, and becomes a target only when an
-- administrator registers it: automation may grow the inventory, never
-- the set of machines people can reach.
CREATE TABLE discovery_sources (
    id               TEXT    PRIMARY KEY,
    name             TEXT    NOT NULL,
    kind             TEXT    NOT NULL CHECK (kind IN ('proxmox', 'vsphere')),
    url              TEXT    NOT NULL,
    -- Proxmox API token id, or the vCenter user name.
    username         TEXT    NOT NULL,
    -- Token secret or password, sealed with the bastion's secret key.
    -- The API never returns it.
    secret           TEXT    NOT NULL,
    ca_pem           TEXT    NOT NULL DEFAULT '',
    insecure         BOOLEAN NOT NULL DEFAULT FALSE,
    node             TEXT    NOT NULL DEFAULT '',
    tag_key          TEXT    NOT NULL,
    name_pattern     TEXT    NOT NULL DEFAULT '',
    port             INTEGER NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    -- Seconds between scheduled runs; 0 runs only when asked to.
    interval_seconds INTEGER NOT NULL DEFAULT 0 CHECK (interval_seconds >= 0),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_by       TEXT    NOT NULL,
    created_at       BIGINT  NOT NULL,
    updated_at       BIGINT  NOT NULL,
    -- When the last run started. The scheduler claims a run by moving it.
    last_run_at      BIGINT
);
CREATE UNIQUE INDEX discovery_sources_name ON discovery_sources (lower(name));

CREATE TABLE discovery_runs (
    id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id    TEXT    NOT NULL REFERENCES discovery_sources (id) ON DELETE CASCADE,
    trigger      TEXT    NOT NULL CHECK (trigger IN ('timer', 'web')),
    actor        TEXT    NOT NULL,
    started_at   BIGINT  NOT NULL,
    finished_at  BIGINT,
    outcome      TEXT    NOT NULL DEFAULT 'running' CHECK (outcome IN ('running', 'ok', 'failed')),
    reason       TEXT    NOT NULL DEFAULT '',
    seen         INTEGER NOT NULL DEFAULT 0,
    new_machines INTEGER NOT NULL DEFAULT 0,
    missing      INTEGER NOT NULL DEFAULT 0,
    key_changed  INTEGER NOT NULL DEFAULT 0,
    unreachable  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX discovery_runs_source ON discovery_runs (source_id, id DESC);

CREATE TABLE discovered_machines (
    source_id     TEXT    NOT NULL REFERENCES discovery_sources (id) ON DELETE CASCADE,
    -- The platform's stable identity (qemu/101, vsphere/vm-42): a machine
    -- renamed or migrated on the platform is the same row, not a new one.
    ref           TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    host          TEXT    NOT NULL DEFAULT '',
    tags          TEXT    NOT NULL DEFAULT '[]',
    running       BOOLEAN NOT NULL DEFAULT FALSE,
    role          TEXT    NOT NULL DEFAULT '',
    tagged        BOOLEAN NOT NULL DEFAULT FALSE,
    -- The host key read in the last run that could read one.
    host_key      TEXT    NOT NULL DEFAULT '',
    -- What stands in the way of registering it, or what differs from the
    -- target it is linked to. Empty when nothing does.
    problem       TEXT    NOT NULL DEFAULT '',
    target_id     TEXT    REFERENCES targets (id) ON DELETE SET NULL,
    ignored       BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen    BIGINT  NOT NULL,
    last_seen     BIGINT  NOT NULL,
    -- Set when a successful run no longer reports the machine. The row
    -- and any target stay: the target has a session history.
    missing_since BIGINT,
    PRIMARY KEY (source_id, ref)
);

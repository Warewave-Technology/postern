-- Temporary (just-in-time) access grants on managed targets.
--
-- A row is the record of an account postern created on a target for a
-- limited time: who asked for it, for whom, on which machine, what it was
-- allowed to do, and when postern took it away again. Rows are never
-- deleted: a grant that was revoked is still the answer to "who had root on
-- that machine last Tuesday".
--
-- username, os_user and target are snapshots, not foreign keys. The postern
-- user may be deleted and recreated under the same name, and the target may
-- be removed; the record of what was granted must survive both.
CREATE TABLE jit_grants (
    id              TEXT    PRIMARY KEY,
    username        TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    os_user         TEXT    NOT NULL,
    -- JSON array of group names the account was added to.
    groups          TEXT    NOT NULL,
    -- JSON of the per-account sudo rule; NULL when the grant carries none.
    sudo_rule       TEXT,
    granted_by      TEXT    NOT NULL,
    granted_at      BIGINT  NOT NULL,
    -- When postern takes the account away. A grant that could not be fully
    -- applied has this set to the time of the failure, so the sweeper cleans
    -- up whatever was half-created without waiting for the requested end.
    expires_at      BIGINT  NOT NULL,
    applied_at      BIGINT,
    apply_report    TEXT    NOT NULL DEFAULT '',
    revoked_at      BIGINT,
    revoke_report   TEXT    NOT NULL DEFAULT '',
    -- Why the last revocation attempt did not complete, and when to retry.
    revoke_error    TEXT    NOT NULL DEFAULT '',
    revoke_attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt    BIGINT
);

CREATE INDEX jit_grants_due    ON jit_grants (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX jit_grants_target ON jit_grants (target, granted_at DESC);
CREATE INDEX jit_grants_user   ON jit_grants (username) WHERE revoked_at IS NULL;

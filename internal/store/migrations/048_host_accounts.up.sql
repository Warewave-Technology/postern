-- What postern has done to an account on a target, and what it should be.
--
-- One row per (target, postern user), written the first time postern
-- touches the pair. No row means "never provisioned here".
--
-- ⚠️ origin IS THE WHOLE POINT OF WRITING THIS DOWN. An account postern
-- created and one it merely joined to a group are indistinguishable on
-- the host; only this column can tell them apart, and that difference
-- decides what a deletion is allowed to offer. It cannot be recovered
-- later by looking at the machine.
--
-- ⚠️ applied_fp IS ON THE CONNECT PATH. Every session compares it with
-- the state computed from the database, and an equal pair means the
-- target is not contacted at all. Without it, opening a session would
-- cost a second SSH connection to the host every single time.
CREATE TABLE host_accounts (
    target_name TEXT NOT NULL REFERENCES targets (name) ON DELETE CASCADE,
    -- users.username, users.name DEĞİL: benzersiz olan sütun o.
    username    TEXT NOT NULL REFERENCES users (username) ON DELETE CASCADE,
    os_user     TEXT NOT NULL CHECK (os_user <> ''),

    origin TEXT NOT NULL CHECK (origin IN ('created', 'adopted')),
    state  TEXT NOT NULL CHECK (state IN ('active', 'locked', 'removed', 'failed')),

    -- Locked by a path with no human in it (directory sync, deactivation,
    -- a deleted group). The panel lists these and a person decides.
    awaiting_decision BOOLEAN NOT NULL DEFAULT FALSE,

    desired_fp TEXT NOT NULL DEFAULT '',
    applied_fp TEXT NOT NULL DEFAULT '',
    applied_at BIGINT,

    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    next_attempt_at BIGINT,

    first_seen BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,

    PRIMARY KEY (target_name, username)
);

-- The panel's "waiting for a decision" list reads only these rows.
CREATE INDEX host_accounts_awaiting ON host_accounts (target_name)
    WHERE awaiting_decision;

-- The numeric id a person carries on every machine postern opens an
-- account for them on.
--
-- ⚠️ ONE NUMBER PER PERSON, FLEET-WIDE. Letting each host pick its own
-- is simpler and wrong the moment anything is shared: the same person is
-- 1003 on one machine and 1007 on another, so a file on an NFS mount or
-- restored from a backup shows the wrong owner — or worse, somebody
-- else's name.
--
-- ⚠️ THE UID IS UNIQUE HERE, WHICH IS WHAT MAKES ALLOCATION SAFE. Two
-- sessions can pick the same free number at the same time; the constraint
-- turns that race into an error one of them retries, instead of two
-- people sharing an identity.
--
-- source says where the number came from: the directory's own uidNumber,
-- or postern's pool. It matters when they disagree later — a directory
-- that starts publishing uidNumber for somebody who already has a pool
-- number must not silently renumber them, because their files do not
-- move with them.
CREATE TABLE user_uids (
    username TEXT    PRIMARY KEY REFERENCES users (username) ON DELETE CASCADE,
    uid      INTEGER NOT NULL UNIQUE CHECK (uid > 0),
    source   TEXT    NOT NULL CHECK (source IN ('directory', 'pool')),

    created_at BIGINT NOT NULL
);

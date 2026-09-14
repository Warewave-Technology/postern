-- The sudo a role carries on the machines it reaches.
--
-- Until now a sudo rule could only be written per grant, into the
-- account's own file on the target. That answered "what may this person
-- run for the next four hours" and never "what may this role run", so
-- the same rule was retyped for every person and drifted.
--
-- One rule per role, not many named ones: on the target a group has a
-- single sudoers file, rendered from a single rule with as many commands
-- as it needs. Several rules per role would have to be merged into that
-- one file, which is a merge nobody asked for.
--
-- The rule lands on a target as `%<role> ALL=(runas) NOPASSWD: ...` in
-- /etc/sudoers.d/postern-<role>, so a person draws it from membership in
-- the role's group. What a grant adds on top stays in the account's own
-- file and leaves with the account.
CREATE TABLE role_sudo_rules (
    role_id      TEXT    PRIMARY KEY REFERENCES roles (id) ON DELETE CASCADE,
    -- sudoers.Rule as JSON, the shape jit_grants.sudo_rule already uses.
    rule         TEXT    NOT NULL,
    -- The operator accepted a rule that sudoers.Validate flagged as a way
    -- out to a root shell. Kept beside the rule so the audit line and the
    -- screen can say it was a decision.
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by   TEXT    NOT NULL,
    updated_at   BIGINT  NOT NULL
);

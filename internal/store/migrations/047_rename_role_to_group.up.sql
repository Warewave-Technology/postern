-- postern's own authorisation object is called a group, not a role.
--
-- The chain a reader has to follow is: directory group -> postern's
-- object -> Unix group on the host. Calling the middle one a "role" gave
-- the same thing three names, and the reader had to carry the mapping.
-- One word makes the chain readable.
--
-- Nothing changes on a managed host. The sudoers file is named after the
-- object's NAME (/etc/sudoers.d/postern-dba), never after the word for
-- its type, so there is no host-side migration and no file to rewrite.
--
-- ⚠️ "group" alone cannot be a column name here: it is a reserved word
-- and PostgreSQL refuses it unquoted (SQLSTATE 42601 — measured against
-- postgres:17-alpine while this was written). "groups" as a TABLE name
-- is accepted. That is why discovered_machines.role becomes group_name
-- rather than group: a column every query would have to quote is a
-- column every future query will forget to quote.
--
-- RENAME, not create-and-copy: the rows are the authorisation data of a
-- running bastion. A copy that drops a row takes someone's access away
-- silently, and the first person to notice is the one who cannot log in.
ALTER TABLE roles            RENAME TO groups;
ALTER TABLE user_roles       RENAME TO user_groups;
ALTER TABLE role_targets     RENAME TO group_targets;
ALTER TABLE role_paths       RENAME TO group_paths;
ALTER TABLE role_sudo_rules  RENAME TO group_sudo_rules;

ALTER TABLE user_groups         RENAME COLUMN role_id TO group_id;
ALTER TABLE group_targets       RENAME COLUMN role_id TO group_id;
ALTER TABLE group_paths         RENAME COLUMN role_id TO group_id;
ALTER TABLE group_sudo_rules    RENAME COLUMN role_id TO group_id;
ALTER TABLE group_mappings      RENAME COLUMN role_id TO group_id;
ALTER TABLE sync_runs           RENAME COLUMN roles_changed TO groups_changed;
ALTER TABLE discovered_machines RENAME COLUMN role TO group_name;

ALTER INDEX user_roles_source_idx RENAME TO user_groups_source_idx;
ALTER INDEX role_paths_role_idx   RENAME TO group_paths_group_idx;
ALTER INDEX group_mappings_group_role_lower_idx
    RENAME TO group_mappings_external_group_lower_idx;

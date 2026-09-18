-- Reverse of 047, in reverse order: indexes, then columns, then tables.
--
-- The order matters. A column rename names its table, so the tables have
-- to still carry their new names while the columns go back; renaming the
-- tables first would leave these statements pointing at names that no
-- longer exist.
ALTER INDEX group_mappings_external_group_lower_idx
    RENAME TO group_mappings_group_role_lower_idx;
ALTER INDEX group_paths_group_idx   RENAME TO role_paths_role_idx;
ALTER INDEX user_groups_source_idx  RENAME TO user_roles_source_idx;

ALTER TABLE discovered_machines RENAME COLUMN group_name TO role;
ALTER TABLE sync_runs           RENAME COLUMN groups_changed TO roles_changed;
ALTER TABLE group_mappings      RENAME COLUMN group_id TO role_id;
ALTER TABLE group_sudo_rules    RENAME COLUMN group_id TO role_id;
ALTER TABLE group_paths         RENAME COLUMN group_id TO role_id;
ALTER TABLE group_targets       RENAME COLUMN group_id TO role_id;
ALTER TABLE user_groups         RENAME COLUMN group_id TO role_id;

ALTER TABLE group_sudo_rules RENAME TO role_sudo_rules;
ALTER TABLE group_paths      RENAME TO role_paths;
ALTER TABLE group_targets    RENAME TO role_targets;
ALTER TABLE user_groups      RENAME TO user_roles;
ALTER TABLE groups           RENAME TO roles;

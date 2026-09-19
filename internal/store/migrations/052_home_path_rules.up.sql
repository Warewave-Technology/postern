-- Let a path rule say "this person's own home".
--
-- ⚠️ A GROUP RULE NAMING ONE PERSON'S HOME IS A RULE FOR ONE PERSON.
-- Measured on the demo: the `developer` group allowed /home/ayse, and
-- every other member of that group opened the file browser onto a
-- refusal. The three ways out without this token are all wrong — a rule
-- per person does not survive the team growing, allowing /home opens
-- everyone's home to everyone in the group, and a group per person is
-- not a group.
--
-- The token is expanded per session from the home the target itself
-- reports, never from a guess like /home/<name>: an account whose home
-- is somewhere else would have its rule pointed at a directory it does
-- not own.
ALTER TABLE group_paths DROP CONSTRAINT IF EXISTS role_paths_prefix_check;
ALTER TABLE group_paths DROP CONSTRAINT IF EXISTS group_paths_prefix_check;
ALTER TABLE group_paths ADD CONSTRAINT group_paths_prefix_check
  CHECK (prefix LIKE '/%' OR prefix = '~' OR prefix LIKE '~/%');

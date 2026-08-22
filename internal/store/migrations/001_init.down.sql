-- 001_init geri alma. Sıra önemli: referans VEREN tablolar önce düşer.
DROP INDEX IF EXISTS sessions_target_started_idx;
DROP INDEX IF EXISTS sessions_user_started_idx;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS role_targets;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS targets;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;

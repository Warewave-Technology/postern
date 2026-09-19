-- ⚠️ ~ KURALLARI ÖNCE SİLİNİYOR. Geri alınan kısıt onları reddediyor ve
-- silmeden eklemek göçü yarıda bırakırdı.
DELETE FROM group_paths WHERE prefix = '~' OR prefix LIKE '~/%';
ALTER TABLE group_paths DROP CONSTRAINT IF EXISTS group_paths_prefix_check;
ALTER TABLE group_paths ADD CONSTRAINT group_paths_prefix_check
  CHECK (prefix LIKE '/%');

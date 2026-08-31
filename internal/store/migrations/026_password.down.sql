-- 026 geri alınıyor. Parolalar SİLİNMİYOR: satırlar duruyor, yalnızca
-- onları paroladan ayıran bilgi kalkıyor. Geri alan operatörün elinde
-- doğrulayıcılar kalsın — geri alma, kimseyi dışarıda bırakmamalı.
ALTER TABLE local_credentials DROP CONSTRAINT local_credentials_admin_secret_from_host;
ALTER TABLE local_credentials DROP CONSTRAINT local_credentials_holder_fkey;
ALTER TABLE local_credentials DROP COLUMN holder_is_admin;
ALTER TABLE users DROP CONSTRAINT users_id_admin_key;
ALTER TABLE local_credentials DROP COLUMN must_change;
ALTER TABLE local_credentials DROP COLUMN chosen_at;

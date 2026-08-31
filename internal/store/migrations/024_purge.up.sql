-- 024_purge: kullanıcı ADINI serbest bırakmak, kaydı silmeden.
--
-- ⚠️ ÇÖZÜLEN SORUN: silinmiş bir hesabın kullanıcı adı dolu kalıyordu.
-- Dizinde aynı adla YENİ biri belirdiğinde (farklı kimlik, aynı ad)
-- hesap açılamıyordu. Nadir ama gerçek.
--
-- ⚠️ VE ÇÖZÜMÜN YAPMAMASI GEREKEN ŞEY: satırı silmek. Denetim kaydı ve
-- oturum kayıtları kullanıcı adını METİN olarak saklıyor (bkz.
-- model.Session yorumu: "cevabın bir JOIN'e ihtiyacı olmasın"). Satır
-- yok olursa geçmişteki "ayse.yilmaz" satırlarının KİME ait olduğu
-- cevapsız kalır — ve aynı adı alan yeni kişiyle karışır.
--
-- Bu yüzden purge SATIRI BIRAKIYOR, yalnızca TANIMLAYICILARI serbest
-- bırakıyor:
--
--   username  → "purged:<id>" (gerçek ad former_username'e taşınıyor)
--   email, idp_subject, dir_subject → NULL
--   anahtarlar ve roller → siliniyor
--
-- ⚠️ NEDEN YENİDEN ADLANDIRMA, "benzersizlik purged olanları saymasın"
-- DEĞİL: ikincisi, kullanıcı adıyla arayan HER sorguya "AND purged_at
-- IS NULL" eklemeyi gerektirirdi ve unutulan tek bir sorgu, yeni
-- kişiyi ölü bir satıra çözerdi. Adın gerçekten farklı olması o hatayı
-- temsil edilemez kılıyor.

ALTER TABLE users ADD COLUMN purged_at BIGINT;

-- Purge edilen hesabın GERÇEK adı. Denetim kaydındaki metinlerin kime
-- ait olduğu ancak buradan okunabilir.
ALTER TABLE users ADD COLUMN former_username TEXT;

-- Aynı ad iki kez purge edilebilir (iki farklı kişi, aynı ad) —
-- benzersizlik YOK, bilerek.
CREATE INDEX users_purged_idx ON users (purged_at) WHERE purged_at IS NOT NULL;

-- admin_log.via'ya dokunulmuyor: purge 'cli' ya da 'web' üzerinden
-- yapılıyor ve ikisi de zaten tanımlı.

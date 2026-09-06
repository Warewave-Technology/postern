-- Rol başına SFTP yol kuralları.
--
-- NEDEN ROLDE, YAPILANDIRMADA DEĞİL: kimlik ve yetki için tek kaynak
-- veritabanı (S3 kararı). Yapılandırma yalnızca altyapıyı anlatıyor; "kim
-- nereye erişebilir" sorusu buradan cevaplanıyor ve yönetim CLI/API ile
-- yapılıyor.
--
-- ⚠️ KURALSIZ ROL KISITSIZDIR — ve bu, sessizce kapatmamak için bilinçli.
-- Bu göç var olan hiçbir rolü değiştirmiyor; kuralı olmayan bir rol
-- bugünkü gibi her yola erişiyor. Aksi hâli, yükseltmenin ertesi sabahı
-- herkesin SFTP'sini kırmak olurdu. Kısıtlama, kural EKLENDİĞİNDE başlıyor.
--
-- ⚠️ BİRLEŞİM, KESİŞİM DEĞİL. Kullanıcı birden çok role sahipse rollerden
-- HERHANGİ BİRİ izin veriyorsa erişim var. Kesişim seçseydik, kısıtlı bir
-- rol eklemek kullanıcının mevcut erişimini SESSİZCE daraltırdı; birleşimde
-- rol eklemek yalnızca genişletiyor ve bu daha az sürprizli.
--
-- Dolayısıyla kuralsız BİR rol, kurallı diğer rolleri etkisiz kılıyor.
-- Sezgiye aykırı görünebilir ama tutarlı: kural yazmak bir rolü
-- kısıtlamak demek, kullanıcıyı değil.
CREATE TABLE role_paths (
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

  -- prefix, mutlak bir yol öneki. Eşleşme DİZİN SINIRINDA:
  -- "/home/u" hem "/home/u" hem "/home/u/..." ile eşleşiyor,
  -- "/home/username" ile EŞLEŞMİYOR. Düz dizgi öneki kullansaydık
  -- ikincisi de eşleşirdi ve kural yazan kişi bunu fark etmezdi.
  prefix TEXT NOT NULL CHECK (prefix LIKE '/%'),

  -- allow, bu önekte erişim var mı. false ise AÇIK RET: izinli bir
  -- ağacın içinden bir dalı kesmeye yarıyor (örneğin /home/u izinliyken
  -- /home/u/.ssh kapalı). En uzun eşleşen önek kazandığı için çalışıyor.
  allow BOOLEAN NOT NULL,

  -- can_write, izin yazmayı da kapsıyor mu. false ise salt okuma.
  can_write BOOLEAN NOT NULL DEFAULT FALSE,

  PRIMARY KEY (role_id, prefix)
);

CREATE INDEX role_paths_role_idx ON role_paths (role_id);

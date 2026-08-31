-- 026_password: yerel kimlik bilgisi artık İKİ ŞEY olabiliyor.
--
-- NEDEN: 015 bu tabloyu "makine üretimi sır" için yazdı ve gerekçesi
-- hâlâ geçerli — kurumsal parolanın postern'e sızmasını engelleyen tek
-- uygulanabilir yol, o değeri kabul edecek bir yolun hiç bulunmaması.
-- Ama o karar, postern'in KENDİ kullanıcı veritabanı olduğu kurulumları
-- görmüyordu: orada insanlardan 34 karakterlik bir base32 dizisini
-- ezberlemeleri isteniyor ve olan şey, dizinin bir yapışkan nota
-- yazılması oluyordu.
--
-- ⚠️ 015'İN KURALI KALDIRILMADI, KAPSAMI DARALDI. Yönetici hesapları
-- hâlâ YALNIZCA makine üretimi sır tutabiliyor: acil durum kapısı,
-- tahmin edilebilir bir değere bağlanamaz. Bu kısıt uygulama
-- katmanında değil, aşağıdaki CHECK'te.

-- chosen_at: NULL ise değer MAKİNE ÜRETİMİ sır (015'in dünyası).
-- Doluysa kullanıcının SEÇTİĞİ parola ve ne zaman seçildiği.
--
-- Ayrı bir "kind" sütunu yerine tarih: iki soruyu birden cevaplıyor.
-- İkincisi ileride lazım olacak — politika sıkılaştırıldığında "hangi
-- parolalar eski kurala göre konmuş" sorusunun cevabı bu sütun, ve
-- sonradan eklemek ikinci bir göç demekti.
ALTER TABLE local_credentials ADD COLUMN chosen_at BIGINT;

-- must_change: bir sonraki girişte parola DEĞİŞTİRİLMEK ZORUNDA.
--
-- Panelden verilen kimlik bilgisi bu bayrakla doğuyor. Kapattığı somut
-- açık: yönetici bir değer üretip kişiye iletiyor — sohbete
-- yapıştırarak, telefonda okuyarak, ekranda bırakarak. O değer, kişi
-- onu değiştirene kadar İKİ kişinin elinde. Bayrak, "iki kişinin
-- elinde" hâlini tek bir girişle sınırlıyor.
ALTER TABLE local_credentials ADD COLUMN must_change BOOLEAN NOT NULL DEFAULT FALSE;

-- ⚠️ YÖNETİCİ PAROLA TUTAMAZ — VERİTABANI SEVİYESİNDE.
--
-- Bunu uygulama katmanındaki üç-beş kontrolle tutmak DENENDİ ve
-- ölçülerek yetmediği görüldü: READ COMMITTED altında iki eşzamanlı
-- işlem — biri "yönetici değil" görüp parola yazan, öbürü "parolası
-- yok" görüp yönetici yapan — ikisi de commit ediyor ve ortada parola
-- tutan bir yönetici kalıyor. Sıralamayı satır kilidiyle zorlamak
-- mümkündü ama o kilidi ALMAYI UNUTAN bir sonraki çağrı yolu, kuralı
-- sessizce delerdi.
--
-- Denormalize edilmiş holder_is_admin + bileşik yabancı anahtar, kuralı
-- YAZILAMAZ hâle getiriyor: is_admin değiştiğinde ON UPDATE CASCADE
-- burayı da güncelliyor ve CHECK, ihlali kabul etmiyor. Yeni bir çağrı
-- yolu eklemek onu delemiyor.
ALTER TABLE users ADD CONSTRAINT users_id_admin_key UNIQUE (id, is_admin);

ALTER TABLE local_credentials ADD COLUMN holder_is_admin BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE local_credentials c
   SET holder_is_admin = u.is_admin
  FROM users u
 WHERE u.id = c.user_id;

ALTER TABLE local_credentials
  ADD CONSTRAINT local_credentials_holder_fkey
  FOREIGN KEY (user_id, holder_is_admin)
  REFERENCES users (id, is_admin)
  ON UPDATE CASCADE ON DELETE CASCADE;

-- ⚠️ KURAL "PAROLA DEĞİL" DEĞİL, "HOST'TAN GELMEYEN DEĞİL".
--
-- İlk yazdığımız hâli `chosen_at IS NOT NULL` idi — yani yalnızca
-- kullanıcının SEÇTİĞİ parolayı yasaklıyordu. Bir saldırı sırası bunun
-- yetmediğini gösterdi ve o sıra tamamen PANELDEN yürüyor:
--
--   1. Yönetici, sıradan bir hesaba panelden giriş bilgisi verir.
--      Değer makine üretimi, yani "parola" değil — ama VEREN KİŞİ
--      değeri biliyor.
--   2. Aynı yönetici, panelden dizin yönetici grubunu o kişiyi
--      kapsayacak şekilde değiştirir (017'den beri mümkün).
--   3. Kişi yönetici olur ve kimlik bilgisi hâlâ ilk yöneticinin
--      bildiği değerdir.
--
-- Sonuç: paneli ele geçiren biri, host'a hiç dokunmadan, sırrını
-- bildiği bir yönetici üretir. Acil durum kapısının tüm anlamı gider.
--
-- Doğru ölçüt değerin TÜRÜ değil KAYNAĞI: yönetici hesabının kimlik
-- bilgisi HOST'TAN çıkmış olmak zorunda. created_by zaten bunu
-- taşıyor ('cli' yalnızca `postern admin bootstrap` ve
-- `postern admin issue` tarafından yazılıyor).
--
-- must_change de aynı CHECK'te ve onsuz bir ÇIKMAZ var: bayrağı taşıyan
-- biri yönetici yapılırsa, parola koyamaz (ilk kural) ama parola
-- koymadan da hiçbir şey yapamaz. Hesap girebilir ve hiçbir şey yapamaz
-- hâlde kilitlenirdi — kurulumun tek yöneticisiyse çıkış yolu host'a
-- gitmekten geçerdi, yani 015'in "kilitleme yok" kuralının engellemek
-- için yazıldığı sonuç.
--
-- ÜÇÜNCÜ ŞART (chosen_at) AYRICA GEREKLİ ve düşürüldüğünde bir test
-- yakaladı: SetChosenPassword created_by'a DOKUNMUYOR — dokunmamalı da,
-- o sütun "kim verdi" sorusunun cevabı. Yani host'tan sır almış bir
-- yönetici, o satırın üstüne parola yazarak ilk iki şartı sağlamaya
-- devam ederdi. Kaynak, tür ve bayrak: üçü de ayrı sorular.
--
-- Hepsini yükseltme yolunda temizliyoruz; buradaki CHECK ise
-- temizlemeyi UNUTAN bir sonraki çağrı yolunun sessizce geçmesini
-- engelliyor.
ALTER TABLE local_credentials
  ADD CONSTRAINT local_credentials_admin_secret_from_host
  CHECK (NOT (holder_is_admin AND (
    created_by <> 'cli' OR must_change OR chosen_at IS NOT NULL)));

-- Denetim kaydına yeni eylemler değil, yeni bir kapı gelmiyor: 'web'
-- ve 'cli' zaten var. Eylem adları uygulama tarafında.

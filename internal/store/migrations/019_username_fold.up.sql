-- 019_username_fold: kullanıcı adı, harf yazımından bağımsız BENZERSİZ.
--
-- ⚠️ KAPATILAN BELİRSİZLİK: users.username yalnızca harfe DUYARLI
-- UNIQUE'ti (001), dolayısıyla "Bob" ile "bob" iki ayrı hesap olarak var
-- olabiliyordu. Bunun kendisi bir tercih sayılabilirdi — ama kod bu
-- ikisini AYIRT ETMEYEN yollarla arıyor:
--
--   * store.UserByNameFold: `lower(username) = lower($1)` sorgusunu
--     QueryRow ile çalıştırıyor; iki satır eşleşirse hangisinin
--     döneceği veritabanının sıralamasına kalıyor.
--   * ApplyAdminGroup: dizinden gelen adı bütün kullanıcılarla
--     EqualFold karşılaştırıp İLK eşleşmede duruyor.
--
-- İkisi de yönetici yetkisi kararlarında kullanılıyor. Yani "hangi Bob"
-- sorusunun cevabı, is_admin'in kime yazılacağını belirleyebiliyordu ve
-- cevabı kimse seçmemişti.
--
-- Dizinler zaten böyle davranıyor: uid ve sAMAccountName eşleşmeleri
-- caseIgnoreMatch. postern'in daha gevşek olması, dizinin tek kişi
-- gördüğü yerde postern'in iki hesap tutabilmesi demekti.

-- ⚠️ ÖNCE ÖLÇ, SONRA UYGULA. Düz bir CREATE UNIQUE INDEX, çakışma
-- varsa anlaşılmaz bir hata veriyor ve operatör hangi hesapların sorun
-- çıkardığını göremiyor. Yükseltmeyi durduran mesaj, ne yapılacağını
-- söylemek zorunda.
DO $$
DECLARE dups TEXT;
BEGIN
  SELECT string_agg(u, ', ') INTO dups FROM (
    SELECT lower(username) AS u
    FROM users
    GROUP BY lower(username)
    HAVING count(*) > 1
  ) x;

  IF dups IS NOT NULL THEN
    RAISE EXCEPTION 'accounts that differ only in letter case exist (%); '
      'postern cannot tell them apart when the directory names one of them. '
      'Remove or rename one of each pair on the bastion host, then upgrade again', dups;
  END IF;
END $$;

CREATE UNIQUE INDEX users_username_lower_idx ON users (lower(username));

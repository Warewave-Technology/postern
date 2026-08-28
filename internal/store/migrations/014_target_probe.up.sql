-- 014_target_probe: hedefte KOMUT ÇALIŞTIRARAK öğrenilenler.
--
-- ⚠️ 013'teki alanlardan AYRI SÜTUNLAR ve ayrı bir zaman damgası, çünkü
-- ayrı bir güven düzeyi: 013 el sıkışmadan geliyor (hedefe dokunmadan),
-- bunlar ancak target_probe.enabled ile, hedefte komut koşturularak.
-- probed_at'in kendi başına durması, panele bakan operatörün "bu bilgiyi
-- öğrenmek için makineye dokunduk mu, ne zaman" sorusunu cevaplıyor.
ALTER TABLE target_facts ADD COLUMN kernel     TEXT NOT NULL DEFAULT '';
ALTER TABLE target_facts ADD COLUMN os_name    TEXT NOT NULL DEFAULT '';
ALTER TABLE target_facts ADD COLUMN probed_at  BIGINT;

-- admin_log.via'ya 'probe' eklenmeli: tanıma koşusu hedefte KOMUT
-- çalıştırıyor ve bunun denetim izi bırakması şart. Ayrı bir via değeri,
-- operatörün "postern hangi makinelere dokundu" sorusunu tek süzgeçle
-- cevaplayabilmesi için — 'cli' ya da 'sso' altında karışmamalı.
ALTER TABLE admin_log DROP CONSTRAINT admin_log_via_check;
ALTER TABLE admin_log ADD CONSTRAINT admin_log_via_check
  CHECK (via IN ('web', 'cli', 'sync', 'sso', 'probe'));

-- Why the session ended, and who ended it.
--
-- ⚠️ BU BİLGİ VARDI VE KAYDA HİÇ GİRMİYORDU. proxy, oturumu bir
-- yöneticinin kestiğini biliyor ve kimin kestiğini de biliyor: ikisi de
-- log satırına ve canlı olay akışına yazılıyordu. Log döner, akış
-- geçicidir; olaydan SONRA denetim ekranına bakan kişi için bir
-- yöneticinin kestiği oturum ile kullanıcının kendi çıktığı oturum
-- birbirinin aynısıydı.
--
-- ⚠️ İKİ AYRI SÜTUN, TEK CÜMLE DEĞİL. closed_by makine tarafından
-- okunan bir jeton (terminated, idle_timeout, max_lifetime,
-- recording_failed); terminated_by bir İNSAN adı. Tek alanda
-- birleştirmek, adında ": " geçen birini ayrıştırılamaz yapardı ve
-- filtrelemeyi metin aramasına indirirdi.
ALTER TABLE sessions ADD COLUMN closed_by     TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN terminated_by TEXT NOT NULL DEFAULT '';

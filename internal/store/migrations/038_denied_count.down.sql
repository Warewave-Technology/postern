-- Geri alma, "bu oturumda kural kaç kez çiğnenmeye çalışıldı" sorusunu
-- cevapsız bırakır. Retlerin KENDİSİ session_files'ta duruyor (denied.
-- önekli satırlar), yani kanıt kaybolmuyor; kaybolan şey, listeyi açan
-- denetçinin hangi satırı açacağını tıklamadan görebilmesi.
ALTER TABLE sessions DROP COLUMN sftp_denied;

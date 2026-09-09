package model

import "time"

// Session, açılmış bir oturumun denetim kaydı.
//
// S3 şemasında sessions tablosu. Bu kayıt oturumdan DAHA UZUN yaşar:
// kullanıcı ya da hedef sonradan silinse bile "kim, nereye, ne zaman
// girdi" sorusunun cevabı durmak zorunda.
type Session struct {
	// ID, record.NewSessionID()'nin ürettiği değer. Kayıt dosyasının adı
	// da bu olduğu için, denetim kaydı ile .cast dosyası arasındaki bağ
	// tek bir alanla kuruluyor.
	ID string

	// User ve Target, id değil AD tutar. Denetim kaydını okuyan insan
	// "hangi kullanıcı" diye sorduğunda cevabın bir JOIN'e ihtiyacı olmasın.
	User   string
	Target string

	// OSUser, oturumun AÇILDIĞI hesap.
	//
	// users.os_user'ın kopyası gibi görünür ama değildir: policy o an
	// başka bir hesaba karar vermiş olabilir ve kullanıcının bugünkü
	// os_user'ı o günkü kararı değiştirmemeli. Denetim, kaydın alındığı
	// andaki gerçeği saklar.
	OSUser string

	// SrcIP, kullanıcının bastion'a bağlandığı adres.
	SrcIP string

	// RecordingChain ve RecordingLinks, kaydın zincir başı ve halka
	// sayısı (göç 034).
	//
	// ⚠️ BOŞ BAŞ "DOĞRULANDI" DEĞİL, "DOĞRULANAMAZ" DEMEK. Göç öncesi
	// kapanmış oturumlarda ve çökme sonrası süpürülen oturumlarda baş
	// yok; ikisini "geçti" gibi göstermek, kanıtı olmayan bir kaydı
	// kanıtlanmış saymak olurdu.
	RecordingChain string
	RecordingLinks int64

	// SFTPJournal, oturum kapanırken defterin durumu (göç 037).
	SFTPJournal SFTPJournal

	StartedAt time.Time

	// EndedAt sıfır değerse oturum hâlâ açık (şemada NULL).
	EndedAt time.Time

	// RecordingPath, .cast dosyasının yolu. Kayıt açılamadıysa boş —
	// ama o durumda oturum zaten reddedilmiş olmalı (S1.8 kararı).
	RecordingPath string
}

/*
 * SFTPJournal, bir oturumun SFTP denetim defterinin kapanıştaki durumu.
 *
 * ⚠️ ÜÇ ALAN, ÇÜNKÜ ÜÇ AYRI SORU. "Kayıt kaç olay saydı", "postern
 * bunların kaçını deftere koyamadığını BİLİYOR" ve "bu ikisi ölçüldü
 * mü". Üçüncüsü olmadan diğer ikisi yanıltıcı: ölçülmemiş bir oturumda
 * Events sıfırdır ve sıfır, "hiç olay olmadı" gibi okunur.
 */
type SFTPJournal struct {
	/*
	 * Measured, kaydın mühür satırındaki sayının bilindiği.
	 *
	 * ⚠️ FALSE "GEÇTİ" DEĞİL, "KARŞILAŞTIRILAMAZ" DEMEK — zincir
	 * başındaki (034) boş baş kararının aynısı. Göç 037'den önce
	 * kapanmış oturumlarda ve kaydı hiç tutulmamış oturumlarda mühür
	 * yok; onları "defteri tam" diye göstermek, hiç yapılmamış bir
	 * kontrolü yapılmış saymak olurdu.
	 */
	Measured bool

	// Events, kaydın mühür satırındaki olay sayısı (internal/sftpcast).
	Events int64

	/*
	 * Digest, mühür satırındaki özet: kayda giren satırların
	 * XOR'lanmış SHA-256'sı, onaltılık.
	 *
	 * ⚠️ SAYININ YANINDA DURUYOR ÇÜNKÜ AYRI BİR SORUYU CEVAPLIYOR.
	 * Sayı "kaç satır" diyor; özet "hangi satırlar" diyor. Sayı tutup
	 * özet tutmuyorsa satır SİLİNMEMİŞ, DEĞİŞTİRİLMİŞ demektir — ve o,
	 * defterden satır silmekten daha ince bir müdahale: silinen satır
	 * en azından bir boşluk bırakıyor, değiştirilen satır tam bir
	 * denetim kaydı gibi duruyor.
	 *
	 * ⚠️ OLAY YOKKEN BOŞ — sıfırların onaltılığı DEĞİL. Mühür satırı
	 * da yazılmıyor; dosyada karşılığı olmayan bir değeri saklamak,
	 * kontrolün "kayıt böyle diyor" dediği şeyi uydurmak olurdu.
	 */
	Digest string

	/*
	 * Lost, postern'in deftere koyamadığını BİLDİĞİ olay sayısı:
	 * tampon taştığı için atılanlar ve kapanışta yazılamamış olarak
	 * elde kalanlar.
	 *
	 * ⚠️ AYRI DURUYOR ÇÜNKÜ AYRI BİR BULGU. Aritmetiği "satırlar
	 * silinmiş" hâliyle aynı (satır sayısı mühürden eksik) ama olayı
	 * bambaşka: biri postern'in kendi arızası, öbürü müdahale.
	 */
	Lost int64

	/*
	 * Denied, POSTERN'İN KENDİ reddettiği istek sayısı — defterdeki
	 * "denied." önekli satırlar (sftpaudit/policy.go).
	 *
	 * ⚠️ HEDEFİN "permission denied"I BURAYA GİRMİYOR. O, hedefin dosya
	 * izinleri hakkında bir şey söylüyor; bu, postern'in kurallarının
	 * çiğnenmeye çalışıldığını. İkisini tek sayıya katlamak, denetçiye
	 * "kural sınandı" ile "kullanıcının o dosyaya erişimi yok"u aynı
	 * rakamla gösterirdi.
	 *
	 * ⚠️ SAYI, DEFTERDEKİ SATIR ADEDİNDEN BÜYÜK OLABİLİR. Ardışık aynı
	 * retler tek satıra katlanıyor ve sayı katlananları da içeriyor:
	 * "kaç satır var" ile "kaç kez denendi" apayrı iki soru, ve
	 * denetçinin sorduğu ikincisi.
	 *
	 * ⚠️ Counted FALSE İKEN SIFIR OKUNMAMALI. Göç 038'den önce kapanmış
	 * oturumlarda sayım yapılmadı; sıfır göstermek "hiçbir şey
	 * reddedilmedi" demek olurdu — Measured'ın aynı gerekçesi.
	 */
	Denied int64

	// Counted, Denied'in gerçekten sayıldığı (göç 038 sonrası).
	Counted bool
}

// Open, oturumun hâlâ sürüp sürmediğini söyler.
func (s Session) Open() bool { return s.EndedAt.IsZero() }

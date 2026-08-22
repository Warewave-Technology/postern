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

	StartedAt time.Time

	// EndedAt sıfır değerse oturum hâlâ açık (şemada NULL).
	EndedAt time.Time

	// RecordingPath, .cast dosyasının yolu. Kayıt açılamadıysa boş —
	// ama o durumda oturum zaten reddedilmiş olmalı (S1.8 kararı).
	RecordingPath string
}

// Open, oturumun hâlâ sürüp sürmediğini söyler.
func (s Session) Open() bool { return s.EndedAt.IsZero() }

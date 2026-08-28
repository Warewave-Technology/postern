package model

import "time"

type Target struct {
	Name    string
	Host    string
	Port    int
	HostKey string

	// Labels, operatörün iliştirdiği key=value notları ("env=prod").
	//
	// ⚠️ YETKİ DEĞİL: erişimi rol → hedef bağı veriyor. Etiket yalnızca
	// hedefleri gruplayıp bulmak için — etiketten yetki türetmek,
	// etiket ekleyebilen herkese yetki dağıtmak olurdu.
	//
	// Yalnızca LİSTELEME yollarında dolu (store.Targets). Oturum açma
	// yolundaki tekil okuma bunu çekmiyor: her bağlantıda ikinci bir
	// sorgu, hiç kullanılmayan bir alan için.
	Labels map[string]string
}

// TargetFacts, hedefe BAĞLANIRKEN öğrenilenler.
//
// ⚠️ Yapılandırma değil GÖZLEM: Target operatörün yazdığını, bu yapı
// makinenin söylediğini tutuyor. Ve içeriği yalnızca el sıkışmadan
// geliyor — hedefte komut çalıştırıp uname/os-release okumak daha
// fazlasını verirdi ama postern kullanıcının oturumu dışında hedefte
// iş çalıştırmaz.
type TargetFacts struct {
	// ServerVersion, sunucunun kendi afişi: "SSH-2.0-OpenSSH_9.6p1 Debian-3".
	ServerVersion string
	// HostKeyType, pinlenmiş anahtarın türü (ssh-ed25519 …).
	HostKeyType string
	// LastSeenAt, son BAŞARILI bağlantı. Sıfır ise hiç bağlanılmadı.
	LastSeenAt time.Time
	// ConnectMS, o bağlantının el sıkışma süresi.
	ConnectMS int
	// LastErrorAt/LastError, son BAŞARISIZ deneme. Başarıyı silmiyor.
	LastErrorAt time.Time
	LastError   string

	// Probe, yalnızca target_probe.enabled ile dolar — yani hedefte
	// komut çalıştırıldıysa. ProbedAt sıfırsa hedefe hiç dokunulmadı.
	//
	// İç içe duruyor ki paneli çizen de, koda bakan da "bu satırı
	// öğrenmek için makineye dokunduk mu" sorusunu tek bakışta
	// cevaplayabilsin.
	Probe    TargetProbe
	ProbedAt time.Time
}

// TargetProbe, hedefte KOMUT ÇALIŞTIRARAK öğrenilenler.
//
// ⚠️ TargetFacts'ten AYRI TUTULUYOR ve bu ayrım kasıtlı: TargetFacts'in
// içeriği el sıkışmadan gelir ve postern hedefte hiçbir şey
// çalıştırmadan öğrenilir. Buradakiler ise ancak target_probe.enabled
// ile, hedefte komut koşturularak elde ediliyor. İkisini aynı yapıya
// koymak, panele bakan operatörün "bunu öğrenmek için makineye
// dokunduk mu" sorusunu cevapsız bırakırdı.
type TargetProbe struct {
	// Kernel, `uname -srm` çıktısı.
	Kernel string
	// OSName, /etc/os-release içindeki PRETTY_NAME (yoksa NAME).
	OSName string
}

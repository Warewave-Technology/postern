package model

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

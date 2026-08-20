package model

// Target, bağlanılabilecek bir makine.
//
// S2'de yalnızca adı gerekiyor (yetki kararı ada bakıyor); bağlantı
// ayrıntıları hâlâ config.TargetConfig'te. S3'te targets tablosu ikisini
// birleştirecek.
type Target struct {
	Name string
}

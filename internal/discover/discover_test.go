package discover

import "testing"

/*
 * ⚠️ ETİKETTEN ROL: ANAHTAR ETİKETİN İÇİNDE.
 *
 * Proxmox etiketleri anahtar/değer çifti DEĞİL, düz dizeler. Operatör
 * bir "anahtar" veriyor ve onu etiketin içinde arıyoruz. İki ayraç da
 * kabul: ikisi de yaygın ve hangisinin kullanıldığını keşif sırasında
 * öğrenmek, kurulumu yeniden etiketlemekten ucuz.
 */
func TestRoleFromTags(t *testing.T) {
	cases := []struct {
		name   string
		tags   []string
		key    string
		want   string
		tagged bool
	}{
		{"esittir", []string{"prod", "role=ops"}, "role", "ops", true},
		{"iki nokta", []string{"role:dba"}, "role", "dba", true},
		{"harf duyarsiz anahtar", []string{"Role=Ops"}, "role", "Ops", true},
		{"bosluklu", []string{" role = ops "}, "role", "ops", true},

		// ⚠️ ETİKETSİZ MAKİNE DÜŞMÜYOR, unknown'a gidiyor: bilmediğimiz
		// makineyi sessizce envanterden çıkarmak, onu gözden kaçırmak
		// demek.
		{"etiket yok", nil, "role", UnknownRole, false},
		{"baska anahtar", []string{"env=prod"}, "role", UnknownRole, false},
		{"anahtar var deger yok", []string{"role="}, "role", UnknownRole, false},

		// Anahtar verilmezse hiçbir etiket rol sayılmıyor.
		{"anahtar bos", []string{"role=ops"}, "", UnknownRole, false},
	}

	for _, c := range cases {
		got, tagged := RoleFromTags(c.tags, c.key)
		if got != c.want || tagged != c.tagged {
			t.Errorf("%s: (%q,%v), beklenen (%q,%v)", c.name, got, tagged, c.want, c.tagged)
		}
	}
}

/*
 * ⚠️ ETİKET GÜVENİLMEYEN GİRDİ.
 *
 * Hipervizöre makine ekleyebilen herkes etiket yazabiliyor ve o değer
 * burada bir ROL ADINA — yani erişim modelinin parçasına — dönüşüyor.
 * Boşluk ya da virgül taşıyan bir ad, liste ayrıştıran her yerde
 * belirsizlik üretir.
 */
func TestValidRoleName(t *testing.T) {
	for _, ok := range []string{"ops", "db-team", "web_01", "a.b", "ROLE1"} {
		if err := ValidRoleName(ok); err != nil {
			t.Errorf("%q reddedildi: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "iki kelime", "a,b", "a/b", "role;drop", "a\nb"} {
		if err := ValidRoleName(bad); err == nil {
			t.Errorf("%q kabul edildi — etiketten gelen bir ad rol adına dönüşüyor", bad)
		}
	}
	long := ""
	for i := 0; i < 65; i++ {
		long += "a"
	}
	if err := ValidRoleName(long); err == nil {
		t.Error("65 karakterlik ad kabul edildi")
	}
}

// Proxmox etiket dizesi üç ayraçla gelebiliyor; tek ayraç varsaymak
// bütün etiketleri TEK etiket gibi okuyup her makineyi unknown'a
// düşürürdü — hiçbir hata vermeden.
func TestSplitTags(t *testing.T) {
	for _, in := range []string{"a;b;c", "a,b,c", "a b c", "a; b , c"} {
		got := splitTags(in)
		if len(got) != 3 || got[0] != "a" || got[2] != "c" {
			t.Errorf("%q -> %v", in, got)
		}
	}
	if got := splitTags(""); len(got) != 0 {
		t.Errorf("boş etiket -> %v", got)
	}
}

/*
 * ⚠️ KULLANILAMAZ ADRESLER ELENİYOR.
 *
 * Konuk aracısı döngü ve bağlantı-yerel adresleri de bildiriyor.
 * Bunları hedefe yazmak, bastion'dan asla bağlanamayacak bir hedef
 * bırakır — ve "neden bağlanmıyor" sorusunun cevabı envanterin
 * içinde saklı kalır.
 */
func TestUsableIP(t *testing.T) {
	for _, bad := range []string{"127.0.0.1", "::1", "169.254.1.5", "0.0.0.0", "", "yok"} {
		if got := usableIP(bad); got != "" {
			t.Errorf("%q kabul edildi: %q", bad, got)
		}
	}
	if got := usableIP("10.0.0.5"); got != "10.0.0.5" {
		t.Errorf("geçerli adres reddedildi: %q", got)
	}
}

// Rapor sırası: önce ATLANANLAR. Operatörün bakması gereken satırlar
// onlar; başarılı yüz satırın altına gömülen bir atlama görülmez.
func TestSortOutcomesPutsSkippedFirst(t *testing.T) {
	in := []Outcome{
		{Machine: Machine{Name: "b"}, Role: "ops"},
		{Machine: Machine{Name: "a"}, Role: "ops", Skipped: "no host key"},
		{Machine: Machine{Name: "c"}, Role: "dba"},
	}
	SortOutcomes(in)
	if in[0].Machine.Name != "a" {
		t.Fatalf("atlanan ilk sırada değil: %+v", in[0])
	}
}

/*
 * ⚠️ PROXMOX ETİKETLERİ "anahtar=değer" YAZAMAZ.
 *
 * ÖLÇÜLEN ARIZA: Proxmox etiket karakter kümesi [a-z0-9_.+-] ile sınırlı
 * (pve-common'daki `pve-tag` biçimi), yani `=` ve `:` bir etikete hiç
 * yazılamıyor. Yalnızca o ikisini tanıyan eski kod, gerçek bir Proxmox
 * kurulumunda HER makineyi sessizce `unknown` rolüne düşürüyordu —
 * hata yok, uyarı yok, sadece hiçbir makinenin rolü yok. Kullanıcının
 * bildirdiği durum tam olarak buydu.
 */
func TestProxmoxStyleUnderscoreTags(t *testing.T) {
	cases := []struct {
		name   string
		tags   []string
		key    string
		want   string
		tagged bool
	}{
		{
			// Sahadan gelen tam biçim.
			name:   "anahtarda tire, değerde tire",
			tags:   []string{"role-name_os-admins"},
			key:    "role-name",
			want:   "os-admins",
			tagged: true,
		},
		{
			name:   "sade",
			tags:   []string{"role_web"},
			key:    "role",
			want:   "web",
			tagged: true,
		},
		{
			/*
			 * ⚠️ ANAHTARIN İÇİNDE ALT ÇİZGİ.
			 *
			 * "İlk ayırıcıda böl" yaklaşımı burada anahtarı "role"
			 * sanar, eşleşmez ve makine unknown'a düşer. Yani alt
			 * çizgiyi ayırıcı listesine EKLEMEK tek başına yetmiyor;
			 * eşleşmenin ön ek üzerinden olması gerekiyor.
			 */
			name:   "anahtarın içinde alt çizgi",
			tags:   []string{"role_name_os-admins"},
			key:    "role_name",
			want:   "os-admins",
			tagged: true,
		},
		{
			// Değerin içinde alt çizgi: geriye kalan her şey değerdir.
			name:   "değerin içinde alt çizgi",
			tags:   []string{"role_web_prod"},
			key:    "role",
			want:   "web_prod",
			tagged: true,
		},
		{
			// Proxmox etiketleri küçük harfe normalleştirebiliyor.
			name:   "anahtar büyük/küçük harf duyarsız",
			tags:   []string{"ROLE_web"},
			key:    "role",
			want:   "web",
			tagged: true,
		},
		{
			// vSphere yolu BOZULMAMALI: orada `=` yazılabiliyor.
			name:   "vsphere kategori=etiket",
			tags:   []string{"role=db"},
			key:    "role",
			want:   "db",
			tagged: true,
		},
		{
			/*
			 * ⚠️ BENZER AMA FARKLI ANAHTAR EŞLEŞMEMELİ. Ön ek
			 * karşılaştırması ayırıcıyı da içeriyor, yoksa "role"
			 * anahtarı "roles_web" etiketini de yakalardı ve makine
			 * yanlış role girerdi.
			 */
			name:   "anahtar önekmiş gibi görünen başka etiket",
			tags:   []string{"roles_web"},
			key:    "role",
			want:   UnknownRole,
			tagged: false,
		},
		{
			// Değeri boş etiket rol değildir.
			name:   "değer yok",
			tags:   []string{"role_"},
			key:    "role",
			want:   UnknownRole,
			tagged: false,
		},
		{
			// Rolü olmayan sıradan etiketler makineyi etkilememeli.
			name:   "ilgisiz etiketler",
			tags:   []string{"production", "linux", "backup_daily"},
			key:    "role",
			want:   UnknownRole,
			tagged: false,
		},
		{
			// Birden çok etiket arasından doğru olanı seçmeli.
			name:   "etiket yığını içinden",
			tags:   []string{"production", "role-name_os-admins", "linux"},
			key:    "role-name",
			want:   "os-admins",
			tagged: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, tagged := RoleFromTags(c.tags, c.key)
			if got != c.want || tagged != c.tagged {
				t.Errorf("RoleFromTags(%q, %q) = (%q, %v), beklenen (%q, %v)",
					c.tags, c.key, got, tagged, c.want, c.tagged)
			}
		})
	}
}

// Etiketten gelen değer rol adı kuralına uymalı: alt çizgili ve tireli
// adlar geçerli, yoksa düzeltme işe yaramaz.
func TestUnderscoreRoleNamesAreValid(t *testing.T) {
	for _, name := range []string{"os-admins", "web_prod", "db.replica"} {
		if err := ValidRoleName(name); err != nil {
			t.Errorf("ValidRoleName(%q) = %v — etiketten gelen ad reddediliyor", name, err)
		}
	}
}

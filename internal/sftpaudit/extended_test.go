package sftpaudit

import "testing"

/*
 * ⚠️ GERÇEK DÜNYADAKİ YENİDEN ADLANDIRMA SSH_FXP_RENAME DEĞİL.
 *
 * ÖLÇÜLEN ARIZA: bu dal hiç yoktu ve yeniden adlandırmalar denetim
 * defterine DÜŞMÜYORDU. OpenSSH'in kendi sftp istemcisi, sunucu
 * eklentiyi ilan ettiğinde "posix-rename@openssh.com" gönderiyor —
 * yani pratikte her rename. Demoda ölçüldü: `rename a b` hedefte
 * çalıştı, session_files boş kaldı.
 *
 * Kanıt tel biçiminden kuruluyor: kod SSH_FXP_RENAME'i işlemeye devam
 * etse bile bu test, EKLENTİ yolunu kapsamadıkça geçmez.
 */
func TestPosixRenameIsRecorded(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpExtended).u32(7).
		str("posix-rename@openssh.com").
		str("/home/u/eski.txt").str("/home/u/yeni.txt").bytes())
	feedTarget(t, s, statusOK(7))

	if len(*got) != 1 {
		t.Fatalf("olay sayısı = %d, 1 bekleniyordu: %+v", len(*got), *got)
	}
	e := (*got)[0]
	if e.Op != OpRename {
		t.Errorf("Op = %q, %q bekleniyordu", e.Op, OpRename)
	}
	if e.Path != "/home/u/eski.txt" || e.NewPath != "/home/u/yeni.txt" {
		t.Errorf("yollar = %q -> %q", e.Path, e.NewPath)
	}
	if !e.OK {
		t.Error("başarılı rename başarısız yazılmış")
	}
}

// Sert bağ, dosyaya İKİNCİ BİR AD veriyor: silinen bir dosyanın
// içeriğinin başka bir yerde yaşamaya devam etmesi denetimin görmesi
// gereken bir olay.
func TestHardlinkIsRecorded(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpExtended).u32(3).
		str("hardlink@openssh.com").
		str("/srv/gizli.db").str("/tmp/kopya").bytes())
	feedTarget(t, s, statusOK(3))

	if len(*got) != 1 || (*got)[0].Op != OpLink {
		t.Fatalf("sert bağ kaydedilmedi: %+v", *got)
	}
	if (*got)[0].NewPath != "/tmp/kopya" {
		t.Errorf("ikinci yol = %q", (*got)[0].NewPath)
	}
}

// Reddedilen eklenti isteği de KANIT: denemeyi görmek, engelin
// çalıştığını görmektir.
func TestRefusedPosixRenameIsKept(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpExtended).u32(9).
		str("posix-rename@openssh.com").
		str("/etc/passwd").str("/tmp/x").bytes())
	feedTarget(t, s, statusErr(9, 3, "Permission denied"))

	if len(*got) != 1 {
		t.Fatalf("olay sayısı = %d: %+v", len(*got), *got)
	}
	if (*got)[0].OK {
		t.Error("reddedilen rename başarılı yazılmış")
	}
	if (*got)[0].Detail != "Permission denied" {
		t.Errorf("detail = %q", (*got)[0].Detail)
	}
}

/*
 * ⚠️ TANIMADIĞIMIZ EKLENTİ SESSİZCE GEÇMEMELİ.
 *
 * Arızanın asıl dersi buydu: adını bilmediğimiz bir eklenti dosyayı
 * taşıyabiliyor ve defter boş kalabiliyordu. Yarın eklenen bir eklenti
 * önceden onaylanmış olmamalı — varsayılan ret, sessiz geçiş değil.
 */
func TestUnknownExtensionIsStillRecorded(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpExtended).u32(11).
		str("copy-data").str("handle-1").bytes())
	feedTarget(t, s, statusOK(11))

	if len(*got) != 1 {
		t.Fatalf("bilinmeyen eklenti sessizce geçti: %+v", *got)
	}
	e := (*got)[0]
	if e.Op != OpExtended {
		t.Errorf("Op = %q, %q bekleniyordu", e.Op, OpExtended)
	}
	// Adı olmadan satır işe yaramaz: operatör neye baktığını bilemez.
	if e.Detail != "copy-data" {
		t.Errorf("detail eklenti adını taşımıyor: %q", e.Detail)
	}
}

// Zararsız üstveri eklentileri satır ÜRETMEMELİ: her fsync için bir
// denetim satırı, defteri okunmaz yapardı (stat/readdir ile aynı karar).
func TestQuietExtensionsProduceNoRow(t *testing.T) {
	s, got := collect(t)

	feedClient(t, s, newPkt(fxpExtended).u32(21).str("fsync@openssh.com").str("h1").bytes())
	feedTarget(t, s, statusOK(21))
	feedClient(t, s, newPkt(fxpExtended).u32(22).str("statvfs@openssh.com").str("/").bytes())
	feedTarget(t, s, statusOK(22))

	if len(*got) != 0 {
		t.Fatalf("sessiz eklentiler satır üretti: %+v", *got)
	}
}

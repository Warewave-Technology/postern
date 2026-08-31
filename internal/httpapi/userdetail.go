package httpapi

import (
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

/*
 * Kullanıcı detay ekranı.
 *
 * ⚠️ NEDEN VAR: liste dokuz sütuna çıkmıştı ve her satırda üç ayrı
 * eylem taşıyordu — rol atama kutusu, aktifleştirme, anahtar paneli,
 * sıfırlama, silme. Bir liste "kimler var ve durumları ne" sorusunu
 * cevaplamalı; tek bir kişi üzerinde yapılacak işler o kişinin
 * sayfasına ait. Hedef ekranında aynı karar zaten verilmişti
 * (TargetDetail); burası onun eşi.
 */

// adminUserDetail: GET /api/admin/users/{name}
func (s *Server) adminUserDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	u, err := s.store.User(r.Context(), name)
	if err != nil {
		s.storeErr(w, "user.detail", err)
		return
	}
	p, err := s.store.UserProfile(r.Context(), name)
	if err != nil {
		s.storeErr(w, "user.detail", err)
		return
	}
	/*
	 * ⚠️ ADI SERBEST BIRAKILMIŞ SATIR "YOK" SAYILIYOR.
	 *
	 * store.Users listesi purged_at dolu satırları zaten gizliyor; bu
	 * uç göstermeye devam etseydi, aynı ürün aynı hesap için iki farklı
	 * cevap verirdi. Üstelik o sayfadaki her eylem anlamsız: adı artık
	 * bu kişiye ait değil, satır yalnızca denetim kaydının okunabilir
	 * kalması için duruyor.
	 */
	if p.Purged {
		writeErr(w, http.StatusNotFound, "no such user")
		return
	}

	type roleRow struct {
		Name    string   `json:"name"`
		Targets []string `json:"targets"`
	}
	roles := make([]roleRow, 0, len(u.Roles))
	for _, ro := range u.Roles {
		roles = append(roles, roleRow{Name: ro.Name, Targets: ro.Targets})
	}

	/*
	 * ⚠️ ANAHTARLAR PARMAK İZİYLE LİSTELENİYOR.
	 *
	 * Panel eskiden yalnızca bir SAYI gösteriyordu ve silmek için
	 * yöneticiden anahtarın METNİNİ yapıştırmasını istiyordu — yani
	 * "şu anahtarı kaldır" demek için önce onu başka bir yerden bulmak
	 * gerekiyordu. Açık anahtar zaten açık; parmak izini göstermemenin
	 * koruduğu bir şey yok, maliyeti ise yapılamayan bir iş.
	 *
	 * Blob'un KENDİSİ yine dönmüyor: gösterilecek bir faydası yok ve
	 * dönen her bayt, saklanmasına gerek olmayan bir bayt.
	 */
	keys, err := s.store.PublicKeys(r.Context(), name)
	if err != nil {
		s.storeErr(w, "user.detail", err)
		return
	}
	type keyRow struct {
		Fingerprint string `json:"fingerprint"`
		Comment     string `json:"comment"`
		AddedAt     string `json:"added_at"`
	}
	keyRows := make([]keyRow, 0, len(keys))
	for _, k := range keys {
		pub, perr := ssh.ParsePublicKey(k.Blob)
		if perr != nil {
			// Saklanmış bozuk bir kayıt sayfayı düşürmemeli.
			s.logger.Error("stored key unparseable", "user", name, "error", perr)
			continue
		}
		keyRows = append(keyRows, keyRow{
			Fingerprint: ssh.FingerprintSHA256(pub),
			Comment:     k.Comment,
			AddedAt:     k.AddedAt.UTC().Format(time.RFC3339),
		})
	}

	// Son oturumlar: "bu hesap gerçekten kullanılıyor mu" sorusu, bir
	// hesabı silmeden önce sorulacak ilk soru.
	sessions, err := s.store.Sessions(r.Context(), name, 10)
	if err != nil {
		s.storeErr(w, "user.detail", err)
		return
	}
	type sessRow struct {
		ID      string `json:"id"`
		Target  string `json:"target"`
		Started string `json:"started"`
		Ended   string `json:"ended,omitempty"`
	}
	sessRows := make([]sessRow, 0, len(sessions))
	for _, se := range sessions {
		row := sessRow{ID: se.ID, Target: se.Target,
			Started: se.StartedAt.UTC().Format(time.RFC3339)}
		if !se.EndedAt.IsZero() {
			row.Ended = se.EndedAt.UTC().Format(time.RFC3339)
		}
		sessRows = append(sessRows, row)
	}

	out := map[string]any{
		"name":    u.Name,
		"os_user": u.OSUser,
		"email":   p.Email,
		"admin":   u.Admin,
		/*
		 * ⚠️ YÖNETİCİLİĞİN KAYNAĞI DA GİDİYOR.
		 *
		 * Panel "kim yönetici" sorusuna cevap verirken "bunu kim verdi"
		 * sorusunu da cevaplamak zorunda: grup üzerinden gelen yetki ile
		 * acil durum için elle açılmış hesap ekranda ayırt edilemezse,
		 * operatör kaldıramayacağı bir yetkiyi kaldırabileceğini sanır.
		 */
		"admin_via": p.AdminVia,
		"state":     p.State,
		"sso_only":  u.SSOOnly,
		"dir_bound": u.DirBound,
		"roles":     roles,
		"keys":      keyRows,
		"sessions":  sessRows,
	}
	if !p.Confirmed.IsZero() {
		out["last_confirmed"] = p.Confirmed.Format(time.RFC3339)
	}
	if p.HasCredential {
		/*
		 * Kimlik bilgisinin TÜRÜ bir teşhis aracı: "neden giremiyor"
		 * sorusunun cevabı çoğu zaman burada. must_change taşıyan bir
		 * hesap giriyor ama paneli açamıyor — önce parolasını koyması
		 * gerekiyor.
		 */
		kind := "secret"
		switch {
		case p.CredChosen:
			kind = "password"
		case p.CredMustChange:
			kind = "issued"
		}
		cred := map[string]any{
			"kind":        kind,
			"must_change": p.CredMustChange,
			"created_at":  p.CredCreatedAt.Format(time.RFC3339),
			"created_by":  p.CredCreatedBy,
		}
		if !p.CredLastUsed.IsZero() {
			cred["last_used_at"] = p.CredLastUsed.Format(time.RFC3339)
		}
		out["credential"] = cred
	}

	writeJSON(w, http.StatusOK, out)
}

// removeKeyBlob, silinecek anahtarı METİN ya da PARMAK İZİ ile bulur.
//
// ⚠️ PARMAK İZİ EKLENDİ ve metin yolu DURUYOR. Detay ekranı artık
// anahtarları parmak izleriyle listeliyor, dolayısıyla "şunu kaldır"
// demenin doğal yolu o. Metin yolunu kaldırmak ise elindeki anahtarla
// çalışan operatörü ve mevcut betikleri kırardı — ikisi de aynı işi
// yapıyor, biri artık kullanışlı.
func (s *Server) removeKeyBlob(w http.ResponseWriter, r *http.Request,
	name, authorizedKey, fingerprint string) ([]byte, bool) {

	if authorizedKey != "" {
		pub, _, okKey := parseAuthorizedKey(w, authorizedKey)
		if !okKey {
			return nil, false
		}
		return pub.Marshal(), true
	}
	if fingerprint == "" {
		writeErr(w, http.StatusBadRequest, "give the key text or its fingerprint")
		return nil, false
	}

	keys, err := s.store.PublicKeys(r.Context(), name)
	if err != nil {
		s.storeErr(w, "user.remove_key", err)
		return nil, false
	}
	for _, k := range keys {
		pub, perr := ssh.ParsePublicKey(k.Blob)
		if perr != nil {
			continue
		}
		if ssh.FingerprintSHA256(pub) == fingerprint {
			return k.Blob, true
		}
	}
	writeErr(w, http.StatusNotFound, "this account has no key with that fingerprint")
	return nil, false
}

package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Warewave-Technology/postern/internal/archive"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * Arşiv kimliğinin panelden yönetimi.
 *
 * ⚠️ KENDİ UCU VAR, genel PUT /api/admin/settings DEĞİL — ve gerekçesi
 * ölçülmüş: oradaki sınıflandırma FAIL-OPEN. federation.go:210
 * `isSecret := ldap.SecretKeys[in.Key]` diyor; haritada olmayan bir
 * anahtar sessizce `false` alıyor ve DÜZ METİN olarak, 200 cevabıyla
 * saklanıyor. Yükleme sırrının o yoldan geçmesi, mühürlemenin tamamını
 * bir harita girdisinin varlığına bağlamak olurdu.
 *
 * ⚠️ HEDEF BURADA YOK. endpoint, bucket, region, prefix, ca_file
 * config dosyasında ve panelden değiştirilemiyor. Sebebi
 * archive/settings.go'da yazılı: hedefi seçebilen bir panel oturumu,
 * bundan sonraki her oturum kaydını başka bir kovaya yönlendirebilirdi
 * — ve bu, "hedef değişirse sırrı düşür" ile kapanmıyor.
 */

// registerArchiveRoutes, arşiv kimliği uçlarını bağlar.
func (s *Server) registerArchiveRoutes(mux *http.ServeMux, admin func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/admin/archive", admin(s.adminArchiveStatus))
	mux.Handle("PUT /api/admin/archive/credential", admin(s.adminSetArchiveCredential))
	mux.Handle("DELETE /api/admin/archive/credential", admin(s.adminClearArchiveCredential))
}

/*
 * adminArchiveStatus: GET /api/admin/archive
 *
 * ⚠️ SIR GERİ OKUNMUYOR. Yalnızca "var mı" ve "nereden geliyor"
 * dönüyor. Maskeli bir değer döndürmek bile gereksiz bir sızıntı
 * yüzeyi olurdu; panelin ihtiyacı alanı doğru çizmek, değeri
 * göstermek değil.
 */
func (s *Server) adminArchiveStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"configured": s.archiveDest.Endpoint != "",
		"endpoint":   s.archiveDest.Endpoint,
		"bucket":     s.archiveDest.Bucket,
		"prefix":     s.archiveDest.Prefix,
		/*
		 * ⚠️ HEDEFİN PANELDEN DEĞİŞTİRİLEMEDİĞİ AÇIKÇA SÖYLENİYOR.
		 * Salt okunur bir alanı sebepsiz göstermek, operatöre
		 * "değiştirebilirim ama çalışmıyor" dedirtirdi.
		 */
		"destination_managed_in": "config file",
	}

	creds, source, err := archive.Credentials(r.Context(), s.store,
		s.archiveDest.AccessKeyID, s.archiveHostSecret)
	if err != nil {
		s.storeErr(w, "archive.status", err)
		return
	}
	out["credential_source"] = string(source)
	out["access_key_id"] = creds.AccessKeyID
	out["can_set_from_panel"] = source != archive.FromHost

	writeJSON(w, http.StatusOK, out)
}

/*
 * adminSetArchiveCredential: PUT /api/admin/archive/credential
 *
 * ⚠️ HOST DOSYASI VARSA REDDEDİLİYOR, sessizce yok sayılmıyor.
 * Kaydedilip yürürlüğe girmeyen bir ayar, bu depodaki en tanıdık
 * arıza: ekran "oldu" der, hiçbir şey olmaz.
 */
func (s *Server) adminSetArchiveCredential(w http.ResponseWriter, r *http.Request) {
	if s.archiveDest.Endpoint == "" {
		writeErr(w, http.StatusConflict,
			"this bastion has no archive destination configured; "+
				"set recording.archive.endpoint and bucket in the config file first")
		return
	}
	if s.archiveHostSecret != "" {
		writeErr(w, http.StatusConflict,
			"this bastion takes its archive key from the host "+
				"(recording.archive.secret_key_file or POSTERN_ARCHIVE_SECRET_KEY); "+
				"change it there, not here")
		return
	}

	var in struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.AccessKeyID = strings.TrimSpace(in.AccessKeyID)
	in.SecretAccessKey = strings.TrimSpace(in.SecretAccessKey)

	// ⚠️ YARIM KİMLİK KABUL EDİLMİYOR: biri boş bırakılırsa yükleme
	// başlamıyor ve sebebi hiçbir ekranda yazmıyordu.
	if in.AccessKeyID == "" || in.SecretAccessKey == "" {
		writeErr(w, http.StatusBadRequest,
			"both access_key_id and secret_access_key are required")
		return
	}

	if err := s.store.SetSetting(r.Context(), archive.KeyAccessKeyID,
		in.AccessKeyID, false, sessionUser(r)); err != nil {
		s.storeErr(w, "archive.credential", err)
		return
	}
	// ⚠️ MÜHÜRLÜ: encrypted=true. Mühür anahtarı yoksa SetSetting
	// hata veriyor ve buraya düşüyor — sır düz metne DÜŞMÜYOR.
	if err := s.store.SetSetting(r.Context(), archive.KeySecretAccessKey,
		in.SecretAccessKey, true, sessionUser(r)); err != nil {
		s.storeErr(w, "archive.credential", err)
		return
	}

	s.audit(r, "archive.credential_set", s.archiveDest.Bucket,
		"access key "+in.AccessKeyID)
	s.logger.Warn("archive credential changed from the panel",
		"actor", sessionUser(r), "bucket", s.archiveDest.Bucket,
		"access_key_id", in.AccessKeyID)
	ok(w)
}

// adminClearArchiveCredential: DELETE /api/admin/archive/credential
//
// Yükleme durur ve yüklenmemiş kayıtlar budanmaz — yani kanıt kaybı
// yok, disk baskısı var. Cevap bunu söylüyor.
func (s *Server) adminClearArchiveCredential(w http.ResponseWriter, r *http.Request) {
	if s.archiveHostSecret != "" {
		writeErr(w, http.StatusConflict,
			"this bastion takes its archive key from the host; clear it there")
		return
	}
	for _, k := range []string{archive.KeySecretAccessKey, archive.KeyAccessKeyID} {
		if err := s.store.DeleteSetting(r.Context(), k); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			s.storeErr(w, "archive.credential", err)
			return
		}
	}
	s.audit(r, "archive.credential_cleared", s.archiveDest.Bucket, "")
	s.logger.Warn("archive credential cleared from the panel; "+
		"uploads have stopped and unarchived recordings will not be pruned",
		"actor", sessionUser(r))
	ok(w)
}

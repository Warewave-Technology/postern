package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"time"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
)

// endedAt, bitmemiş oturum için nil döner — adminListSessions ile aynı
// şekil, panel iki ucu aynı tipe bağlayabilsin diye.
func endedAt(sess model.Session) *string {
	if sess.Open() {
		return nil
	}
	e := sess.EndedAt.Format(time.RFC3339)
	return &e
}

// Oturum kaydının panelden izlenmesi.
//
// Kayıtlar S1.7'den beri yazılıyordu ama hiçbir yerden okunamıyordu:
// denetim dosyası vardı, denetim YOKTU. Buradaki iki uç o boşluğu
// kapatıyor.

// recordingState, bir oturumun kaydının durumu.
//
// Dört ayrı durum çünkü panelde dördü farklı şey söylüyor ve üçünü
// "kayıt yok" diye birleştirmek operatörü yanıltırdı.
const (
	// recNone: oturumun kaydı hiç açılmamış.
	recNone = "none"
	// recMissing: yol var ama dosya yok — silinmiş, taşınmış ya da
	// recording.dir değişmiş.
	recMissing = "missing"
	// recPartial: oturum HÂLÂ SÜRÜYOR, dosya büyümeye devam ediyor.
	recPartial = "partial"
	// recComplete: oturum bitti, kayıt tam.
	recComplete = "complete"
	/*
	 * recArchived: yerel dosya yok AMA kayıt nesne deposunda.
	 *
	 * ⚠️ recMissing'DEN AYRI TUTULUYOR. "missing" panelde "saklama
	 * politikası sildi ya da postern dışında silindi" diye
	 * gösteriliyor; arşivlenmiş bir kayıt için bu cümle YANLIŞ olurdu
	 * ve denetçi var olan bir kaydı kayıp sanırdı.
	 *
	 * ⚠️ DOSYANIN YOKLUĞUNDAN ÇIKARILMIYOR: arşiv satırından
	 * okunuyor. Yoklukla çıkarım yapmak, yüklenmemiş ama elle silinmiş
	 * bir kaydı "güvende" göstermek olurdu.
	 */
	recArchived = "archived"
)

// UseRecordings, kayıt deposunu bağlar ve kayıt uçlarını açar.
//
// Çağrılmazsa rotalar HİÇ KURULMAZ — kapalı özellik, kapalı yüzey.
// Web terminalindeki aynı kalıp (bkz. EnableTerminal).
func (s *Server) UseRecordings(rec *record.Store) { s.records = rec }

// registerRecordingRoutes, kayıt uçlarını kurar.
func (s *Server) registerRecordingRoutes(mux *http.ServeMux, admin func(http.HandlerFunc) http.Handler) {
	if s.records == nil {
		return
	}
	mux.Handle("GET /api/admin/sessions/{id}", admin(s.adminSessionDetail))
	mux.Handle("GET /api/admin/sessions/{id}/recording", admin(s.adminSessionRecording))
}

// sessionRecording, oturumun kaydını açar ve durumunu sınıflandırır.
//
// Dosyayı AÇIK döner: çağıran ya kapatır ya okur.
func (s *Server) sessionRecording(sess model.Session) (*os.File, string, int64, error) {
	f, err := s.records.Open(sess.ID, sess.RecordingPath)
	switch {
	case errors.Is(err, record.ErrNotRecorded):
		return nil, recNone, 0, nil

	case errors.Is(err, record.ErrOutsideRoot):
		// Bu bir reddetme, "bulunamadı" değil — ve SESSİZ KALMAMALI.
		// Kayıt kökünü değiştiren bir operatör aksi hâlde "eski
		// kayıtlar 404 veriyor" diye sebepsiz bir semptom görür.
		s.logger.Error("recording refused: stored path is outside the recordings root",
			"session", sess.ID, "stored_path", sess.RecordingPath, "root", s.records.Root())
		return nil, recMissing, 0, nil

	case errors.Is(err, os.ErrNotExist):
		/*
		 * Dosya yok. Arşiv defteri "yüklendi" diyorsa bu bir kayıp
		 * değil, bir TAŞINMA — ve panel ikisini karıştırmamalı.
		 */
		if st, found, aerr := s.store.ArchiveStateOf(context.Background(), sess.ID); aerr == nil &&
			found && st.Archived {
			return nil, recArchived, st.SizeBytes, nil
		}
		return nil, recMissing, 0, nil

	case err != nil:
		return nil, "", 0, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, "", 0, err
	}

	state := recComplete
	if sess.Open() {
		state = recPartial
	}
	return f, state, info.Size(), nil
}

// adminSessionDetail: GET /api/admin/sessions/{id}
func (s *Server) adminSessionDetail(w http.ResponseWriter, r *http.Request) {
	sess, err := s.store.Session(r.Context(), r.PathValue("id"))
	if err != nil {
		s.storeErr(w, "sessions.detail", err)
		return
	}

	f, state, size, err := s.sessionRecording(sess)
	if err != nil {
		s.logger.Error("recording stat failed", "session", sess.ID, "error", err)
		http.Error(w, "recording unavailable", http.StatusInternalServerError)
		return
	}
	if f != nil {
		f.Close()
	}

	/*
	 * ⚠️ DOSYA OLAYLARI DETAYIN PARÇASI, AYRI BİR UÇ NOKTA DEĞİL.
	 *
	 * SFTP oturumunun terminal kaydı BOŞTUR — protokol ham ikili aktığı
	 * için kayda hiç yazılmıyor (bkz. proxy/sftp.go). Dosya olayları
	 * ayrı bir yerde dursaydı, denetçi boş bir oynatıcı görüp "bu
	 * oturumda bir şey olmamış" sonucuna varırdı. Oysa tam da o oturumda
	 * dosya taşınmış olabilir.
	 *
	 * Okunamamaları oturum detayını düşürmüyor ama SESSİZ de geçmiyor:
	 * boş liste "dosyaya dokunulmadı" demek, "bakamadık" demek değil.
	 */
	files, ferr := s.store.SessionFiles(r.Context(), sess.ID)
	if ferr != nil {
		s.logger.Error("session file events unavailable",
			"session", sess.ID, "error", ferr)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         sess.ID,
		"user":       sess.User,
		"target":     sess.Target,
		"os_user":    sess.OSUser,
		"src_ip":     sess.SrcIP,
		"started_at": sess.StartedAt.Format(time.RFC3339),
		"ended_at":   endedAt(sess),
		"recording":  recordingBlock(r, s, sess, state, size),
		"files":      files,
		// files_error, "dokunulmadı" ile "bakamadık"ı ayırıyor.
		"files_error": ferr != nil,
	})
}

/*
 * recordingBlock, panelin kayıt bölümünü kurar.
 *
 * ⚠️ ARŞİVLENMİŞ KAYITTA NESNENİN YERİ DE DÖNÜYOR — ve bu, 1.0'da
 * panelin nesne deposundan OKUMAMASININ karşılığı. Denetçi kaydı
 * kendi kimliğiyle oradan alıyor; bastion'a bir okuma kimliği koymak,
 * bütün arşivi tek bir ele geçirmeyle dışarı çıkarılabilir yapardı.
 */
func recordingBlock(r *http.Request, s *Server, sess model.Session, state string, size int64) map[string]any {
	out := map[string]any{"state": state, "size": size}
	if state != recArchived {
		return out
	}
	st, found, err := s.store.ArchiveStateOf(r.Context(), sess.ID)
	if err != nil || !found {
		return out
	}
	out["archive"] = map[string]any{
		"bucket":      st.Bucket,
		"object_key":  st.ObjectKey,
		"sha256":      st.SHA256,
		"archived_at": st.ArchivedAt.Format(time.RFC3339),
	}
	return out
}

// adminSessionRecording: GET /api/admin/sessions/{id}/recording
//
// Kaydın kendisini döner (asciicast v2, NDJSON).
func (s *Server) adminSessionRecording(w http.ResponseWriter, r *http.Request) {
	sess, err := s.store.Session(r.Context(), r.PathValue("id"))
	if err != nil {
		s.storeErr(w, "sessions.detail", err)
		return
	}

	f, state, size, err := s.sessionRecording(sess)
	if err != nil {
		s.logger.Error("recording open failed", "session", sess.ID, "error", err)
		http.Error(w, "recording unavailable", http.StatusInternalServerError)
		return
	}
	if f == nil {
		http.Error(w, "no recording for this session", http.StatusNotFound)
		return
	}
	defer f.Close()

	// ⚠️ DENETİM KAYDI BAYTLARDAN ÖNCE. Bir oturumu kimin izlediği de
	// denetlenmesi gereken bir olay: kayıtlar başkalarının yazdığı
	// komutları ve çıktılarını içeriyor. Denetim satırı yazılamazsa
	// KAYIT DA VERİLMEZ — izi tutulamayan bir okuma yapılmamalıdır.
	if err := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor:   sessionUser(r),
		Via:     "web",
		Action:  "session.replay",
		Entity:  sess.ID,
		Details: fmt.Sprintf("user %s target %s", sess.User, sess.Target),
	}); err != nil {
		s.logger.Error("replay audit write failed", "session", sess.ID, "error", err)
		http.Error(w, "audit write failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Recording-State", state)

	// SÜREN oturumda yalnızca SON SATIR SONUNA kadar servis et.
	//
	// Kayıt dosyasına başka bir goroutine tamponsuz yazıyor; okuyucu
	// satırın ortasına düşebilir ve ayrıştırıcıya yarım bir JSON dizisi
	// gitmiş olur. Kaydedicinin bekleyen UTF-8 kuyruğu (≤3 bayt) da
	// henüz yazılmamış olabilir.
	if state == recPartial {
		if cut := lastNewline(f, size); cut > 0 {
			io.Copy(w, io.NewSectionReader(f, 0, cut))
			return
		}
		return
	}

	io.Copy(w, f)
}

// lastNewline, size'a kadar olan son '\n' konumunu (dahil) döner.
func lastNewline(f *os.File, size int64) int64 {
	const window = 8192

	for end := size; end > 0; {
		start := end - window
		if start < 0 {
			start = 0
		}

		buf := make([]byte, end-start)
		if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
			return 0
		}

		for i := len(buf) - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				return start + int64(i) + 1
			}
		}
		end = start
	}
	return 0
}

package httpapi

import (
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

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         sess.ID,
		"user":       sess.User,
		"target":     sess.Target,
		"os_user":    sess.OSUser,
		"src_ip":     sess.SrcIP,
		"started_at": sess.StartedAt.Format(time.RFC3339),
		"ended_at":   endedAt(sess),
		"recording":  map[string]any{"state": state, "size": size},
	})
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

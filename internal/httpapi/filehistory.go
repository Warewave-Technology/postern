package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * "Bu dosyaya kim dokundu" — soruşturmanın ucu.
 *
 * ⚠️ NEDEN AYRI BİR UÇ: panelde yalnızca TERS yön vardı. Oturum
 * detayının `files` bloğu "bu oturum hangi dosyalara dokundu"yu
 * cevaplıyor; soruşturmanın elinde ise oturum değil YOL oluyor. Depoda
 * doğru sorgu ilk günden duruyordu (store.FileHistory) ama hiçbir
 * yerden çağrılmıyordu: SFTP denetimini yazma gerekçesi olan sorunun
 * cevabı, yazılmış ve ulaşılamaz hâlde bekliyordu.
 *
 * ⚠️ YALNIZCA ADMIN. Bir yolun geçmişi, BAŞKALARININ ne yaptığını
 * gösteriyor; kendi oturumunu görebilen bir kullanıcıya bunu açmak,
 * dosya adlarıyla başkalarının işini taramaya izin vermek olurdu.
 *
 * ⚠️ DEFTERE YAZILMIYOR ve bu bir tercih: bu API'de admin_log
 * DEĞİŞİKLİKLERİ tutuyor, okumaları değil (oturum detayı da, kayıt
 * izleme de yazmıyor). Aramayı tek başına deftere yazmak, defteri iki
 * farklı şeyin karışımı hâline getirirdi.
 */

// registerFileRoutes, dosya geçmişi ucunu bağlar.
func (s *Server) registerFileRoutes(mux *http.ServeMux, admin func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/admin/files", admin(s.adminFileHistory))
}

/*
 * adminFileHistory: GET /api/admin/files?path=…&limit=…
 *
 * ⚠️ ÖLÇÜTSÜZ İSTEK 400 — BOŞ LİSTE DEĞİL. Boş bir aramayı "sonuç yok"
 * diye cevaplamak, denetçiye aradığı dosyaya dokunulmadığını söylemek
 * olurdu; oysa henüz hiçbir şey aranmadı. İkisi aynı ekrana çıkamaz.
 *
 * ⚠️ YOL TEK BAŞINA ZORUNLU DEĞİL. "ayse ne aldı" ve "web01'de ne oldu"
 * kendi başına sorular; bir yol aramasının süzgeci olarak sorulamazlar,
 * çünkü hangi dosyaya bakacağını bilmiyorsun — zaten onu arıyorsun.
 */
func (s *Server) adminFileHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := store.FileQuery{
		Path:   strings.TrimSpace(q.Get("path")),
		User:   strings.TrimSpace(q.Get("user")),
		Target: strings.TrimSpace(q.Get("target")),
		Under:  q.Get("under") == "1",
	}
	if query.Path == "" && query.User == "" && query.Target == "" {
		writeErr(w, http.StatusBadRequest,
			"give at least one of path, user or target "+
				"(for example ?path=/etc/shadow)")
		return
	}
	// ⚠️ Ağaç araması bir YOL gerektiriyor. Sessizce tam eşleşmeye
	// düşmek, operatöre sormadığı soruyu cevaplamak olurdu.
	if query.Under && query.Path == "" {
		writeErr(w, http.StatusBadRequest,
			"under=1 needs a path to be under")
		return
	}
	/*
	 * ⚠️ YOL BURADA NORMALLEŞTİRİLİYOR, YALNIZCA store'da DEĞİL — çünkü
	 * cevap onu YANKILIYOR ve panel yankılananı ekrana yazıyor.
	 * Normalleştirmeyi store'un içinde bıraksaydık ekran "under /etc/"
	 * derken sorgu "/etc" ile çalışırdı: denetçiye, yaptığı aramadan
	 * başka bir arama gösterilirdi. Rozet karşılaştırması da (panelde
	 * matchesQuery) bu yankılanan değere bakıyor.
	 */
	if query.Under {
		query.Path = store.CleanSearchPath(query.Path)
	}

	limit, valid := historyLimit(q.Get("limit"))
	if !valid {
		writeErr(w, http.StatusBadRequest, "limit must be a positive number")
		return
	}
	query.Limit = limit

	events, err := s.store.FileHistory(r.Context(), query)
	if err != nil {
		s.storeErr(w, "files.history", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"path":   query.Path,
		"under":  query.Under,
		"user":   query.User,
		"target": query.Target,
		"events": events,
		"limit":  limit,
		/*
		 * ⚠️ KESİLDİYSE SÖYLE. Sessizce ilk N'i döndürmek, denetçinin
		 * "olan biten bu" sanması demek — ve bu ekranda o yanlış
		 * anlamanın bedeli, görülmemiş bir transferin hiç olmamış
		 * sayılması.
		 */
		"truncated": len(events) >= limit,
	})
}

/*
 * historyLimit, ?limit= değerini kaç satır okunacağına çevirir.
 *
 * ⚠️ TAVAN BURADA DA UYGULANIYOR, store'a bırakılmıyor. store aşırı
 * limiti sessizce kırpıyor; istemcinin geçtiği sayıyı olduğu gibi
 * cevaba yazsaydık, limit=5000 diyen bir istemci 200 satır alır ve
 * "5000 istedim 200 geldi, demek ki hepsi bu" diye okurdu — kesilmiş
 * bir denetim listesini tam sanmak, bu ekranın en pahalı hatası.
 *
 * ⚠️ AYRI BİR FONKSİYON çünkü tek başına ölçülebilmesi gerekiyor:
 * handler'ın içinde kalsaydı, kırpmayı sınayan test bir veritabanı
 * ister ve pratikte hiç yazılmazdı.
 */
func historyLimit(raw string) (int, bool) {
	if raw == "" {
		return store.FileHistoryDefaultLimit, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, false
	}
	return min(n, store.FileHistoryMaxLimit), true
}

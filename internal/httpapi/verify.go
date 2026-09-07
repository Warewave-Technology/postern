package httpapi

// Panelden zincir doğrulaması: POST /api/admin/sessions/{id}/verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/Warewave-Technology/postern/internal/archive"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/objstore"
	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/verify"
)

/*
 * ⚠️ NİYE POST, GET DEĞİL.
 *
 * İş yapıyor: dosyanın tamamını okuyor, istenirse kovaya HTTP isteği
 * atıyor, ve denetim defterine satır yazıyor. GET olsaydı tarayıcı ve
 * araya giren vekiller onu önbelleğe alabilir, tekrarlayabilir, ve
 * önyükleme sırasında kendiliğinden çağırabilirdi — denetim satırını
 * kullanıcının basmadığı bir düğme için yazdırarak.
 */

/*
 * verifySlots, aynı anda koşabilecek doğrulama sayısı.
 *
 * ⚠️ SIRAYA GİRMİYOR, REDDEDİYOR. Yuva doluyken beklemek, isteği tutan
 * goroutine'i ve bağlantıyı da tutmak demek; bu sunucuda WriteTimeout
 * bilerek yok (web terminali saatlerce açık kalıyor), yani biriken
 * istekleri kesen hiçbir şey olmazdı. Dolu yuvada anında "şu an meşgul"
 * demek, kullanıcının tekrar denemesini sağlıyor ve kaynağı serbest
 * bırakıyor.
 *
 * Sayı küçük çünkü iş disk okuması: paralellik burada hız değil, kuyruk
 * üretiyor.
 */
const verifySlots = 3

/*
 * verifyArchiveTimeout, arşiv HEAD'i için süre.
 *
 * ⚠️ KOVA İSTEMCİSİNİN KENDİ 30 SANİYESİ DEVRALINMIYOR. O değer bir
 * arka plan yükleyicisi için makul; bir panel isteğinin yolunda yarım
 * dakika beklemek, kullanıcıya "panel dondu" dedirtir. Erişilemeyen bir
 * kova "bakılamadı" olarak raporlanıyor ve o cevap birkaç saniyede
 * verilebiliyor.
 */
const verifyArchiveTimeout = 6 * time.Second

// handleVerifyRecording, bir kaydın zincirini doğrular.
func (s *Server) handleVerifyRecording(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	/*
	 * ⚠️ YUVA HER ŞEYDEN ÖNCE ALINIYOR. Denetim satırını yazıp sonra
	 * meşgul olduğumuzu fark etmek, yapılmamış bir işi deftere yazmak
	 * olurdu.
	 */
	select {
	case s.verifySlots <- struct{}{}:
		defer func() { <-s.verifySlots }()
	default:
		writeErr(w, http.StatusTooManyRequests,
			"another recording is being verified right now; try again in a moment")
		return
	}

	sess, err := s.store.Session(r.Context(), id)
	if err != nil {
		s.storeErr(w, "sessions.verify", err)
		return
	}

	/*
	 * ⚠️ DENETİM SATIRI İŞTEN ÖNCE, VE YAZILAMAZSA İŞ YAPILMIYOR.
	 *
	 * Kuralı buradan icat etmiyoruz: aynı dosyadaki kayıt verme yolu
	 * (session.replay) baytlardan önce yazıyor ve yazamazsa kaydı
	 * vermiyor. Gerekçe okumanın ÇIKTIYA dönmesine değil, kaydın
	 * İÇERİĞİNE dokunulmasına bağlı — doğrulama içeriğin tamamını
	 * okuyor. Kim, hangi kaydı, ne zaman doğruladı: izi tutulamayan bir
	 * okuma yapılmamalıdır.
	 *
	 * Bağlam istekten KOPARILIYOR: uzun bir dosya okunurken istemci
	 * bağlantıyı keserse r.Context() iptal olur ve satır yazılamazdı.
	 */
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	if aerr := s.store.LogAdmin(auditCtx, store.AdminLogEntry{
		Actor:   sessionUser(r),
		Via:     "web",
		Action:  "session.verify",
		Entity:  sess.ID,
		Details: fmt.Sprintf("user %s target %s", sess.User, sess.Target),
	}); aerr != nil {
		s.logger.Error("verify audit write failed; refusing to verify",
			"session", sess.ID, "error", aerr)
		writeErr(w, http.StatusServiceUnavailable,
			"could not record who is verifying this recording, so it was not verified; "+
				"try again shortly")
		return
	}

	out := s.verifyRecording(r, sess)
	writeJSON(w, http.StatusOK, out)
}

/*
 * verifyResult, panele giden cevap.
 *
 * ⚠️ İKİ EKSEN AYRI KALIYOR ve bu, cevabın en önemli özelliği. Yerel
 * zincirin tutması ile arşivdeki kopyanın onaylaması iki ayrı iddia;
 * tek bir "sonuç" alanında birleştirmek, birini diğerinin arkasına
 * saklardı — özellikle "yerel tuttu ama arşiv çelişiyor" durumunu, ki o
 * en güçlü kurcalama işareti.
 */
type verifyResult struct {
	// Local, yerel dosyanın zincirle tutup tutmadığı.
	Local string `json:"local"`
	// Detail, Local'ın tek cümlelik gerekçesi.
	Detail string `json:"detail,omitempty"`

	// Chain/StoredLinks, veritabanındaki baş. Links, dosyadan sayılan.
	Chain       string `json:"chain,omitempty"`
	StoredLinks int64  `json:"stored_links,omitempty"`
	Links       int64  `json:"links,omitempty"`

	OffBox offBoxJSON `json:"off_box"`
}

type offBoxJSON struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Links  string `json:"links,omitempty"`
	Object string `json:"object,omitempty"`
}

/*
 * Local ekseninin değerleri.
 *
 * ⚠️ "verified" DIŞINDAKİLERİN HİÇBİRİ ONAY DEĞİL ve panel bunu böyle
 * çizmek zorunda. Özellikle "unsealed": veritabanında baş olmaması,
 * kaydın bozuk olduğu anlamına GELMİYOR — göç 034'ten önce kapanmış ya
 * da hâlâ süren bir oturum da öyle görünür. Onu bir alarm gibi
 * göstermek, ilk yükseltmede geçmişin tamamını suçlamak olurdu.
 */
const (
	verifyVerified  = "verified"
	verifyChanged   = "changed"
	verifyUnsealed  = "unsealed"
	verifyRunning   = "in_progress"
	verifyNoLocal   = "no_local_copy"
	verifyNotStored = "not_recorded"
	verifyError     = "error"
)

func (s *Server) verifyRecording(r *http.Request, sess model.Session) verifyResult {
	out := verifyResult{
		Chain:       sess.RecordingChain,
		StoredLinks: sess.RecordingLinks,
	}

	off := s.offBoxFor(r, sess)
	out.OffBox = offBoxJSON{
		State: off.State.String(), Detail: off.Detail,
		Chain: off.Chain, Links: off.Links, Object: off.Object,
	}

	switch {
	case sess.RecordingPath == "":
		out.Local = verifyNotStored
		out.Detail = "this session has no recording"

		return out

	case sess.Open():
		/*
		 * ⚠️ SÜREN OTURUM DOĞRULANAMAZ VE BU BİR ARIZA DEĞİL. Zincir
		 * başı oturum KAPANIRKEN yazılıyor; süren bir oturumu
		 * "mühürsüz" diye göstermek, her açık kabuğu şüpheli
		 * gösterirdi.
		 */
		out.Local = verifyRunning
		out.Detail = "the session is still open; the chain is written when it closes"

		return out

	case sess.RecordingChain == "":
		out.Local = verifyUnsealed
		out.Detail = "no chain was stored — the session ended before chains existed, " +
			"or it has only just closed"

		return out
	}

	f, err := s.records.Open(sess.ID, sess.RecordingPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			/*
			 * ⚠️ YEREL KOPYA YOK AMA ARŞİVDEKİ HÂLÂ CEVAP VEREBİLİR.
			 * Budayıcı arşivlenmiş bir kaydı sildiğinde geriye kalan
			 * tek kanıt o kopya; "dosya yok" deyip susmak, arşivlemenin
			 * amacını boşa çıkarır.
			 */
			out.Local = verifyNoLocal
			out.Detail = "the recording is not on this host — it was archived and pruned; " +
				"the bytes were not checked"

			return out
		}
		s.logger.Error("verify could not open the recording",
			"session", sess.ID, "error", err)
		out.Local = verifyError
		out.Detail = "the recording could not be read on this host"

		return out
	}
	defer f.Close()

	ok, links, err := record.VerifyChain(f, sess.RecordingChain)
	if err != nil {
		s.logger.Error("verify failed to read the recording",
			"session", sess.ID, "error", err)
		out.Local = verifyError
		out.Detail = "the recording could not be read to the end"

		return out
	}

	out.Links = links
	if ok {
		out.Local = verifyVerified
	} else {
		out.Local = verifyChanged
		out.Detail = fmt.Sprintf("the file has %d links and a different chain", links)
		if links < sess.RecordingLinks {
			out.Detail += fmt.Sprintf("; it is short by %d lines", sess.RecordingLinks-links)
		}
	}

	return out
}

/*
 * offBoxFor, arşivdeki kopyayı okur.
 *
 * ⚠️ KARARI internal/verify VERİYOR, BURASI DEĞİL. Aynı soruyu
 * `postern session verify` de soruyor; iki ayrı uygulama bir gün aynı
 * kayıt için farklı iki cevap verirdi.
 */
func (s *Server) offBoxFor(r *http.Request, sess model.Session) verify.OffBox {
	if s.archiveDest.Endpoint == "" {
		return verify.OffBoxOf(r.Context(), nil, store.ArchiveState{}, false, sess.RecordingChain)
	}

	st, found, err := s.store.ArchiveStateOf(r.Context(), sess.ID)
	if err != nil {
		return verify.OffBox{State: verify.OffBoxUnchecked,
			Detail: "could not read the archive state"}
	}
	if !found || !st.Archived {
		return verify.OffBoxOf(r.Context(), nil, st, false, sess.RecordingChain)
	}

	client, cerr := s.archiveHead(r.Context())
	if cerr != nil {
		return verify.OffBox{State: verify.OffBoxUnchecked, Detail: cerr.Error()}
	}

	ctx, cancel := context.WithTimeout(r.Context(), verifyArchiveTimeout)
	defer cancel()

	return verify.OffBoxOf(ctx, client, st, true, sess.RecordingChain)
}

/*
 * archiveHead, kovanın ÜSTVERİSİNİ okuyacak istemciyi kurar.
 *
 * ⚠️ BU, "PANEL NESNE DEPOSUNDAN OKUMAZ" KARARINI ÇİĞNEMİYOR — ve ayrımı
 * yazmak gerekiyor, çünkü ilk bakışta öyle görünüyor. O karar
 * (recordingBlock'un başındaki not) nesnenin İÇERİĞİYLE ilgili: panele
 * arşivden kayıt indirtmek, tek bir ele geçirmeyle bütün arşivi dışarı
 * çıkarılabilir yapardı. Buradaki istek bir HEAD ve dönen tek şey zincir
 * başı — bayt yok, indirme yok.
 *
 * Kimlik bilgisi de yeni değil: yükleyici onu zaten kullanıyor ve
 * `postern session verify` de aynı çözücüden alıyor. Ayrı bir çözücü
 * yazmak, CLI ile panelin farklı kimlikler kullanabilmesi demekti.
 */
func (s *Server) archiveHead(ctx context.Context) (verify.HeadReader, error) {
	// Testlerin taktığı sahte okuyucu.
	if s.archiveClient != nil {
		return s.archiveClient, nil
	}

	creds, _, err := archive.Credentials(ctx, s.store,
		s.archiveDest.AccessKeyID, s.archiveHostSecret)
	if err != nil {
		return nil, fmt.Errorf("could not read the archive credential")
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, errors.New("no archive credential on this host")
	}

	ac := s.archiveDest

	return objstore.New(objstore.Config{
		Endpoint: ac.Endpoint, Region: ac.Region, Bucket: ac.Bucket,
		CAFile: ac.CAFile, Timeout: ac.Timeout,
		ServerSideEncryption: ac.ServerSideEncryption,
		Credentials:          creds,
	})
}

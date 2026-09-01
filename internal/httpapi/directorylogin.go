package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

/*
 * Dizin parolasıyla panel girişi.
 *
 * ⚠️ ÜRÜNÜN EN KESKİN İDDİASININ HARCANDIĞI YER. postern bugüne kadar
 * kullanıcının kurumsal parolasını hiç görmüyordu. Burası görüyor —
 * yalnızca PANELDE, yalnızca doğrulamak için, hiçbir yere yazmadan.
 * SSH kapısı parolayı hâlâ hiç kullanmıyor: orada anahtar var. Kurumsal
 * parola bilerek TEK bir kapıya hapsedildi.
 */

// directoryBindSlots, aynı anda yürütülebilecek bind sayısı.
//
// Yerel sırdaki argon2 yuvalarından AYRI: orada korunan şey postern'in
// belleği, burada korunan şey KURUMUN DİZİNİ. Her deneme taze bir
// TCP+TLS+bind demek (ldap.connect'te havuz yok) ve kimliği
// doğrulanmamış bir istek bunu tetikleyebiliyor.
const directoryBindSlots = 8

/*
 * directoryLogin, kullanıcıyı dizin parolasıyla doğrular ve oturum açar.
 *
 * Çağıran (handleLocalLogin) buraya yalnızca AKTİF KAYNAK dizinken
 * düşüyor. Yani burada hiçbir hesap adı yerel doğrulayıcıya, hiçbir
 * yerel sır dizine gitmiyor: hangi kapının açık olduğu isteğin
 * içeriğine değil, ayara bağlı.
 */
func (s *Server) directoryLogin(w http.ResponseWriter, r *http.Request,
	log logger, username, password string) {

	if !s.localLimit.allow(s.clientKey(r)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts; try again in a minute")
		return
	}

	select {
	case s.bindSlots <- struct{}{}:
		defer func() { <-s.bindSlots }()
	default:
		// Kuyruk yerine RET: bekleyen istekler, saldırganın bedavaya
		// tutabileceği bir kaynak olurdu — üstelik kurumun dizinine
		// karşı.
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "sign-in is busy; try again shortly")
		return
	}

	res, err := ldap.AuthenticateFromStore(r.Context(), s.store, username, password)
	switch {
	case errors.Is(err, ldap.ErrEmptySecret):
		// Boş parola bind'e HİÇ ulaşmadı (kimliksiz bind tuzağı).
		// Dışarıya yine aynı cevap: hangi kontrolde düştüğü bilgisi
		// kimseye yaramaz.
		//
		// Denetim satırı YAZILIYOR: reddedilen her giriş iz bırakmalı,
		// yoksa "hiç denenmedi" ile "denendi ve reddedildi" ayrılamaz.
		// Kullanıcı adı ham yazılmıyor — hesabı hiç aramadık, yani
		// bilinen bir ad olduğunu söyleyemeyiz.
		log.Warn("directory login refused: empty password")
		if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
			Actor: "anonymous", Via: "local", Action: "auth.directory_denied",
			Entity: "unknown account", Details: "empty password (would be an unauthenticated bind)",
		}); aerr != nil {
			log.Error("audit write failed", "error", aerr)
		}
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	case errors.Is(err, ldap.ErrNotConfigured):
		log.Error("directory login attempted with no directory configured")
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	case err != nil:
		// ⚠️ ARIZA "YANLIŞ PAROLA" DEĞİLDİR. Dizin cevap veremiyorsa
		// kullanıcıya parolasının yanlış olduğunu söylemek, saatlerce
		// yanlış yerde arattırır.
		log.Error("directory login failed", "error", err)
		writeErr(w, http.StatusServiceUnavailable,
			"the directory could not be reached; this is not a password problem")
		return
	}

	if res.Presence != ldap.PresencePresent || !res.Authenticated || res.Disabled {
		/*
		 * ⚠️ TEK CEVAP, ÜÇ AYRI SEBEP. "Böyle bir kullanıcı yok",
		 * "parola yanlış" ve "hesap kapalı" dışarıya aynı görünüyor:
		 * ayrım, kimliği doğrulanmamış birine hesap keşfi imkânı
		 * verirdi. Ayrım LOGDA ve denetim kaydında duruyor.
		 */
		reason := "wrong password"
		switch {
		case res.Presence == ldap.PresenceAbsent:
			reason = "no such user in the directory"
		case res.Disabled:
			reason = "account is disabled in the directory: " + res.DisabledReason
		}
		log.Warn("directory login refused", "user", username, "reason", reason)

		// Denetim kaydına, bilinen bir hesap adı olmadıkça ham kullanıcı
		// adı YAZILMIYOR — parola kutusuna yanlış alan yazan operatörün
		// değeri kalıcı bir tabloya düşmesin.
		entity := "unknown account"
		if res.Presence == ldap.PresencePresent {
			entity = username
		}
		if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
			Actor: "anonymous", Via: "local", Action: "auth.directory_denied",
			Entity: entity, Details: reason,
		}); aerr != nil {
			log.Error("audit write failed", "error", aerr)
		}
		/*
		 * ⚠️ SÜRESİ DOLMUŞ PAROLA, TEK İSTİSNA.
		 *
		 * Diğer üç hâl (yok / yanlış / kapalı) dışarıya AYNI cevabı
		 * veriyor ve bu kasıtlı: ayrım, kimliği doğrulanmamış birine
		 * hesap keşfi imkânı verirdi.
		 *
		 * Süresi dolmuş parola farklı, çünkü sızdırdığı şey farklı:
		 * dizin bunu YALNIZCA doğru parolayla bağlanmaya çalışana
		 * söylüyor. Yani zaten kimliğini kanıtlamış birine, neden
		 * giremediğini anlatıyoruz — keşfe açılan bir kapı değil.
		 * Söylememenin bedeli somut: kullanıcı doğru parolasını
		 * defalarca deniyor ve sonra yanlış yerde, postern'de, arıza
		 * arıyor. Yapılacak iş burada değil.
		 */
		if res.PasswordExpired {
			writeErr(w, http.StatusUnauthorized,
				"your directory password has expired — change it with your "+
					"organisation's own tool, then sign in here again")
			return
		}
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}

	/*
	 * ⚠️ EŞLEŞTİRME ÖNCE KARARLI KİMLİKLE, SONRA ADLA.
	 *
	 * Bu sıra 011'in OIDC için kurduğu kuralın dizin karşılığı. Dizin
	 * bir kararlı kimlik veriyorsa (objectGUID / entryUUID) hesabı O
	 * belirler — kullanıcının o an ne yazdığı değil. Böylece dizinde
	 * yeniden adlandırılan kişi kendi hesabına girmeye devam ediyor
	 * (ölçüldü: yeniden adlandırma ve OU taşıma kimliği değiştirmiyor),
	 * ve ayrılan birinin adını devralan kişi onun hesabını devralmıyor
	 * (ölçüldü: aynı adla yeniden açılan kayıt FARKLI kimlik alıyor).
	 *
	 * Ada düşmek YALNIZCA ilk temas için: postern'in o kimliği hiç
	 * görmediği an. Orada başka hiçbir delil yok — CLI'da operatörün
	 * yazdığı ad ile dizinin söylediği adı birbirine bağlayan tek şey
	 * adın kendisi.
	 */
	/*
	 * Gelen kimliğin KENDİSİ yönetici grubunda mı? Gruplar burada
	 * gerçekten çözüldü (Presence present), yani sormak güvenli.
	 */
	adminMember, aerr := auth.InAdminGroup(r.Context(), s.store, res.Groups)
	if aerr != nil {
		log.Error("admin group lookup failed", "error", aerr)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	u, err := s.resolveDirectoryUser(r.Context(), log, username, res.Identity, adminMember)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			/*
			 * Kimliği doğrulandı, hesabı yok. Kapıyı yüzüne kapatmak
			 * yerine ne olduğunu SÖYLÜYORUZ: ya hesap kendiliğinden
			 * açılıyor, ya onay kuyruğuna düşüyor ve kişi bunu
			 * ekranda görüyor.
			 */
			s.admitOrQueue(w, r, log, "dir", res.Identity, username, res.Groups, adminMember)
		case errors.Is(err, store.ErrAdminBindRefused):
			// Ölçülmüş saldırının dizin tarafındaki karşılığı: adı bir
			// yöneticiyle eşleşen, ilk kez görülen bir kimlik.
			log.Warn("directory login denied: this username belongs to an administrator "+
				"account and cannot be claimed by a first sign-in",
				"user", username, "identity", res.Identity)
			writeErr(w, http.StatusForbidden,
				"the directory knows you, but this bastion has no account for you yet; "+
					"ask an administrator to add it")
		case errors.Is(err, store.ErrConflict):
			log.Warn("directory login denied: that account is bound to a different "+
				"directory identity", "user", username, "identity", res.Identity)
			writeErr(w, http.StatusForbidden,
				"the directory knows you, but this bastion has no account for you yet; "+
					"ask an administrator to add it")
		default:
			log.Error("directory login: user load failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "sign-in failed")
		}
		return
	}

	/*
	 * ⚠️ SİLİNMİŞ HESAP GİRİŞLE GERİ GELMEZ. Pasif hesap gelir —
	 * başarılı girişin kendisi kaynağın doğrulaması (bkz. göç 023).
	 */
	if derr := s.store.RefuseIfDeleted(r.Context(), u.Name); derr != nil {
		log.Warn("directory login denied: account is deleted", "user", u.Name)
		writeErr(w, http.StatusForbidden,
			"this account has been removed on this bastion; ask an administrator")
		return
	}

	s.finishDirectorySession(w, r, log, u, res.Groups, adminMember)
}

/*
 * finishDirectorySession, rolleri tazeler ve oturumu açar.
 *
 * Ayrı bir fonksiyon çünkü İKİ yol buraya çıkıyor: var olan hesapla
 * giriş, ve hesabın o an kendiliğinden açılması. İkisinin de aynı
 * rol/yönetici/denetim yolundan geçmesi gerekiyor — ayrı yazılsaydı,
 * biri unutulan bir adımla ilerlerdi.
 */
func (s *Server) finishDirectorySession(w http.ResponseWriter, r *http.Request, log logger,
	u model.User, groups []string, adminGroupMember bool) {

	// Presence çağıranda Present olarak doğrulandı: boş liste burada
	// "hiçbir grupta değil" demek, "bilmiyorum" değil.
	roles, _, rerr := s.store.RolesForGroups(r.Context(), model.ResolvedGroups(groups))
	if rerr != nil {
		s.storeErr(w, "auth.directory", rerr)
		return
	}
	if serr := s.store.SyncRoles(r.Context(), u.Name, roles); serr != nil {
		s.storeErr(w, "auth.directory", serr)
		return
	}
	// Yönetici yetkisi de dizinden: gruplar BURADA gerçekten çözüldü,
	// yani uygulamak güvenli (bkz. applyGroupAdmin'deki not).
	s.applyGroupAdmin(r.Context(), u.Name, groups)

	/*
	 * ⚠️ KAYNAK BU KİŞİYİ ŞU AN DOĞRULADI.
	 *
	 * Zaman temelli iptalin tek girdisi bu damga (göç 023). Bir kapı
	 * damgalamayı unutursa, oradan girenler yavaş yavaş pasifleşir —
	 * yani eksik bir çağrı sessiz bir erişim kaybına dönüşür.
	 */
	if cerr := s.store.ConfirmAccount(r.Context(), u.Name, time.Now()); cerr != nil {
		log.Error("confirm stamp failed", "user", u.Name, "error", cerr)
	}

	token, err := s.webSessions.Create(u.Name)
	if err != nil {
		log.Error("web session create failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}
	// #nosec G124 -- Secure koşullu: bkz. Server.SetExternalURL
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies || r.TLS != nil,
	})

	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: u.Name, Via: "local", Action: "auth.directory_login", Entity: u.Name,
		Details: "signed in with the directory password",
	}); aerr != nil {
		log.Error("audit write failed", "error", aerr)
	}
	log.Info("directory login", "user", u.Name, "roles", len(roles))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// logger, handleLocalLogin'in kurduğu alt logger'ın arayüzü.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

/*
 * resolveDirectoryUser, dizin kullanıcısını postern hesabına çevirir.
 *
 * Sıra ve gerekçeleri çağrı yerinde. Buradaki kural şu: bağlama YALNIZCA
 * ilk temasta ve YALNIZCA yetkisiz, henüz bağlanmamış bir hesap için
 * yapılır. Yönetici hesabı adla devralınamaz — ölçülmüş bir saldırı ve
 * gerekçesi göç 020'de.
 */
func (s *Server) resolveDirectoryUser(ctx context.Context, log logger,
	username, identity string, adminGroupMember bool) (model.User, error) {

	// 1) Kararlı kimlik: varsa TEK doğru cevap bu.
	if identity != "" {
		u, err := s.store.UserByDirSubject(ctx, identity)
		if err == nil {
			return u, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return model.User{}, err
		}
	}

	// 2) İlk temas: adı eşleşen hesap var mı?
	u, err := s.store.User(ctx, username)
	if err != nil {
		return model.User{}, err
	}

	/*
	 * ⚠️ Kimlik YOKSA bağlama da yok — ama giriş sürüyor.
	 *
	 * Dizin kararlı bir değer vermiyorsa (eski şema, ya da servis
	 * hesabı okuyamıyor) postern'in bugünkü davranışı korunuyor: ada
	 * göre bulunan hesapla devam. Bu bir gerileme değil, yokluğun
	 * kabulü — ve teşhis ekranı o dizinde kimlik gelmediğini zaten
	 * söylüyor.
	 */
	if identity == "" {
		return u, nil
	}

	/*
	 * ⚠️ Yönetici hesabı, yalnızca adla devralınamaz — GELEN KİMLİK
	 * kendisi yönetici grubunda değilse.
	 *
	 * Grup üyesiyse kapı açık: o kişi zaten yönetici ve başka bir
	 * yönetici hesabını almakla yeni bir yetki kazanmıyor. Kapalı
	 * tutmak, dizin grubundan yönetici olan herkesi yükseltmeden sonra
	 * kendi hesabından kilitlerdi (ölçüldü).
	 */
	if u.Admin && !adminGroupMember {
		return model.User{}, store.ErrAdminBindRefused
	}

	if berr := s.store.BindDirIdentity(ctx, u.Name, identity); berr != nil {
		// Hesap BAŞKA bir kimliğe bağlı: devralma denemesi.
		return model.User{}, berr
	}

	/*
	 * ⚠️ İLK BAĞLAMA DENETLENEBİLİR OLMALI (011'in aynı notu).
	 *
	 * Bu, kalan tek devralma penceresi. Sessiz kalırsa kimse fark etmez;
	 * denetim satırı yazılamıyorsa bağlamayı yapmış olmayı da istemeyiz,
	 * o yüzden hata yukarı taşınıyor.
	 */
	if lerr := s.store.LogAdmin(ctx, store.AdminLogEntry{
		Actor: "system", Via: "dir", Action: "user.dir_bind", Entity: u.Name,
		Details: "first directory sign-in bound this account to identity " + identity,
	}); lerr != nil {
		return model.User{}, lerr
	}
	log.Info("directory identity bound", "user", u.Name, "identity", identity)
	return s.store.User(ctx, u.Name)
}

/*
 * admitOrQueue, hesabı olmayan ama kimliği doğrulanmış kişiyi karşılar.
 *
 * İki yol var ve hangisinin geçerli olduğunu auth.auto_create söylüyor:
 *
 *   AÇIK  → hesap kendiliğinden açılır. Rol eşlemesi hâlâ kapıda:
 *           hiçbir grubu role eşleşmiyorsa hesap AÇILMAZ.
 *   KAPALI→ kişi onay kuyruğuna düşer ve "onay bekliyor" cevabı alır.
 *
 * ⚠️ KARARLI KİMLİK OLMADAN KUYRUĞA DA ALMIYORUZ. Kuyruk satırı
 * kimlikle anahtarlı (göç 022); anahtarsız bir satır, adını değiştiren
 * herkesin yeniden başvurabildiği ve reddin hiçbir şey ifade etmediği
 * bir kuyruk demek olurdu.
 */
func (s *Server) admitOrQueue(w http.ResponseWriter, r *http.Request, log logger,
	source, identity, username string, groups []string, adminGroupMember bool) {

	if identity == "" {
		log.Warn("no postern account and the directory gives no stable identity",
			"user", username)
		writeErr(w, http.StatusForbidden,
			"the directory knows you, but this bastion has no account for you yet, "+
				"and your directory does not publish a stable identity for you; "+
				"ask an administrator to add the account")
		return
	}

	if auth.AutoCreateEnabled(r.Context(), s.store) {
		u, err := s.store.CreateFromDirectory(r.Context(), store.DirectoryAccount{
			Username: username, Subject: identity, Groups: groups,
		})
		if err != nil {
			if errors.Is(err, store.ErrAccessDenied) {
				// Rol eşlemesi yok: hesap açmak, hiçbir yere
				// erişemeyen bir kayıt bırakmak olurdu.
				log.Warn("auto-create refused: no group maps to a role",
					"user", username, "groups", groups)
				writeErr(w, http.StatusForbidden,
					"none of your groups is mapped to a role on this bastion; "+
						"ask an administrator")
				return
			}
			log.Error("auto-create failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "sign-in failed")
			return
		}
		log.Info("account created from directory", "user", u.Name, "identity", identity)
		s.finishDirectorySession(w, r, log, u, groups, adminGroupMember)
		return
	}

	state, err := s.store.RecordPending(r.Context(), store.PendingUser{
		Subject: identity, Source: source, Username: username, SeenGroups: groups,
	})
	if err != nil {
		log.Error("pending record failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	if state == store.PendingRejected {
		// ⚠️ Reddedilmiş kimliğe "bekliyor" demiyoruz: bekletmediğimiz
		// birini beklettiğimizi söylemek, onu süresiz bir kuyrukta
		// tutmak olurdu.
		log.Warn("rejected identity tried again", "user", username, "identity", identity)
		writeErr(w, http.StatusForbidden,
			"an administrator has declined access for this account")
		return
	}

	log.Info("pending account recorded", "user", username, "identity", identity)
	writeErr(w, http.StatusForbidden,
		"your account is waiting for an administrator to approve it")
}

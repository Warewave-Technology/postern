package ldap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/warewave/postern/internal/store"
)

/*
 * Dizin parolasıyla kimlik doğrulama (bind).
 *
 * ⚠️ BU, ÜRÜNÜN EN KESKİN İDDİASINI HARCADIĞI YER. postern bugüne kadar
 * kullanıcının kurumsal parolasını hiç görmüyordu. Bu yol onu görüyor —
 * yalnızca PANELDE, yalnızca doğrulamak için, hiçbir yere yazmadan ve
 * yalnızca SAKLANAN dizin adresine göndererek.
 *
 * SSH tarafı parolayı ASLA kullanmıyor: orada kapı anahtarla açılıyor.
 * Böylece kurumsal parola tek bir kapıya hapsediliyor.
 */

// ErrEmptySecret, parolanın boş olduğu.
//
/*
 * ⚠️ AYRI BİR HATA OLMASI ŞART VE BU BİR GÜVENLİK KONTROLÜ.
 *
 * LDAP'ta DN verip parolayı boş bırakmak "unauthenticated bind"dir ve
 * sonucu SUNUCUNUN YAPILANDIRMASINA bağlıdır. Ölçtük: bu depodaki
 * OpenLDAP onu reddediyor (Result Code 53, "unauthenticated bind
 * disallowed"). Active Directory ise varsayılan olarak anonim bind
 * gibi ele alıp BAŞARILI döner.
 *
 * Kontrolün burada olmasının sebebi tam olarak bu belirsizlik:
 * postern, bağlandığı dizinin nasıl yapılandırıldığını bilemez ve
 * "parola alanını boş bırakan herkes içeri girer" hâlini uzaktaki bir
 * ayara emanet edemez. Boş parola bind'e HİÇ ulaşmıyor.
 */
var ErrEmptySecret = errors.New("ldap: empty password would be an anonymous bind")

// AuthResult, bir bind denemesinin sonucu.
type AuthResult struct {
	// Presence, kullanıcının dizinde bulunup bulunmadığı.
	Presence Presence

	// Authenticated, parolanın DOĞRU olduğu. Presence present olsa da
	// false olabilir — kullanıcı var, parola yanlış.
	Authenticated bool

	// Disabled, hesabın dizinde kapatılmış olduğu (bkz. liveness.go).
	// Parola doğru olsa bile giriş verilmemeli.
	Disabled       bool
	DisabledReason string

	/*
	 * PasswordExpired, dizin "parola doğru ama süresi dolmuş / önce
	 * değiştirmelisin" dedi.
	 *
	 * ⚠️ Authenticated FALSE kalıyor ve bu doğru: giriş verilmiyor.
	 * Ayrı bir alan olmasının sebebi SÖYLENEN ŞEY: bu hâl "yanlış
	 * parola" olarak gösterildiğinde kullanıcı doğru parolasını
	 * defalarca deniyor, sonra da yanlış yerde — postern'de — arıza
	 * arıyor. Oysa yapılacak iş belli ve postern'de değil: parolayı
	 * kurumun kendi aracıyla değiştirmek.
	 */
	PasswordExpired bool

	Groups     []string
	OutOfScope []string

	/*
	 * Identity, dizinin verdiği KARARLI ve opak kimlik (objectGUID ya
	 * da entryUUID), kanonik biçimde. Boş: bu dizin ya da bu servis
	 * hesabı böyle bir değer vermiyor.
	 *
	 * ⚠️ Eşleştirmenin ASIL anahtarı bu, kullanıcı adı değil. Ad
	 * dizinde değişir (ölçüldü: yeniden adlandırma ve OU taşıma bu
	 * değeri değiştirmiyor) ve yeniden kullanılır (ölçüldü: aynı adla
	 * yeniden açılan kayıt FARKLI kimlik alıyor).
	 */
	Identity string

	// IdentityError, öznitelik geldi ama çözümlenemedi. "Yok" ile aynı
	// şey değil ve teşhis ekranında ayrı görünmeli.
	IdentityError string
}

/*
 * Authenticate, kullanıcıyı dizin parolasıyla doğrular.
 *
 * Sıra önemli:
 *  1. Boş parola REDDEDİLİR (anonim bind tuzağı).
 *  2. Servis hesabıyla kullanıcı aranır — DN, grup ve hesap durumu.
 *  3. Kullanıcının DN'i ile AYRI bir bağlantıda bind denenir.
 *
 * Üçüncü adımın ayrı bağlantıda olması şart: bind, bağlantının kimliğini
 * DEĞİŞTİRİR. Servis hesabının bağlantısı üzerinde kullanıcı bind'i
 * yapmak, o bağlantıyı sonraki sorgular için kullanıcının yetkisine
 * düşürürdü.
 */
func (s *Source) Authenticate(ctx context.Context, username, password string) (AuthResult, error) {
	if username == "" {
		return AuthResult{Presence: PresenceUnknown}, fmt.Errorf("ldap: empty username")
	}
	if password == "" {
		return AuthResult{Presence: PresenceUnknown}, ErrEmptySecret
	}

	lookupConn, err := s.connect(ctx)
	if err != nil {
		return AuthResult{Presence: PresenceUnknown}, err
	}
	defer lookupConn.Close()

	ue, err := s.findUser(lookupConn, username)
	if err != nil {
		return AuthResult{Presence: PresenceUnknown}, err
	}
	if ue.DN == "" {
		// Dizin cevap verdi ve böyle biri yok. Parolayı denemiyoruz
		// bile: denemek, var olmayan bir DN'e bind etmek olurdu.
		return AuthResult{Presence: PresenceAbsent}, nil
	}

	out := AuthResult{
		Presence:       PresencePresent,
		Disabled:       ue.Disabled,
		DisabledReason: ue.DisabledReason,
		OutOfScope:     ue.OutOfScope,
		Identity:       ue.Identity,
		IdentityError:  ue.IdentityError,
	}

	/*
	 * ⚠️ KAPALI HESAP İÇİN PAROLA HİÇ DENENMİYOR.
	 *
	 * Denemek zararsız görünür ama iki şey yapardı: kapalı bir hesabın
	 * parolasını dizinde bir kez daha yanlış deneme sayacına yazdırır,
	 * ve "parola doğruydu ama hesap kapalı" ile "parola yanlıştı"
	 * ayrımını bu koda taşırdı — dışarıya aynı cevabı vereceğimiz iki
	 * hâl için gereksiz bir bilgi.
	 */
	if ue.Disabled {
		return out, nil
	}

	bindConn, err := s.connect(ctx)
	if err != nil {
		return AuthResult{Presence: PresenceUnknown}, err
	}
	defer bindConn.Close()

	if berr := bindConn.Bind(ue.DN, password); berr != nil {
		var lerr *goldap.Error
		if errors.As(berr, &lerr) && lerr.ResultCode == goldap.LDAPResultInvalidCredentials {
			/*
			 * ⚠️ AD, "PAROLAN SÜRESİ DOLDU"YU DA BURADAN SÖYLÜYOR.
			 *
			 * Active Directory bütün bu hâlleri aynı sonuç koduyla
			 * (49) veriyor ve gerçek sebebi mesajın içindeki alt koda
			 * gömüyor. Hepsini "yanlış parola" saymak, doğru parolasını
			 * bilen kullanıcıyı onu defalarca denemeye ve sonra yanlış
			 * yerde — postern'de — arıza aramaya gönderiyordu.
			 *
			 *   532  parolanın süresi doldu
			 *   773  ilk girişte parola değiştirilmeli
			 *   701  hesabın süresi doldu
			 *   533  hesap kapalı
			 *   775  hesap kilitli
			 *
			 * Son üçü zaten hesap DURUMU (liveness.go onları özniteliğe
			 * bakarak da yakalıyor); buradaki kazanç, servis hesabının
			 * o öznitelikleri okuyamadığı kurulumlarda da doğru cümleyi
			 * kurabilmek.
			 */
			switch {
			case adSubCode(berr, "532"), adSubCode(berr, "773"):
				out.PasswordExpired = true
			case adSubCode(berr, "533"):
				out.Disabled, out.DisabledReason = true, "the directory says this account is disabled"
			case adSubCode(berr, "701"):
				out.Disabled, out.DisabledReason = true, "the directory says this account has expired"
			case adSubCode(berr, "775"):
				out.Disabled, out.DisabledReason = true, "the directory says this account is locked out"
			}
			// Yanlış parola bir ARIZA değil: kullanıcı bulundu, kimlik
			// doğrulanamadı. Hata döndürmek, çağıranın bunu dizin
			// kesintisiyle karıştırmasına yol açardı.
			return out, nil
		}
		return AuthResult{Presence: PresenceUnknown}, fmt.Errorf("ldap: bind as user: %w", berr)
	}

	out.Authenticated = true

	// Gruplar, aramayı yapan SERVİS hesabının bağlantısından okunuyor:
	// kullanıcının kendi yetkisi grup ağacını okumaya yetmeyebilir ve
	// yetmediğinde sessizce "hiç grubu yok" görünürdü.
	if s.cfg.GroupAttribute != "" {
		out.Groups = s.normalizeAll(ue.Groups)
	} else {
		groups, oos, gerr := s.searchGroups(lookupConn, ue.DN)
		if gerr != nil {
			return AuthResult{Presence: PresenceUnknown}, gerr
		}
		out.Groups, out.OutOfScope = groups, oos
	}
	return out, nil
}

// AuthenticateFromStore, saklanan yapılandırmayla bind dener.
//
// ⚠️ SAKLANAN adres kullanılıyor: parola yalnızca kurumun kaydettiği
// dizine gidiyor, isteğin taşıdığı bir adrese değil.
func AuthenticateFromStore(ctx context.Context, db *store.Store, username, password string) (AuthResult, error) {
	src, err := SourceFromStore(ctx, db)
	if err != nil {
		return AuthResult{Presence: PresenceUnknown}, err
	}
	return src.Authenticate(ctx, username, password)
}

/*
 * adSubCode, Active Directory'nin 49 numaralı hatasına gömdüğü alt kodu
 * arar.
 *
 * ⚠️ METİN EŞLEŞTİRMESİ ve bunu yazıyorum çünkü kırılgan: AD alt kodu
 * yapılandırılmış bir alanda değil, hata METNİNİN içinde
 * ("... data 532, v..."). LDAP'ın kendisi böyle bir alan tanımlamıyor,
 * dolayısıyla başka bir yol yok.
 *
 * Kırılganlığın bedeli SINIRLI ve bilinçli: eşleşme tutmazsa hiçbir
 * bayrak konmuyor ve davranış eskisiyle aynı oluyor — "yanlış parola".
 * Yani yanlış pozitif üretmiyor, yalnızca daha iyi bir cümle kurma
 * fırsatını kaçırıyor.
 *
 * Ayraçlar aranıyor ("data 532,"): çıplak "532", başka bir sayının
 * içinde de geçebilirdi.
 */
func adSubCode(err error, code string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "data "+code+",") ||
		strings.Contains(err.Error(), "data "+code+" ")
}

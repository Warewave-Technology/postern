package httpapi

/*
 * Yapılandırmanın SALT-OKUNUR görünümü.
 *
 * ⚠️ BURADAN HİÇBİR ŞEY DEĞİŞMİYOR. Dosyadaki ayarlar makinede duruyor
 * ve orada kalıyor; bu ekranın tek işi "bu bastion hangi değerlerle
 * koşuyor" sorusunu, host'a girmeden cevaplamak. Yazma yolu açmak,
 * panelden ele geçirilen bir oturuma dinleme adresini, kayıt hedefini ve
 * güven zincirini değiştirme yetkisi vermek olurdu.
 *
 * ⚠️ BEYAZ LİSTE, STRUCT DÖKÜMÜ DEĞİL. Yapılandırmanın içinde parolalı
 * bir bağlantı dizgesi ve bir istemci sırrı var; "her alanı yaz"
 * diyen bir ekran, bir gün eklenen `smtp.password`ü de yazardı. Her alan
 * ya gösterilenlerde ya gizlenenlerde olmak zorunda ve sınıflandırılmamış
 * bir alan TESTİ DÜŞÜRÜYOR (configview_test.go) — yani yeni bir alan
 * eklenirken karar vermek zorunlu.
 */

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/internal/config"
)

/*
 * hiddenConfig, DEĞERİ SIR olan alanlar ve gizlenme sebepleri.
 *
 * ⚠️ REDAKSİYON DEĞİL, GİZLEME. Bağlantı dizgesinin parolasını ayıklayıp
 * gerisini göstermek cazip ama iki biçimi (URL ve anahtar=değer) ayrıştıran
 * bir kod, bir gün yanlış ayrıştırdığında sırrı EKRANA yazar. Ayrıştırmayan
 * bir kodun böyle bir hatası olamıyor.
 *
 * Dosya YOLLARI burada değil: bir yol sırrın kendisi değil ve "hangi
 * anahtar dosyasıyla koşuyor" sorusu, bu ekranın var olma sebeplerinden.
 */
var hiddenConfig = map[string]string{
	"database.dsn":       "carries the database password",
	"oidc.client_secret": "is a secret",
}

// shownConfig, gösterilen alanlar ve satırın altındaki kısa not.
var shownConfig = map[string]string{
	"listen.addr":                              "where the bastion listens for SSH",
	"listen.external_addr":                     "the address printed to users; empty means the listen address",
	"listen.max_conns":                         "connections accepted at once",
	"listen.max_conns_per_ip":                  "connections accepted at once from one address",
	"listen.handshake_timeout":                 "how long a connection may take to authenticate",
	"listen.max_auth_tries":                    "authentication attempts per connection",
	"listen.max_channels_per_conn":             "channels one connection may open",
	"listen.max_pending_logins":                "sign-ins waiting for a second factor",
	"host_key":                                 "the bastion's own host key",
	"ca.key_file":                              "the certificate authority users are signed with",
	"session.accept_env":                       "environment variables passed through to the target",
	"session.idle_timeout":                     "how long a session may sit idle",
	"session.sftp":                             "file transfer over SSH",
	"session.sftp_panel":                       "the panel's file browser",
	"session.sftp_panel_write":                 "writing through the panel's file browser",
	"session.max_lifetime":                     "the longest a session may last",
	"sync.enabled":                             "the directory synchronisation loop",
	"sync.interval":                            "how often the directory is asked",
	"sync.grace":                               "how long someone may be missing before groups are revoked",
	"sync.timeout":                             "how long one directory query may take",
	"sync.max_zero_fraction":                   "blast radius: share of users that may drop to no group in one run",
	"sync.min_zero_floor":                      "blast radius: the floor that share is measured against",
	"sync.max_unknown_fraction":                "blast radius: share of users the directory may not know",
	"sync.max_revoke_per_run":                  "groups one run may revoke",
	"sync.dry_run":                             "plan only: the loop reports and revokes nothing",
	"auth.public_key_login":                    "signing in with a public key",
	"auth.totp_window":                         "how far a code may be off in time",
	"auth.totp_max_failures":                   "wrong codes before the account is locked",
	"auth.totp_lock_for":                       "how long that lock lasts",
	"target_probe.enabled":                     "reachability probing of targets",
	"target_probe.refresh":                     "how often targets are probed",
	"target_probe.timeout":                     "how long one probe may take",
	"manage.enabled":                           "management access to targets (temporary accounts)",
	"manage.propagate_accounts":                "creating and adopting OS accounts on targets as people connect",
	"manage.uid_pool_min":                      "lowest number postern hands out when the directory gives none",
	"manage.uid_pool_max":                      "highest number postern hands out when the directory gives none",
	"secret_key_file":                          "the key sealed secrets are encrypted with",
	"recording.dir":                            "where session recordings are written",
	"recording.record_input":                   "recording what users type, not just what they see",
	"recording.retain":                         "how long recordings are kept on disk",
	"recording.min_free":                       "free space below which sessions are refused",
	"recording.archive.endpoint":               "where recordings are copied off the box",
	"recording.archive.bucket":                 "the bucket they are copied into",
	"recording.archive.region":                 "the region of that bucket",
	"recording.archive.prefix":                 "the key prefix used there",
	"recording.archive.ca_file":                "the CA the archive endpoint is verified with",
	"recording.archive.access_key_id":          "the key id used there; the secret is not shown",
	"recording.archive.secret_key_file":        "file the archive secret is read from",
	"recording.archive.server_side_encryption": "encryption asked of the archive",
	"recording.archive.interval":               "how often finished recordings are copied",
	"recording.archive.timeout":                "how long one upload may take",
	"http.addr":                                "where the panel listens",
	"http.external_url":                        "the panel's address as users reach it",
	"http.trusted_proxies":                     "proxies whose forwarded client address is believed",
	"http.terminal_enabled":                    "the terminal in the panel",
	"oidc.issuer_url":                          "the identity provider",
	"oidc.client_id":                           "this bastion's client id there",
	"shutdown.drain_timeout":                   "how long sessions may finish on shutdown",
}

// UseConfig, okunmuş yapılandırmayı ve dosyanın yolunu ekrana bağlar.
func (s *Server) UseConfig(c config.Config, path string) {
	s.config = &c
	s.configPath = path
}

func (s *Server) registerConfigRoutes(mux *http.ServeMux) {
	// Yapılandırma verilmediyse rota HİÇ kurulmuyor: kapalı özellik,
	// kapalı yüzey.
	if s.config == nil {
		return
	}
	mux.Handle("GET /api/admin/config", noStore(s.requireSession(
		s.requireAdmin(s.sameOrigin(http.HandlerFunc(s.adminConfig))))))
}

/*
 * groupTitles, bölüm başlıklarının okunur hâli.
 *
 * ⚠️ HAM ANAHTAR BİR BAŞLIK DEĞİL. "target_probe" ve "http" bir yapı
 * adı; ekranda bölüm başlığı olarak "Panel" ile "Target probing" yazması,
 * aradığı ayarı bilmeyen birinin de doğru tabloya bakmasını sağlıyor.
 * Listede olmayan bir bölüm ham adıyla çizilir — yeni bir bölüm eklenince
 * ekran çirkin görünür ama YANLIŞ görünmez.
 */
var groupTitles = map[string]string{
	"general":      "General",
	"listen":       "SSH listener",
	"ca":           "Certificate authority",
	"session":      "Sessions",
	"sync":         "Directory sync",
	"auth":         "Authentication",
	"target_probe": "Target probing",
	"manage":       "Management access",
	"recording":    "Recording",
	"http":         "Panel",
	"oidc":         "OIDC",
	"shutdown":     "Shutdown",
}

type configEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Note  string `json:"note"`
}

type configGroup struct {
	Title   string        `json:"title"`
	Entries []configEntry `json:"entries"`
}

// adminConfig: GET /api/admin/config
func (s *Server) adminConfig(w http.ResponseWriter, r *http.Request) {
	groups := []configGroup{}
	byTitle := map[string]int{}
	for _, l := range configLeaves(reflect.ValueOf(*s.config), "") {
		note, ok := shownConfig[l.key]
		if !ok {
			continue
		}
		title := strings.SplitN(l.key, ".", 2)[0]
		if !strings.Contains(l.key, ".") {
			title = "general"
		}
		i, seen := byTitle[title]
		if !seen {
			shownTitle := title
			if t, ok := groupTitles[title]; ok {
				shownTitle = t
			}
			groups = append(groups, configGroup{Title: shownTitle})
			i = len(groups) - 1
			byTitle[title] = i
		}
		groups[i].Entries = append(groups[i].Entries,
			configEntry{Key: l.key, Value: l.value, Note: note})
	}

	withheld := make([]configEntry, 0, len(hiddenConfig))
	for k, why := range hiddenConfig {
		withheld = append(withheld, configEntry{Key: k, Note: why})
	}
	// Harita sırası rastgele; ekran her açılışta aynı sırayı görmeli.
	sortEntries(withheld)

	writeJSON(w, http.StatusOK, map[string]any{
		"path":   s.configPath,
		"groups": groups,
		/*
		 * ⚠️ GİZLENENLER DE LİSTELENİYOR — ADLARIYLA, DEĞERSİZ. "Bu alan
		 * var ve bilerek gösterilmiyor" cümlesi, alanın hiç olmadığını
		 * sanmaktan iyi: eksik bir listeyi okuyan operatör, ayarın
		 * yazılmadığını düşünüp ikinci kez yazmaya kalkar.
		 */
		"withheld": withheld,
	})
}

func sortEntries(e []configEntry) {
	for i := 1; i < len(e); i++ {
		for j := i; j > 0 && e[j].Key < e[j-1].Key; j-- {
			e[j], e[j-1] = e[j-1], e[j]
		}
	}
}

type configLeaf struct {
	key   string
	value string
}

/*
 * configLeaves, yapılandırmanın yaprak alanlarını yaml adlarıyla verir.
 *
 * ⚠️ TİP ÜZERİNDEN İNİYOR, DEĞER ÜZERİNDEN DEĞİL — sıfır bir yapı
 * verildiğinde de bütün anahtarlar çıkıyor. Test bunu böyle kullanıyor:
 * yeni bir alan, hiç doldurulmamış olsa bile listede görünmek ve
 * sınıflandırılmak zorunda.
 */
func configLeaves(v reflect.Value, prefix string) []configLeaf {
	out := []configLeaf{}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.SplitN(f.Tag.Get("yaml"), ",", 2)[0]
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = strings.ToLower(f.Name)
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}

		fv := v.Field(i)
		ft := f.Type
		if ft.Kind() == reflect.Struct {
			out = append(out, configLeaves(fv, key)...)
			continue
		}
		out = append(out, configLeaf{key: key, value: showValue(fv)})
	}

	return out
}

/*
 * showValue, bir alanın okunur hâli.
 *
 * ⚠️ BOŞ İLE VARSAYILAN AYRI CÜMLELER. İşaretçi alanlar (auth.*) "yazılmadı,
 * dolayısıyla varsayılan geçerli" demek; boş bir dizge ise "yazıldı ve boş".
 * İkisini aynı göstermek, operatöre yazdığı bir ayarı yazmamış gibi okutur.
 */
func showValue(v reflect.Value) string {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "(default)"
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.String:
		if v.String() == "" {
			return "(not set)"
		}
		return v.String()
	case reflect.Bool:
		return fmt.Sprintf("%t", v.Bool())
	case reflect.Int64:
		if d, ok := v.Interface().(time.Duration); ok {
			return d.String()
		}
		return fmt.Sprintf("%d", v.Int())
	case reflect.Slice:
		if v.Len() == 0 {
			return "(none)"
		}
		parts := make([]string, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			parts = append(parts, fmt.Sprint(v.Index(i).Interface()))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprint(v.Interface())
	}
}

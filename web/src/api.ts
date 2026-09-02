// Backend ile sözleşme — şekiller internal/httpapi/admin.go'daki girdi
// şekilleriyle birebir. Değişecekse İKİSİ birlikte değişir.

export type Me = {
  name: string;
  os_user: string;
  admin: boolean;
  targets: string[];
  // Sunucuda terminal rotası kurulu mu. Kurulu değilse panel düğmeyi
  // hiç göstermez: olmayan bir kapıyı sunup 404 aldırmak, kullanıcıya
  // özelliğin BOZUK olduğunu düşündürür.
  terminal_enabled: boolean;
  /** Anahtarla giriş açık mı (auth.public_key_login). Kapalıysa panel
   *  anahtar yönetimini hiç çizmiyor — asıl koruma sunucuda. */
  public_key_login: boolean;
  /** Panelin kopyalattığı ssh komutunun adresi. BOŞ = adres bilinmiyor
   *  ve kopyalama seçeneği hiç çizilmiyor: yapıştırıldığında
   *  çalışmayacak bir komut, hiç komut olmamasından kötü. */
  ssh_host?: string;
  ssh_port?: number;
  /** Hesap bir dizin kimliğine bağlı mı. Sihirbaz buna bakıyor: zaten
   *  bağlı olana "önce bağla" demek, ilerleyemeyeceği bir duvar olurdu. */
  dir_bound?: boolean;
  /** ⚠️ Kurulum yapılmadıysa panel SADECE sihirbazdan ibaret. İsteğe
   *  bağlı bir ekran olarak bırakıldığında atlanıyor ve geriye kaynağı
   *  seçilmemiş bir kurulum kalıyordu. */
  setup_required?: boolean;
  /** ⚠️ Parola değiştirilmeden panel KULLANILAMAZ. Yönetici tarafından
   *  verilen değeri veren de biliyor; bu bayrak, o hâli tek bir girişle
   *  sınırlıyor. Asıl koruma sunucuda (requireSession): ekranın doğru
   *  çizilmesine güvenerek açık bırakılan bir kapı, kapalı değildir. */
  must_change_password?: boolean;
  /** Kuralın TEK KAYNAĞI sunucu. Ekrana ikinci bir kopyasını yazmak,
   *  bir güvenlik kontrolünü iki yerde tutmak olurdu. */
  password_policy?: PasswordPolicy;
  /** Bu hesabın parolası panelden DEĞİŞTİRİLEBİLİR mi. Dizinden gelen
   *  hesapların parolası postern'de yok (uç 409 döner), yöneticininki
   *  ise acil çıkış sırrı ve seçilmiş parolaya çevrilemez (göç 026).
   *  Bayrak olmadan panel iki durumda da form çizer ve kullanıcı,
   *  özelliğin BOZUK mu yoksa kendisine KAPALI mı olduğunu ayırt
   *  edemeden hata alır. */
  can_change_password?: boolean;
};

/** PasswordPolicy, parolanın geçmesi gereken kurallar. */
export type PasswordPolicy = {
  min_length: number;
  max_length: number;
  min_distinct: number;
};

/**
 * UserDetail, tek bir kullanıcının sayfası.
 *
 * ⚠️ LİSTE TİPİNDEN AYRI. Liste "kimler var ve durumları ne" sorusunu
 * cevaplıyor ve her satır için ödenen her alan, sayfa açılışında N kere
 * ödeniyor. Buradaki alanlar tek bir kişi için ve teşhis içindir.
 */
export type UserDetail = {
  name: string;
  os_user: string;
  email: string;
  admin: boolean;
  /** ⚠️ "cli", "group" ya da boş. Panelin kaldırabildiği ile
   *  kaldıramadığı ayrı şeyler; kaynağı göstermeyen bir ekran,
   *  operatöre kaldıramayacağı bir yetkiyi kaldırabileceğini sandırır. */
  admin_via: string;
  state: "active" | "inactive" | "deleted";
  last_confirmed?: string;
  sso_only: boolean;
  dir_bound: boolean;
  /* ⚠️ Hedefler ROL BAŞINA geliyor; düz bir "targets" alanı YOK.
     Burada zorunlu bir string[] olarak duruyordu ve sunucu onu hiç
     göndermiyordu — TypeScript'in var saydığı, çalışma anında hep
     undefined olan bir alan. Okuyan olmadığı için hata vermiyordu;
     okuyan ilk kişi için bir tuzaktı. */
  roles: { name: string; targets: string[] }[];
  keys: { fingerprint: string; comment: string; added_at: string }[];
  sessions: { id: string; target: string; started: string; ended?: string }[];
  /** Hesabın postern'de doğrulanabilir bir değeri varsa. Yoksa kimliği
   *  dizinden ya da kimlik sağlayıcıdan geliyor. */
  credential?: {
    /** "secret" (makine üretimi, acil durum), "issued" (verildi, henüz
     *  değiştirilmedi) ya da "password" (kullanıcının seçtiği). */
    kind: "secret" | "issued" | "password";
    must_change: boolean;
    created_at: string;
    created_by: string;
    last_used_at?: string;
  };
  /** İkinci faktör. Yoksa alan hiç gelmiyor — "kayıtlı değil" ile
   *  "bakamadık"ı ayırmak için (sunucu okuma hatasını logluyor). */
  totp?: { enrolled: boolean; last_used_at?: string };
};

/**
 * CreateUserResult, kullanıcı yaratmanın cevabı.
 *
 * ⚠️ ÜÇ AYRI HÂL ve üçü de ayırt edilebilir olmalı:
 *   - secret dolu: yerel kaynak, değer üretildi, TEK KEZ gösterilecek.
 *   - credential_error dolu: hesap AÇILDI ama değer verilemedi. Bunu
 *     yutmak, hiçbir şekilde giremeyen bir kullanıcıyı sessizce
 *     bırakmak olurdu.
 *   - ikisi de boş: yerel kapı kapalı, üretilecek bir değer yok.
 */
export type CreateUserResult = {
  username?: string;
  secret?: string;
  credential_error?: string;
};

/** IssuedCredential, panelden verilen giriş bilgisi. */
export type IssuedCredential = {
  username: string;
  /** ⚠️ TEK GÖSTERİM — hiçbir yerde saklanmıyor, yeniden üretilemez. */
  secret: string;
  /** Var olanın üstüne mi yazıldı ("parolamı unuttum" yolu). */
  replaced?: boolean;
  /** ⚠️ Hesap AÇILDI ama sır verilemedi. Bunu yutmak, giremeyen bir
   *  kullanıcıyı sessizce bırakmak olurdu. */
  credential_error?: string;
};

/** OIDCSettings, kimlik sağlayıcı ayarlarının panel görünümü. */
export type OIDCSettings = {
  issuer_url: string;
  client_id: string;
  /** ⚠️ Sırrın KENDİSİ dönmüyor, yalnızca var olup olmadığı: panelin
   *  okuyabildiği bir sır, panele erişen herkesin okuyabildiği sırdır. */
  client_secret_set: boolean;
  /** ⚠️ Sağlayıcıya özel: grupları taşıyan claim. Boşsa "groups".
   *  Entra "roles", bazı kurulumlar "memberOf" kullanıyor — sabit
   *  bıraksaydık o kurumlar grupsuz kalırdı. */
  groups_claim: string;
  /** ⚠️ İstenen kapsamlar. Boşsa "openid email profile". Okta ve
   *  Auth0 grupları ancak açıkça istenirse gönderiyor. */
  scopes: string;
  managed_in_db: boolean;
  /** Ayarlı mı — çalışıyor mu ayrı sorular ve ayrı ekranlar hak ediyor. */
  configured: boolean;
  live: boolean;
};
export type User = {
  name: string;
  os_user: string;
  admin: boolean;
  roles: string[];
  /** ⚠️ SAYI, anahtarların kendisi değil. Listenin cevapladığı soru
   *  "kim hiç bağlanamıyor" — sıfır anahtarlı hesap, rolü ne olursa
   *  olsun hiçbir hedefe SSH ile ulaşamıyor. */
  keys: number;
  /**
   * ⚠️ Hesabın yaşam döngüsü. Kaynağın bir süredir doğrulamadığı
   * hesaplar kendiliğinden pasifleşiyor; bunu göstermeyen bir liste
   * "neden giremiyorum" sorusunu cevaplayamaz ve yönetici postern'de
   * bir arıza arar.
   */
  state?: "active" | "inactive" | "deleted";
  /** Kaynağın bu kişiyi en son ne zaman doğruladığı. */
  last_confirmed?: string;
};
export type Role = { name: string; targets: string[] };
export type Target = {
  name: string;
  host: string;
  port: number;
  fingerprint: string;
  // Sunucu nil map yerine {} döndürüyor: null gelseydi Object.entries
  // her satırda patlardı.
  labels: Record<string, string>;
};
export type Session = {
  id: string;
  user: string;
  target: string;
  os_user: string;
  src_ip: string;
  started_at: string;
  ended_at: string | null;
  /** Bu süreçte GERÇEKTEN akıyor mu.
   *
   *  ⚠️ `!ended_at` ile AYNI ŞEY DEĞİL: ended_at'in boş olması "bitişini
   *  kaydetmedik" demek ve postern çökerse o satır sonsuza dek boş
   *  kalıyor. Kapatma düğmesi yalnızca `running` olana çizilir; aksi
   *  hâlde panel var olmayan bir oturumu kapatmayı teklif ederdi. */
  running?: boolean;
};
/** MyTarget, ana ekrandaki kutu. Adres YOK: sıradan kullanıcı hedefe
 *  postern üzerinden bağlanıyor ve ağ topolojisini bilmesi gerekmiyor. */
export type MyTarget = {
  name: string;
  labels: Record<string, string>;
  server_version?: string;
  last_seen_at?: string;
};

/*
 * MyTargetDetail, kullanıcının KENDİ hedef sayfası.
 *
 * ⚠️ host/port YOK ve olmayacak: kullanıcı hedefe postern üzerinden
 * bağlanıyor, adresini bilmesi gerekmiyor. Adresi vermek, bastion'ın
 * varlık sebebi olan "ağ topolojisini gizleme"yi panelden sızdırırdı.
 *
 * ⚠️ sessions yalnızca KENDİ oturumları. Aynı hedefe başkalarının ne
 * zaman bağlandığı bir denetim sorusu ve yönetici ekranında duruyor.
 */
export type MyTargetDetail = MyTarget & {
  sessions: {
    id: string;
    started: string;
    ended?: string;
    os_user: string;
  }[];
};

/** ScannedKey, bir adresteki makinenin O ANDA sunduğu host key.
 *  ⚠️ Doğrulanmış değil: operatörün makineyle karşılaştırması gerekiyor. */
export type ScannedKey = {
  key_type: string;
  fingerprint: string;
  authorized_key: string;
  /** Hedefteki dosya yolu — doğrulama komutu için. Sunucu türetiyor. */
  key_file?: string;
  conflicts_with?: string;
  /** "different-type": aynı makinenin başka türden anahtarı (sık ve
   *  masum). "different-key": AYNI türde BAŞKA anahtar (alarm). */
  conflict_kind?: "different-type" | "different-key";
};

export type TargetFacts = {
  server_version?: string;
  host_key_type?: string;
  last_seen_at?: string;
  connect_ms?: number;
  last_error_at?: string;
  last_error?: string;
  // Yalnızca target_probe açıkken dolar: hedefte komut çalıştırıldı.
  kernel?: string;
  os_name?: string;
  probed_at?: string;
};

export type TargetDetail = {
  name: string;
  host: string;
  port: number;
  fingerprint: string;
  labels: Record<string, string>;
  facts: TargetFacts;
  granted_by: string[];
  recent_sessions: {
    id: string;
    user: string;
    os_user: string;
    src_ip: string;
    started_at: string;
    ended_at?: string;
  }[];
};

export type Mapping = { group: string; role: string; created_by: string };
export type UnmappedGroup = {
  name: string;
  seen_count: number;
  last_seen: string;
};
export type Setting = {
  key: string;
  value: string;
  secret: boolean;
  updated_by: string;
};
export type LDAPCandidate = {
  url: string;
  bind_dn: string;
  /** Boş bırakılırsa saklanan parola kullanılır — YALNIZCA adres
   *  değişmediyse. Sunucu aksi hâlde 400 döner. */
  bind_password: string;
  user_base: string;
  user_filter: string;
  group_attribute: string;
  group_base: string;
  group_filter: string;
  group_name_from: string;
  user?: string;
};

/** Senkronizasyonun ETKİN ayarları: saklanan yoksa YAML'daki değer. */
export type SyncSettings = {
  enabled: boolean;
  dry_run: boolean;
  interval: string;
  grace: string;
  max_zero_fraction: number;
  min_zero_floor: number;
  max_unknown_fraction: number;
  max_revoke_per_run: number;
  overridden: string[];
  error?: string;
};

/**
 * AdminGroupStatus, "kim yönetici ve bunu kim verdi".
 *
 * `via` ekranda kalmak zorunda: gruptan gelen yetki panelden
 * kaldırılamaz (bir sonraki eşitlemede geri gelir) ve CLI'ın verdiği hiç
 * kaldırılamaz. Kaynağı göstermeyen bir liste, operatöre
 * kaldıramayacağı bir yetkiyi kaldırabileceğini düşündürür.
 */
export type AdminGroupStatus = {
  group: string;
  holders: { username: string; via: string }[];
  /** Dizin üyeliği SAYILABİLİYOR mu. OIDC claim'i "bu kişi bu
   *  gruptaymış" der ama grubun ÜYELERİNİ listeleyemez — o kurulumda
   *  onay ekranı kimseyi sayamaz. */
  enumerable: boolean;
  /** Sayılamamanın sebebi BOZUK bir LDAP yapılandırmasıysa, hatası.
   *  Boşsa sebep yokluk: LDAP hiç kurulmamış, gruplar claim'den
   *  geliyor. İkisi aynı cümleye düşerse yanlış teşhis konur. */
  enumerable_error?: string;
};

/**
 * PendingUser, kimliği doğrulanmış ama henüz hesabı olmayan kişi.
 *
 * ⚠️ `subject` KARARLI kimlik; satır onunla anahtarlı. `username`,
 * `email` ve `seen_groups` yalnızca GÖSTERİM — üçü de kaynakta
 * değişebiliyor ve hiçbir karar onlara bakmıyor.
 */
export type PendingUser = {
  id: string;
  subject: string;
  source: "dir" | "oidc";
  username: string;
  email: string;
  seen_groups: string[];
  state: "waiting" | "rejected";
  first_seen: string;
  last_seen: string;
  decided_by?: string;
  decided_at?: string;
  reason?: string;
};

/** AdminGroupPreview, "bu grubu kaydedersem kim yönetici olur". */
export type AdminGroupPreview = {
  ok: boolean;
  error?: string;
  group: string;
  admins: string[];
  /** admins'in postern hesabı OLMAYAN kısmı: yetkileri ancak ilk
   *  girişlerinde oluşur. */
  no_account: string[];
  /** Grup üyesi görünüp de çözümlemeden geçemeyenler. Sessizce
   *  atılmıyor, çünkü beklenen birinin listede olmaması bir bulgu. */
  skipped: string[];
  truncated: boolean;
  note?: string;
};

export type LDAPTestResult = {
  ok: boolean;
  error?: string;
  // presence yalnızca bir kullanıcı adı sorulduğunda gelir ve ÜÇ
  // farklı cevabı ayırır: dizinde var, dizinde yok, dizin cevap
  // veremedi. "grubu yok" ile "kendisi yok" aynı şey değil.
  presence?: "present" | "absent" | "unknown";
  groups?: string[];
  roles?: string[];
  unmapped?: string[];
  // Kullanıcının üye olduğu ama grup kapsamı dışında kaldığı için
  // sayılmayan gruplar. Boş olmayan bir liste, yükseltmede rol kaybı
  // demek — ekranda sessiz kalmamalı.
  out_of_scope?: string[];
  /** Dizinin verdiği KARARLI ve opak kimlik (objectGUID / entryUUID).
   *  Boşsa dizin ya da servis hesabı böyle bir değer vermiyor. */
  identity?: string;
  /** Öznitelik geldi ama çözümlenemedi. "Yok" ile aynı şey değil. */
  identity_error?: string;
};

// SyncRun, bir senkronizasyon koşusunun sonucu.
export type SyncRun = {
  id: number;
  started_at: string;
  finished_at: string;
  trigger: string;
  outcome: string;
  reason: string;
  considered: number;
  unknown: number;
  revoked: number;
  roles_changed: number;
  dry_run: boolean;
};

/*
 * AuthMethods, ŞU AN AÇIK olan giriş yolları.
 *
 * ⚠️ "Yapılandırıldı mı" değil "açık mı". Aynı anda yalnızca bir kaynak
 * aktif olabiliyor; giriş ekranı da tek kapı göstermeli, yoksa
 * kullanıcıyı çalışmayacak bir yola sokar.
 */
export type AuthMethods = {
  source: "local" | "oidc" | "ldap";
  oidc: boolean;
  local: boolean;
  /** Dizin kapısı: aynı forma KURUMSAL parola yazılıyor. Yerelden
   *  ayırt edilmesi şart — metinler farklı olmalı. */
  ldap: boolean;
};

/** AuthSourceStatus, aktif kaynak ve her seçeneğin seçilebilirliği. */
export type AuthSourceStatus = {
  source: "local" | "oidc" | "ldap";
  /** false ise kaynak SEÇİLMEDİ, config dosyasından türetildi. */
  stored: boolean;
  options: { source: string; eligible: boolean; why?: string }[];
  /**
   * postern'in bugüne kadar HİÇ GÖRMEDİĞİ grup adlarına yazılmış
   * eşlemeler.
   *
   * ⚠️ Asıl risk eşlemelerin kaybolması değil — kaybolmuyorlar. Risk,
   * yerinde kalıp hiçbirinin eşleşmemesi: kaynak değişince grup adları
   * bambaşka bir biçimde gelir ve sonuç "grup gelmiyor" ile birebir
   * aynı görünür. Bu liste o sessiz hâli görünür kılıyor.
   */
  unseen_mappings?: string[];
};

// MyKey, kullanıcının kendi açık anahtarı.
export type MyKey = { fingerprint: string; comment: string; added_at: string };

/*
 * MyKeys, kendi anahtarlarım ve ekleme kuralının durumu.
 *
 * reauth_required: bu hesap ilk anahtarını çoktan eklemiş; yeni bir
 * anahtar eklemek yeniden kimlik doğrulama istiyor.
 * reauth_possible: postern'in bu hesap için doğrulayabileceği bir
 * kimlik bilgisi var mı. Yoksa panel boş yere sır sormamalı, yolu
 * yöneticiye göstermeli.
 */
export type MyKeys = {
  keys: MyKey[];
  reauth_required: boolean;
  reauth_possible: boolean;
  // reauth_totp: doğrulama TOTP koduyla yapılacak (yerel sır yerine).
  // Panelin hangi alanı göstereceğini belirliyor.
  reauth_totp?: boolean;
};

/*
 * TOTPStatus, hesabın ikinci faktör durumu.
 *
 * needs_fresh_login, kaydın NEDEN yapılamayabileceğini söylüyor: yerel
 * sırrı olmayan hesaplarda (SSO/dizin) kayıt taze bir giriş istiyor,
 * çünkü çalınmış bir oturumun ikinci faktör bağlaması, korumanın
 * kendisini atlatmanın yolu olurdu.
 */
export type TOTPStatus = {
  enrolled: boolean;
  pending: boolean;
  can_begin: boolean;
  needs_fresh_login: boolean;
  confirmed_at?: string;
  last_used_at?: string;
};

export type TOTPEnrolment = {
  secret: string;
  uri: string;
  /* qr: sunucunun ürettiği modül matrisi ('0'/'1' satırları). Panelde
     ikinci bir kodlayıcı tutmuyoruz — kodlayıcı Go tarafında bağımsız
     bir uygulamaya karşı doğrulanıyor (internal/qr). */
  qr: string[];
};

export type RecordingState = "none" | "missing" | "partial" | "complete";

/*
 * SessionFile, SFTP oturumunda gerçekleşen tek bir dosya olayı.
 *
 * ⚠️ ok=false satırlar da geliyor ve gösterilmeli: izinsizlikten dönen
 * bir silme denemesi, engelin çalıştığının kanıtı. Yalnızca başarılıları
 * gösteren bir ekran, "kimse denemedi" ile "denediler ama giremediler"i
 * aynı gösterirdi.
 */
export type SessionFile = {
  id: string;
  at: string;
  op: string;
  path: string;
  new_path?: string;
  flags?: string;
  read: number;
  wrote: number;
  ok: boolean;
  detail?: string;
};

export type SessionDetail = Session & {
  recording: { state: RecordingState; size: number };
  files: SessionFile[];
  // files_error: liste okunamadı. Boş liste ile karıştırılmamalı —
  // "dokunulmadı" ile "bakamadık" farklı şeyler.
  files_error?: boolean;
};

export type LogEntry = {
  at: string;
  actor: string;
  via: string;
  action: string;
  entity: string;
  details: string;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * toMessage, herhangi bir hatayı GÖSTERİLEBİLİR bir metne çevirir.
 *
 * ⚠️ Boş dönemez, ve sebebi bir hata değil bir GÜVENLİK özelliği:
 * ErrorLine boş mesajda hiçbir şey çizmiyor, dolayısıyla Error olmayan
 * bir reddediş (bir dize, undefined) BAŞARISIZ bir silme işlemini
 * başarılı olmuş gibi gösteriyordu. Bir bastion'ın yetkilendirme
 * ekranında sessizce başarısız olan bir iptal, olabilecek en kötü
 * arızadır.
 */
export function toMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message || `request failed (${e.status})`;
  // fetch ağ hatasında TypeError atar ve mesajı ("Failed to fetch")
  // kullanıcıya hiçbir şey anlatmaz.
  if (e instanceof TypeError)
    return "could not reach postern — check your connection";
  if (e instanceof Error) return e.message || "request failed";
  const s = String(e);
  return s && s !== "undefined" && s !== "null" ? s : "request failed";
}

/*
 * Oturumun düştüğünü DUYURAN kanal.
 *
 * ⚠️ TEK YERDE olmak zorunda. 401 her uçtan gelebiliyor ve her sayfa
 * onu kendi hata satırında çizdiğinde, oturumu bitmiş kullanıcı yönetim
 * ekranında "Error: unauthenticated" yazısıyla oturup kalıyordu —
 * ekrandaki her şey artık yalan, ama ekran duruyor. Sayfa sayfa
 * yakalamak da işe yaramaz: bir sonraki eklenen sayfa unutulur.
 *
 * ⚠️ OTOMATİK OLARAK IdP'YE YÖNLENDİRMİYORUZ, giriş EKRANINI
 * gösteriyoruz. Kalıcı bir 401 üreten bir arıza (çerez yazılamıyor,
 * saat kayması, vekil yapılandırması) otomatik sıçramayla postern ile
 * IdP arasında çıkışı olmayan bir döngüye dönerdi. Tek tık, döngüsüz.
 */
let sessionLost: (() => void) | null = null;

export function onSessionLost(fn: () => void) {
  sessionLost = fn;
}

function noteStatus(status: number) {
  if (status === 401) sessionLost?.();
}

async function req<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const r = await fetch(path, {
    method,
    headers:
      body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) {
    noteStatus(r.status);
    let msg = r.statusText;
    try {
      msg = (await r.json()).error ?? msg;
    } catch {
      /* gövde JSON değilse statusText kalır */
    }
    throw new ApiError(r.status, msg);
  }
  return r.status === 204 ? (undefined as T) : r.json();
}

/**
 * reqText, JSON DEĞİL düz metin bekleyen uçlar için.
 *
 * Kayıt dosyası NDJSON: her satırı ayrı bir JSON, bütünü değil.
 * r.json() onu ayrıştıramaz.
 */
async function reqText(method: string, path: string): Promise<string> {
  const r = await fetch(path, { method });
  if (!r.ok) {
    noteStatus(r.status);
    let msg = r.statusText;
    try {
      msg = (await r.json()).error ?? msg;
    } catch {
      /* gövde JSON değilse statusText kalır */
    }
    throw new ApiError(r.status, msg);
  }
  return r.text();
}

export const api = {
  me: () => req<Me>("GET", "/api/me"),

  users: () => req<User[]>("GET", "/api/admin/users"),
  createUser: (u: {
    name: string;
    os_user: string;
    email?: string;
    roles?: string[];
    /** ⚠️ Yerel kaynakta cevap giriş bilgisini TAŞIYOR ve tek kez
     *  gösteriliyor. Diğer kaynaklarda yerel kapı kapalı olduğu için
     *  hiçbir değer üretilmiyor. */
  }) => req<CreateUserResult>("POST", "/api/admin/users", u),
  patchUser: (name: string, p: { email?: string; os_user?: string }) =>
    req<void>("PATCH", `/api/admin/users/${encodeURIComponent(name)}`, p),
  deleteUser: (name: string) =>
    req<void>("DELETE", `/api/admin/users/${encodeURIComponent(name)}`),
  assignRole: (user: string, role: string) =>
    req<void>("POST", `/api/admin/users/${encodeURIComponent(user)}/roles`, {
      role,
    }),
  revokeRole: (user: string, role: string) =>
    req<void>(
      "DELETE",
      `/api/admin/users/${encodeURIComponent(user)}/roles/${encodeURIComponent(role)}`,
    ),
  addKey: (user: string, authorized_key: string) =>
    req<void>("POST", `/api/admin/users/${encodeURIComponent(user)}/keys`, {
      authorized_key,
    }),
  userDetail: (name: string) =>
    req<UserDetail>("GET", `/api/admin/users/${encodeURIComponent(name)}`),
  /** Parmak iziyle silme: detay ekranı anahtarları parmak izleriyle
   *  listeliyor, dolayısıyla "şunu kaldır" demenin doğal yolu bu. */
  removeKeyByFingerprint: (user: string, fingerprint: string) =>
    req<void>(
      "POST",
      `/api/admin/users/${encodeURIComponent(user)}/keys/remove`,
      { fingerprint },
    ),

  roles: () => req<Role[]>("GET", "/api/admin/roles"),
  createRole: (r: { name: string; targets?: string[] }) =>
    req<void>("POST", "/api/admin/roles", r),
  deleteRole: (name: string) =>
    req<void>("DELETE", `/api/admin/roles/${encodeURIComponent(name)}`),
  grantTarget: (role: string, target: string) =>
    req<void>("POST", `/api/admin/roles/${encodeURIComponent(role)}/targets`, {
      target,
    }),
  revokeTarget: (role: string, target: string) =>
    req<void>(
      "DELETE",
      `/api/admin/roles/${encodeURIComponent(role)}/targets/${encodeURIComponent(target)}`,
    ),

  targets: () => req<Target[]>("GET", "/api/admin/targets"),
  myTargets: () => req<MyTarget[]>("GET", "/api/targets"),
  myTarget: (name: string) =>
    req<MyTargetDetail>("GET", `/api/targets/${encodeURIComponent(name)}`),
  scanHostKey: (host: string, port: number) =>
    req<ScannedKey>("POST", "/api/admin/targets/scan", { host, port }),
  targetDetail: (name: string) =>
    req<TargetDetail>("GET", `/api/admin/targets/${encodeURIComponent(name)}`),
  createTarget: (t: {
    name: string;
    host: string;
    port?: number;
    host_key: string;
    labels?: Record<string, string>;
  }) => req<void>("POST", "/api/admin/targets", t),
  deleteTarget: (name: string) =>
    req<void>("DELETE", `/api/admin/targets/${encodeURIComponent(name)}`),
  setTargetLabel: (name: string, key: string, value: string) =>
    req<void>(
      "PUT",
      `/api/admin/targets/${encodeURIComponent(name)}/labels/${encodeURIComponent(key)}`,
      { value },
    ),
  removeTargetLabel: (name: string, key: string) =>
    req<void>(
      "DELETE",
      `/api/admin/targets/${encodeURIComponent(name)}/labels/${encodeURIComponent(key)}`,
    ),

  mappings: () => req<Mapping[]>("GET", "/api/admin/mappings"),
  addMapping: (group: string, role: string) =>
    req<void>("POST", "/api/admin/mappings", { group, role }),
  removeMapping: (group: string, role: string) =>
    req<void>(
      "DELETE",
      `/api/admin/mappings/${encodeURIComponent(group)}/${encodeURIComponent(role)}`,
    ),
  unmappedGroups: () =>
    req<UnmappedGroup[]>("GET", "/api/admin/unmapped-groups"),

  settings: () => req<Setting[]>("GET", "/api/admin/settings"),
  setSetting: (key: string, value: string) =>
    req<{ ok: boolean; source: string }>("PUT", "/api/admin/settings", {
      key,
      value,
    }),
  /** ADAY yapılandırmayı sınar — saklananı değil. Düzenleme ekranı
   *  buna dayanıyor: sınanmamış değişiklik canlıya çıkmasın. */
  verifyLDAP: (cfg: LDAPCandidate) =>
    req<LDAPTestResult>("POST", "/api/admin/ldap/verify", cfg),
  authMethods: () => req<AuthMethods>("GET", "/api/auth/methods"),
  oidcSettings: () => req<OIDCSettings>("GET", "/api/admin/oidc"),
  /** client_secret undefined ise DEĞİŞTİRİLMEZ (boş dize "temizle"
   *  demek değil: sırsız public client geçerli bir kurulum). */
  setOIDCSettings: (
    issuer_url: string,
    client_id: string,
    client_secret?: string,
    /** Boş dize "varsayılana dön" demek; gönderilmemesi "dokunma". */
    groups_claim?: string,
    scopes?: string,
  ) =>
    req<{ ok: boolean; live: boolean; error: string }>(
      "PUT",
      "/api/admin/oidc",
      {
        issuer_url,
        client_id,
        ...(client_secret === undefined ? {} : { client_secret }),
        ...(groups_claim === undefined ? {} : { groups_claim }),
        ...(scopes === undefined ? {} : { scopes }),
      },
    ),
  completeSetup: () =>
    req<{ ok: boolean }>("POST", "/api/admin/setup/complete", {}),
  authSource: () => req<AuthSourceStatus>("GET", "/api/admin/auth/source"),

  /** Kendi parolamı değiştir. Zorunlu değişiklik kısıtından çıkışın
   *  TEK yolu — mevcut değeri de istiyor. */
  changePassword: (current: string, next: string) =>
    req<{ ok: true }>("POST", "/api/me/password", { current, new: next }),

  /** Giriş bilgisini SIFIRLA ("parolamı unuttum"). Yönetici
   *  hesaplarında sunucu reddediyor: onların kimlik bilgisi acil durum
   *  kapısı ve yalnızca host'tan çıkabiliyor. */
  resetCredential: (name: string) =>
    req<IssuedCredential>(
      "POST",
      `/api/admin/users/${encodeURIComponent(name)}/credential`,
    ),
  /** ⚠️ Kaynağı çevirmeden ÖNCE çağrılır: oturum zaten açıkken kendi
   *  dizin kimliğini bağlar, yani kurulumu yapan kişi kendini dışarıda
   *  bırakmaz. */
  bindOwnDirectory: (username: string, password: string) =>
    req<{ ok: boolean; identity: string; directory_username: string }>(
      "POST",
      "/api/admin/auth/bind-directory",
      { username, password },
    ),
  setAuthSource: (source: string) =>
    req<{ ok: boolean; source: string; note: string }>(
      "POST",
      "/api/admin/auth/source",
      { source },
    ),
  myKeys: () => req<MyKeys>("GET", "/api/me/keys"),
  totpStatus: () => req<TOTPStatus>("GET", "/api/me/totp"),
  totpBegin: (reauth?: string) =>
    req<TOTPEnrolment>("POST", "/api/me/totp/begin", { reauth: reauth ?? "" }),
  totpConfirm: (code: string) =>
    req<void>("POST", "/api/me/totp/confirm", { code }),
  totpDisable: (code: string) =>
    req<void>("POST", "/api/me/totp/disable", { code }),
  /* reauth: yerel sır. code: TOTP kodu. Hangisinin isteneceğini
     myKeys().reauth_totp söylüyor. */
  addMyKey: (authorized_key: string, reauth?: string, code?: string) =>
    req<{ ok: boolean }>("POST", "/api/me/keys", {
      authorized_key,
      reauth: reauth ?? "",
      code: code ?? "",
    }),
  /** Kendi anahtarımı parmak iziyle sil. Liste ucu metni değil parmak
   *  izini döndürüyor, dolayısıyla panelin elindeki tek tanımlayıcı bu. */
  removeMyKeyByFingerprint: (fingerprint: string) =>
    req<{ ok: true }>("POST", "/api/me/keys/remove", { fingerprint }),
  localLogin: (username: string, secret: string) =>
    req<{ ok: boolean }>("POST", "/auth/local", { username, secret }),
  syncSettings: () => req<SyncSettings>("GET", "/api/admin/sync/settings"),
  syncRuns: (limit = 20) =>
    req<SyncRun[]>("GET", `/api/admin/sync/runs?limit=${limit}`),
  checkLDAPConnection: () =>
    req<{ ok: boolean; error?: string }>(
      "POST",
      "/api/admin/ldap/check-connection",
    ),
  testLDAP: (user?: string) =>
    req<LDAPTestResult>("POST", "/api/admin/ldap/test", { user: user ?? "" }),

  adminGroup: () => req<AdminGroupStatus>("GET", "/api/admin/ldap/admin-group"),
  previewAdminGroup: (group: string) =>
    req<AdminGroupPreview>("POST", "/api/admin/ldap/admin-group/preview", {
      group,
    }),
  /** ⚠️ confirm, panelin GÖSTERDİĞİ listedir ve sunucu onu yeniden
   *  hesaplayıp karşılaştırır. Eşleşmezse 409 döner: onaylanan küme
   *  artık geçerli değil, yeniden bakılmalı. */
  /** confirm: kaydedenin GÖRDÜĞÜ yönetici listesi. Sayılamayan bir
   *  kaynakta (OIDC claim'i) böyle bir liste yok — boş gönderilir ve
   *  sunucu `deferred: true` döner: kimse şimdi yönetici olmuyor,
   *  herkes kendi bir sonraki girişinde değerlendiriliyor. */
  setAdminGroup: (group: string, confirm: string[]) =>
    req<{
      ok: boolean;
      group: string;
      granted: string[];
      revoked: string[];
      deferred?: boolean;
    }>("POST", "/api/admin/ldap/admin-group", { group, confirm }),
  pending: () => req<PendingUser[]>("GET", "/api/admin/pending"),
  approvePending: (id: string, os_user?: string) =>
    req<{ ok: boolean; username: string; note: string }>(
      "POST",
      "/api/admin/pending/approve",
      { id, os_user: os_user ?? "" },
    ),
  rejectPending: (id: string, reason: string) =>
    req<{ ok: boolean }>("POST", "/api/admin/pending/reject", { id, reason }),
  /** Reddi geri alır: satır tamamen silinir ve kişi yeniden başvurabilir. */
  forgetPending: (id: string) =>
    req<{ ok: boolean }>("POST", "/api/admin/pending/forget", { id }),

  setUserState: (name: string, state: "active" | "inactive" | "deleted") =>
    req<{ ok: boolean }>(
      "POST",
      `/api/admin/users/${encodeURIComponent(name)}/state`,
      { state },
    ),

  /** ⚠️ Satırı SİLMİYOR, adı serbest bırakıyor: denetim kaydı kullanıcı
   *  adını metin olarak sakladığı için satır yok olursa geçmiş
   *  okunamaz hâle gelirdi. */
  purgeUser: (name: string) =>
    req<{
      ok: boolean;
      keys_released: number;
      roles_released: number;
      note: string;
    }>("POST", `/api/admin/users/${encodeURIComponent(name)}/purge`, {}),

  sessions: () => req<Session[]>("GET", "/api/admin/sessions"),
  sessionDetail: (id: string) =>
    req<SessionDetail>("GET", `/api/admin/sessions/${encodeURIComponent(id)}`),
  /** Canlı oturumu kapatır. DELETE DEĞİL: oturum satırı silinmiyor,
   *  denetim izi olarak kalıyor; duran şey akışın kendisi. */
  terminateSession: (id: string) =>
    req<{ ok: boolean }>(
      "POST",
      `/api/admin/sessions/${encodeURIComponent(id)}/terminate`,
    ),
  // Kaydın kendisi: asciicast v2, satır satır JSON — düz metin olarak
  // alınıyor (bkz. reqText).
  sessionRecording: (id: string) =>
    reqText("GET", `/api/admin/sessions/${encodeURIComponent(id)}/recording`),
  /** Kullanıcının ikinci faktörünü sıfırla — telefonunu kaybedenin yolu. */
  resetUserTOTP: (name: string) =>
    req<void>(
      "POST",
      `/api/admin/users/${encodeURIComponent(name)}/totp/reset`,
    ),
  adminLog: () => req<LogEntry[]>("GET", "/api/admin/log"),
};

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
};
export type User = { name: string; os_user: string; admin: boolean; roles: string[]; keys: number };
export type Role = { name: string; targets: string[] };
export type Target = {
  name: string; host: string; port: number; fingerprint: string;
  // Sunucu nil map yerine {} döndürüyor: null gelseydi Object.entries
  // her satırda patlardı.
  labels: Record<string, string>;
};
export type Session = {
  id: string; user: string; target: string; os_user: string;
  src_ip: string; started_at: string; ended_at: string | null;
};
export type Mapping = { group: string; role: string; created_by: string };
export type UnmappedGroup = { name: string; seen_count: number; last_seen: string };
export type Setting = { key: string; value: string; secret: boolean; updated_by: string };
export type LDAPTestResult = {
  ok: boolean;
  error?: string;
  groups?: string[];
  roles?: string[];
  unmapped?: string[];
};

export type RecordingState = "none" | "missing" | "partial" | "complete";

export type SessionDetail = Session & {
  recording: { state: RecordingState; size: number };
};

export type LogEntry = {
  at: string; actor: string; via: string; action: string; entity: string; details: string;
};

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
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
  if (e instanceof TypeError) return "could not reach postern — check your connection";
  if (e instanceof Error) return e.message || "request failed";
  const s = String(e);
  return s && s !== "undefined" && s !== "null" ? s : "request failed";
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error ?? msg; } catch { /* gövde JSON değilse statusText kalır */ }
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
    let msg = r.statusText;
    try { msg = (await r.json()).error ?? msg; } catch { /* gövde JSON değilse statusText kalır */ }
    throw new ApiError(r.status, msg);
  }
  return r.text();
}

export const api = {
  me: () => req<Me>("GET", "/api/me"),

  users: () => req<User[]>("GET", "/api/admin/users"),
  createUser: (u: { name: string; os_user: string; email?: string; roles?: string[] }) =>
    req<void>("POST", "/api/admin/users", u),
  patchUser: (name: string, p: { email?: string; os_user?: string }) =>
    req<void>("PATCH", `/api/admin/users/${encodeURIComponent(name)}`, p),
  deleteUser: (name: string) => req<void>("DELETE", `/api/admin/users/${encodeURIComponent(name)}`),
  assignRole: (user: string, role: string) =>
    req<void>("POST", `/api/admin/users/${encodeURIComponent(user)}/roles`, { role }),
  revokeRole: (user: string, role: string) =>
    req<void>("DELETE", `/api/admin/users/${encodeURIComponent(user)}/roles/${encodeURIComponent(role)}`),
  addKey: (user: string, authorized_key: string) =>
    req<void>("POST", `/api/admin/users/${encodeURIComponent(user)}/keys`, { authorized_key }),
  removeKey: (user: string, authorized_key: string) =>
    req<void>("POST", `/api/admin/users/${encodeURIComponent(user)}/keys/remove`, { authorized_key }),

  roles: () => req<Role[]>("GET", "/api/admin/roles"),
  createRole: (r: { name: string; targets?: string[] }) => req<void>("POST", "/api/admin/roles", r),
  deleteRole: (name: string) => req<void>("DELETE", `/api/admin/roles/${encodeURIComponent(name)}`),
  grantTarget: (role: string, target: string) =>
    req<void>("POST", `/api/admin/roles/${encodeURIComponent(role)}/targets`, { target }),
  revokeTarget: (role: string, target: string) =>
    req<void>("DELETE", `/api/admin/roles/${encodeURIComponent(role)}/targets/${encodeURIComponent(target)}`),

  targets: () => req<Target[]>("GET", "/api/admin/targets"),
  createTarget: (t: {
    name: string; host: string; port?: number; host_key: string;
    labels?: Record<string, string>;
  }) =>
    req<void>("POST", "/api/admin/targets", t),
  deleteTarget: (name: string) => req<void>("DELETE", `/api/admin/targets/${encodeURIComponent(name)}`),
  setTargetLabel: (name: string, key: string, value: string) =>
    req<void>("PUT",
      `/api/admin/targets/${encodeURIComponent(name)}/labels/${encodeURIComponent(key)}`,
      { value }),
  removeTargetLabel: (name: string, key: string) =>
    req<void>("DELETE",
      `/api/admin/targets/${encodeURIComponent(name)}/labels/${encodeURIComponent(key)}`),

  mappings: () => req<Mapping[]>("GET", "/api/admin/mappings"),
  addMapping: (group: string, role: string) =>
    req<void>("POST", "/api/admin/mappings", { group, role }),
  removeMapping: (group: string, role: string) =>
    req<void>("DELETE",
      `/api/admin/mappings/${encodeURIComponent(group)}/${encodeURIComponent(role)}`),
  unmappedGroups: () => req<UnmappedGroup[]>("GET", "/api/admin/unmapped-groups"),

  settings: () => req<Setting[]>("GET", "/api/admin/settings"),
  setSetting: (key: string, value: string) =>
    req<{ ok: boolean; source: string }>("PUT", "/api/admin/settings", { key, value }),
  testLDAP: (user?: string) =>
    req<LDAPTestResult>("POST", "/api/admin/ldap/test", { user: user ?? "" }),

  sessions: () => req<Session[]>("GET", "/api/admin/sessions"),
  sessionDetail: (id: string) =>
    req<SessionDetail>("GET", `/api/admin/sessions/${encodeURIComponent(id)}`),
  // Kaydın kendisi: asciicast v2, satır satır JSON — düz metin olarak
  // alınıyor (bkz. reqText).
  sessionRecording: (id: string) =>
    reqText("GET", `/api/admin/sessions/${encodeURIComponent(id)}/recording`),
  adminLog: () => req<LogEntry[]>("GET", "/api/admin/log"),
};

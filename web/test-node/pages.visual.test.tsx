import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import App from "../src/App";
import {
  ApiError,
  api,
  type Grant,
  type LogEntry,
  type Me,
  type PendingUser,
  type Session,
  type SessionDetail,
  type Target,
  type TargetDetail,
  type User,
  type UserDetail,
} from "../src/api";

/*
 * SAYFA DÜZEYİNDE GÖRSEL ÇIKTI — visual.test.tsx'in kart düzeyindeki
 * aracının bütün panele uygulanmış hâli.
 *
 * ⚠️ NEDEN VAR: kart tek başına doğru görünürken kabuğun içinde
 * (üst çubuk + Settings yan listesi + kartın gerçek sütun genişliği)
 * taşabiliyor. Kullanıcının bulduğu kozmetik hataların hepsi tam
 * sayfada, gerçek veriyle ortaya çıktı — yalnız bileşen değil, sayfa
 * bakılabilir olmalı.
 *
 * Her sayfa <App /> üzerinden, gerçek gezinmeyle (sekme + bölüm
 * düğmeleri) açılıyor ve gövdenin HTML'i gerçek stil dosyasıyla
 * .visual/pages/<ad>.<tema>.html olarak yazılıyor. Yanına
 * <ad>.controls.json: sayfadaki düğme/bağlantı adları — bir sonraki
 * turda hangi düğmeye basılacağını buradan görüyoruz.
 *
 * ⚠️ VERİ KASITLI OLARAK UZUN VE KALABALIK: uzun kullanıcı adı, IPv6
 * adres, 200 karakterlik hata cümlesi, altı rol, çok etiket. Kısa
 * örnek veriyle her şey sığar; sığmayan yeri ancak sığmayacak veri
 * gösterir.
 *
 * ⚠️ MOCKLANMAMIŞ HER API ÇAĞRISI "visual: <ad> not mocked" diye
 * REDDEDİLİYOR, sessizce boş dönmüyor. Böylece eksik fikstür sayfada
 * kırmızı bir satır olarak görünüyor ve _gaps.json'a düşüyor; yoksa
 * "boş liste" ile "fikstürü unuttum" ayırt edilemezdi.
 *
 * ⚠️ BU BİR TEST DEĞİL, BİR ARAÇ (visual.test.tsx ile aynı gerekçe).
 * Tek iddiası her sayfanın yazılmış olması.
 */

vi.mock("../src/Terminal", () => ({
  default: () => <div className="terminal-stub" style={{ flex: 1, minHeight: 480 }} />,
}));

const OUT = path.resolve(process.cwd(), ".visual/pages");
const css = () => fs.readFileSync(path.resolve(process.cwd(), "src/styles.css"), "utf8");

const written: string[] = [];
const gaps: Record<string, string[]> = {};

/*
 * Sayfaya gömülen ölçüm: window.__check() yerleşim kusurlarını sayar.
 *
 * ⚠️ GÖZLE BAKMANIN YERİNE DEĞİL, ÖNÜNE: 41 sayfa × 3 genişlik × 2 tema
 * ekran görüntüsü, bakan kişinin dikkatini ilk on sayfada bitiriyor.
 * Bu sayım "nereye bakılacak"ı söylüyor; kusurun kendisi yine gözle
 * doğrulanıyor. Dört sınıf:
 *   beyond  — kutu görüntü alanının sağından taşıyor (sayfa yatay kayar)
 *   clipped — overflow:hidden bir kutunun içeriği kesiliyor
 *   spill   — overflow:visible bir kutunun metni kendi sınırından dışarı akıyor
 *   overlap — iki kardeş kutu üst üste biniyor
 * Kaydırma sarmalayıcısı (.table-wrap gibi) içindekiler sayılmıyor: orada
 * taşma tasarımın kendisi.
 */
const CHECK_JS = `
window.__check = function () {
  var vw = document.documentElement.clientWidth;
  var out = [];
  var seen = {};
  function sel(el) {
    var s = el.tagName.toLowerCase();
    if (el.className && typeof el.className === "string") {
      var cls = el.className.trim().split(/\\s+/).slice(0, 3).join(".");
      if (cls) s += "." + cls;
    }
    return s;
  }
  function path(el) {
    var parts = [];
    var e = el;
    for (var i = 0; i < 4 && e && e !== document.body; i++) { parts.unshift(sel(e)); e = e.parentElement; }
    return parts.join(" > ");
  }
  function inScroller(el) {
    var e = el.parentElement;
    while (e && e !== document.body) {
      var o = getComputedStyle(e).overflowX;
      if (o === "auto" || o === "scroll") return true;
      e = e.parentElement;
    }
    return false;
  }
  function push(k, el, extra) {
    var key = k + "|" + path(el);
    if (seen[key]) return;
    seen[key] = 1;
    var t = (el.textContent || "").trim().replace(/\\s+/g, " ").slice(0, 50);
    out.push(Object.assign({ k: k, el: path(el), text: t }, extra));
  }
  var all = document.body.querySelectorAll("*");
  for (var i = 0; i < all.length; i++) {
    var el = all[i];
    if (el.tagName === "SCRIPT" || el.tagName === "STYLE" || el.tagName === "SVG" || el.closest("svg")) continue;
    var r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    var cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") continue;
    if (el.classList.contains("sr-only")) continue;
    if (r.right > vw + 1 && !inScroller(el)) push("beyond", el, { right: Math.round(r.right), vw: vw });
    if (el.scrollWidth > el.clientWidth + 2) {
      var form = /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName);
      // Kaydırma sarmalayıcısı tasarım gereği kayar; yine de KAÇ piksel
      // kaydığı raporlanıyor — 1280'de 700px kayan bir tablo bir bulgu.
      if (/auto|scroll/.test(cs.overflowX)) push("scrolls", el, { over: el.scrollWidth - el.clientWidth });
      else if (inScroller(el) || form) { /* kabın içinde ya da form alanı: beklenen */ }
      else if (/hidden|clip/.test(cs.overflowX)) push("clipped", el, { over: el.scrollWidth - el.clientWidth });
      else if (cs.overflowX === "visible" && cs.display !== "inline") push("spill", el, { over: el.scrollWidth - el.clientWidth });
    }
  }
  // Kardeş kutuların üst üste binmesi: yalnızca blok/flex çocuklar.
  var parents = document.body.querySelectorAll("*");
  for (var p = 0; p < parents.length; p++) {
    var kids = [].slice.call(parents[p].children).filter(function (c) {
      var d = getComputedStyle(c).display;
      // <dialog> anlık görüntüde üst katmanda DEĞİL (showModal çağrılmadı),
      // içeriğin üstüne düşmesi beklenen; arama kutusunun × düğmesi de
      // kutunun içine bilerek konmuş.
      if (c.tagName === "DIALOG" || c.classList.contains("search-clear")) return false;
      return c.tagName !== "SCRIPT" && d !== "none" && d !== "inline" && d !== "contents";
    });
    for (var a = 0; a < kids.length; a++) {
      for (var b = a + 1; b < kids.length; b++) {
        var ra = kids[a].getBoundingClientRect(), rb = kids[b].getBoundingClientRect();
        if (ra.width === 0 || rb.width === 0 || ra.height === 0 || rb.height === 0) continue;
        var ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
        var oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
        if (ox > 4 && oy > 4) push("overlap", kids[b], { with: sel(kids[a]), ox: Math.round(ox), oy: Math.round(oy) });
      }
    }
  }
  return { vw: vw, pageScroll: document.documentElement.scrollWidth > vw + 1, n: out.length, items: out.slice(0, 20) };
};
`;

/** İki temayı da diske yazar; denetim yardımcıları için kontrol listesini ekler. */
function page(name: string) {
  fs.mkdirSync(OUT, { recursive: true });
  const body = document.body.innerHTML;
  for (const theme of ["light", "dark"]) {
    fs.writeFileSync(
      path.join(OUT, `${name}.${theme}.html`),
      `<!doctype html>
<html lang="en" data-theme="${theme}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${name} (${theme})</title>
<style>${css()}</style>
</head>
<body>${body}<script>${CHECK_JS}</script></body>
</html>
`,
    );
  }
  const controls = Array.from(
    document.querySelectorAll("button, a, [role=menuitem], input, select, textarea, summary"),
  ).map((el) => {
    const tag = el.tagName.toLowerCase();
    const label =
      el.getAttribute("aria-label") ||
      el.getAttribute("placeholder") ||
      el.textContent?.trim().replace(/\s+/g, " ").slice(0, 60) ||
      "";
    return `${tag}: ${label}`;
  });
  fs.writeFileSync(path.join(OUT, `${name}.controls.json`), JSON.stringify(controls, null, 1));

  const text = document.body.textContent ?? "";
  const missing = Array.from(text.matchAll(/visual: (\w+) not mocked/g)).map((m) => m[1]);
  if (missing.length > 0) gaps[name] = Array.from(new Set(missing));
  written.push(name);
}

/** Mock'lanan istekler anında çözülüyor; birkaç makro görev yeter. */
async function settle() {
  for (let i = 0; i < 5; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 15));
    });
  }
}

type Fixtures = Partial<Record<keyof typeof api, unknown>>;

/** Her api üyesini mock'lar: fikstürü olan çözülür, olmayan reddedilir. */
function mockAll(fix: Fixtures) {
  const target = api as unknown as Record<string, (...a: unknown[]) => unknown>;
  for (const k of Object.keys(api)) {
    if (k in fix) {
      const v = fix[k as keyof typeof api];
      if (typeof v === "function") {
        vi.spyOn(target, k).mockImplementation(v as (...a: unknown[]) => unknown);
      } else {
        vi.spyOn(target, k).mockImplementation(() => Promise.resolve(structuredClone(v)));
      }
    } else {
      vi.spyOn(target, k).mockImplementation(() =>
        Promise.reject(new ApiError(500, `visual: ${k} not mocked`)),
      );
    }
  }
}

const click = (name: string | RegExp) => {
  fireEvent.click(screen.getByRole("button", { name }));
};

/** Varsa tıklar; yoksa sessizce false döner (düğme adı keşfediliyor). */
const tryClick = (re: RegExp): boolean => {
  const b = screen.queryAllByRole("button").find((el) => re.test(el.textContent ?? "") || re.test(el.getAttribute("aria-label") ?? ""));
  if (!b) return false;
  fireEvent.click(b);
  return true;
};

/* ------------------------------------------------------------------ */
/* Fikstürler                                                          */
/* ------------------------------------------------------------------ */

const T = (h: number, m = 0) => `2026-09-13T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:00Z`;

const LONG_HOST = "prod-eu-west-1-database-replica-02.internal.example.com";
const LONG_ERR =
  "upstream.DialManagement: target prod-eu-west-1-database-replica-02: upstream: target unreachable: dial tcp 10.42.7.19:22: connect: no route to host (after 3 attempts over 2m10s)";

const meAdmin: Me = {
  name: "yigit.basalma",
  os_user: "ybasalma",
  admin: true,
  targets: ["web-01", "db-primary"],
  terminal_enabled: true,
  files_enabled: true,
  files_write_enabled: true,
  public_key_login: true,
  ssh_host: "bastion.ops.example.internal",
  ssh_port: 2222,
  dir_bound: false,
  can_change_password: true,
  password_policy: { min_length: 12, max_length: 128, min_distinct: 6 },
  jit_enabled: true,
};

const meUser: Me = { ...meAdmin, name: "ayse.yilmaz-demirtas", os_user: "ayse", admin: false };

const labelsBig = {
  env: "production",
  team: "platform-infrastructure-and-reliability",
  region: "eu-west-1",
  role: "database",
  owner: "sre-oncall@example.com",
  "cost-center": "CC-4471-EMEA",
};

const myTargets = [
  { name: "web-01", labels: { env: "prod", team: "web" }, server_version: "SSH-2.0-OpenSSH_9.6", last_seen_at: T(9, 12) },
  { name: LONG_HOST, labels: labelsBig, server_version: "SSH-2.0-OpenSSH_8.0p1 Rocky Linux 8", last_seen_at: T(8, 3) },
  { name: "db-primary", labels: { env: "prod", role: "database" }, server_version: "SSH-2.0-OpenSSH_9.3", last_seen_at: T(7) },
  { name: "cache-03", labels: {}, server_version: undefined, last_seen_at: undefined },
  { name: "build-runner-linux-amd64-07", labels: { env: "ci", pool: "linux-amd64-large-memory-runners" }, server_version: "SSH-2.0-OpenSSH_9.6", last_seen_at: T(6, 45) },
  { name: "demo-a", labels: { env: "demo" }, server_version: "SSH-2.0-OpenSSH_9.9", last_seen_at: T(10, 1) },
  { name: "demo-b", labels: { env: "demo" }, server_version: "SSH-2.0-OpenSSH_9.9" },
];

const roles = [
  { name: "sre", targets: ["web-01", LONG_HOST, "db-primary", "cache-03", "build-runner-linux-amd64-07"] },
  { name: "dba", targets: ["db-primary", LONG_HOST] },
  { name: "readonly-auditors-emea", targets: [] },
  { name: "web", targets: ["web-01"] },
  { name: "ci", targets: ["build-runner-linux-amd64-07"] },
  { name: "demo", targets: ["demo-a", "demo-b"] },
];

const users: User[] = [
  { name: "yigit.basalma", os_user: "ybasalma", admin: true, roles: ["sre", "dba", "web", "ci", "demo", "readonly-auditors-emea"], keys: 3, state: "active", last_confirmed: T(9) },
  { name: "ayse.yilmaz-demirtas", os_user: "ayse", admin: false, roles: ["dba"], keys: 1, state: "active", last_confirmed: T(8) },
  { name: "veli", os_user: "veli", admin: false, roles: [], keys: 0, state: "active" },
  { name: "mehmet.kaya", os_user: "mkaya", admin: false, roles: ["web", "ci"], keys: 2, state: "inactive", last_confirmed: "2026-07-01T10:00:00Z" },
  { name: "svc-backup-nightly-runner", os_user: "svcbackup", admin: false, roles: ["sre"], keys: 1, state: "active", last_confirmed: T(1) },
  { name: "deleted.person", os_user: "dperson", admin: false, roles: [], keys: 0, state: "deleted" },
  { name: "ops", os_user: "ops", admin: true, roles: ["sre"], keys: 1, state: "active", last_confirmed: T(9, 30) },
  { name: "auditor.external.kpmg", os_user: "auditor", admin: false, roles: ["readonly-auditors-emea"], keys: 1, state: "active", last_confirmed: T(2) },
];

const targets: Target[] = [
  { name: "web-01", host: "10.0.1.11", port: 22, fingerprint: "SHA256:I3mJ5osOLjwSlMDq4UpW+nBcTtBCjux2CiFcN0Mudns", labels: { env: "prod", team: "web" } },
  { name: LONG_HOST, host: LONG_HOST, port: 2222, fingerprint: "SHA256:aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6c", labels: labelsBig },
  { name: "db-primary", host: "10.0.2.5", port: 22, fingerprint: "SHA256:QwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcdEFG", labels: { env: "prod", role: "database" } },
  { name: "cache-03", host: "2001:db8:85a3::8a2e:370:7334", port: 22, fingerprint: "SHA256:zXcVbNmAsDfGhJkLqWeRtYuIoP1234567890QwErTyU", labels: {} },
  { name: "build-runner-linux-amd64-07", host: "runner-07.ci.example.internal", port: 22, fingerprint: "SHA256:MnBvCxZlKjHgFdSaPoIuYtReWq0987654321LkJhGfD", labels: { env: "ci", pool: "linux-amd64-large-memory-runners" } },
  { name: "demo-a", host: "demo-a", port: 22, fingerprint: "SHA256:demoAdemoAdemoAdemoAdemoAdemoAdemoAdemoAdem", labels: { env: "demo" } },
  { name: "demo-b", host: "demo-b", port: 22, fingerprint: "SHA256:demoBdemoBdemoBdemoBdemoBdemoBdemoBdemoBdem", labels: { env: "demo" } },
];

const sessions: Session[] = [
  { id: "s-2026-09-13-0001", user: "yigit.basalma", target: "web-01", os_user: "ybasalma", src_ip: "192.168.1.23", started_at: T(9, 12), ended_at: null, running: true, denied: 0 },
  { id: "s-2026-09-13-0002", user: "ayse.yilmaz-demirtas", target: LONG_HOST, os_user: "ayse", src_ip: "2001:db8:85a3::8a2e:370:7334", started_at: T(9, 2), ended_at: null, running: true, denied: 3, lost: 1 },
  { id: "s-2026-09-13-0003", user: "veli", target: "db-primary", os_user: "veli", src_ip: "10.8.0.4", started_at: T(8, 40), ended_at: T(8, 58), denied: 12 },
  { id: "s-2026-09-13-0004", user: "svc-backup-nightly-runner", target: "cache-03", os_user: "svcbackup", src_ip: "10.0.9.9", started_at: T(1), ended_at: T(1, 4) },
  { id: "s-2026-09-13-0005", user: "ops", target: "demo-a", os_user: "ops", src_ip: "192.168.1.50", started_at: T(7, 30), ended_at: null },
  { id: "s-2026-09-12-0342", user: "auditor.external.kpmg", target: "web-01", os_user: "auditor", src_ip: "203.0.113.77", started_at: "2026-09-12T16:05:00Z", ended_at: "2026-09-12T18:41:00Z", denied: 0, lost: 0 },
  { id: "s-2026-09-12-0341", user: "mehmet.kaya", target: "build-runner-linux-amd64-07", os_user: "mkaya", src_ip: "10.0.3.31", started_at: "2026-09-12T15:00:00Z", ended_at: "2026-09-12T15:02:00Z" },
];

const sessionDetail = (id: string): SessionDetail => ({
  ...(sessions.find((s) => s.id === id) ?? sessions[2]),
  recording: {
    state: "complete",
    size: 4823905,
    chain: "sha256:9f2c1e0b7d4a6c8e1f3b5d7a9c2e4f6081a3c5e7f9b1d3a5c7e9f1b3d5a7c9e1",
    links: 143,
  },
  files: [
    { id: "f1", at: T(8, 41), op: "open", path: "/var/log/nginx/access.log", read: 1048576, wrote: 0, ok: true, in_recording: true },
    { id: "f2", at: T(8, 42), op: "denied.remove", path: "/etc/shadow", read: 0, wrote: 0, ok: false, detail: "role dba: /etc is not allowed", in_recording: true },
    { id: "f3", at: T(8, 44), op: "rename", path: "/srv/app/releases/2026-09-13-1/config.yaml", new_path: "/srv/app/releases/2026-09-13-1/config.yaml.bak", read: 0, wrote: 0, ok: true, in_recording: true },
    { id: "f4", at: T(8, 50), op: "open", path: "/srv/app/releases/2026-09-13-1/very/deeply/nested/directory/structure/that/keeps/going/for/a/while/artifact-linux-amd64.tar.gz", flags: "w", read: 0, wrote: 73400320, ok: true, in_recording: true },
  ],
  journal: { state: "intact", events: 4, rows: 4, lost: 0, detail: "4 events sealed, 4 rows in the ledger", digest_checked: true },
});

const userDetail = (name: string): UserDetail => {
  const u = users.find((x) => x.name === name) ?? users[0];
  return {
    name: u.name,
    os_user: u.os_user,
    email: `${u.name}@very-long-corporate-domain-name.example.com`,
    admin: u.admin,
    admin_via: u.admin ? "group" : "",
    state: u.state ?? "active",
    last_confirmed: u.last_confirmed,
    sso_only: false,
    dir_bound: true,
    roles: roles.filter((r) => u.roles.includes(r.name)),
    keys: [
      { fingerprint: "SHA256:I3mJ5osOLjwSlMDq4UpW+nBcTtBCjux2CiFcN0Mudns", comment: "yigit@macbook-pro-16-2025 work laptop (ed25519)", added_at: "2026-08-01T10:00:00Z" },
      { fingerprint: "SHA256:aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6c", comment: "", added_at: "2026-08-20T10:00:00Z" },
      { fingerprint: "SHA256:QwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcdEFG", comment: "yubikey-5c-nano-backup-key-kept-in-the-office-safe", added_at: T(3) },
    ].slice(0, Math.max(u.keys, 0)),
    sessions: sessions.filter((s) => s.user === u.name).map((s) => ({ id: s.id, target: s.target, started: s.started_at, ended: s.ended_at ?? undefined })),
    credential: { kind: "issued", must_change: true, created_at: T(6), created_by: "ops", last_used_at: undefined },
    totp: { enrolled: true, last_used_at: T(9) },
  };
};

const targetDetail = (name: string): TargetDetail => {
  const t = targets.find((x) => x.name === name) ?? targets[1];
  return {
    ...t,
    facts: {
      server_version: "SSH-2.0-OpenSSH_8.0p1 Rocky Linux 8",
      host_key_type: "ssh-ed25519",
      last_seen_at: T(8, 3),
      connect_ms: 412,
      last_error_at: T(2, 15),
      last_error: LONG_ERR,
      kernel: "Linux 4.18.0-553.16.1.el8_10.x86_64",
      os_name: "Rocky Linux 8.10 (Green Obsidian)",
      probed_at: T(8, 3),
    },
    granted_by: ["sre", "dba", "readonly-auditors-emea"],
    recent_sessions: sessions.slice(0, 5).map((s) => ({ id: s.id, user: s.user, os_user: s.os_user, src_ip: s.src_ip, started_at: s.started_at, ended_at: s.ended_at ?? undefined })),
    recent_partial: true,
    recent_scanned: 200,
    manage_enabled: true,
  };
};

const grants: Grant[] = (() => {
  const g = (over: Partial<Grant>): Grant => ({
    id: "g", username: "ayse.yilmaz-demirtas", target: LONG_HOST, os_user: "ayse", groups: ["dba"],
    granted_by: "yigit.basalma", granted_at: T(10), expires_at: T(18), applied_at: T(10, 1), revoke_attempts: 0, ...over,
  });
  return [
    g({ id: "1" }),
    g({ id: "2", username: "veli", os_user: "veli", groups: ["dba", "docker", "systemd-journal"], expires_at: T(11) }),
    g({ id: "3", applied_at: undefined, apply_report: "1 applied, 1 failed, 2 not attempted" }),
    g({ id: "4", expires_at: "2026-09-12T18:00:00Z", revoke_attempts: 4, revoke_error: "could not connect: " + LONG_ERR }),
    g({ id: "5", revoked_at: T(11, 30), revoke_report: "5 applied" }),
  ];
})();

const pending: PendingUser[] = [
  { id: "p1", subject: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", source: "dir", username: "hasan.demir", email: "hasan.demir@very-long-corporate-domain-name.example.com", seen_groups: ["CN=SRE,OU=Groups,DC=example,DC=com", "CN=Platform Engineering EMEA,OU=Groups,DC=example,DC=com", "vpn-users", "all-staff"], state: "waiting", first_seen: T(6), last_seen: T(9, 55) },
  { id: "p2", subject: "oidc|110234987234", source: "oidc", username: "j.doe", email: "j.doe@example.com", seen_groups: [], state: "waiting", first_seen: T(9, 50), last_seen: T(9, 50) },
  { id: "p3", subject: "f0e1d2c3-b4a5-6789-0fed-cba987654321", source: "dir", username: "contractor.long.name.with.dots", email: "contractor@partner.example.org", seen_groups: ["contractors"], state: "rejected", first_seen: "2026-09-10T08:00:00Z", last_seen: "2026-09-11T08:00:00Z", decided_by: "ops", decided_at: "2026-09-11T09:00:00Z", reason: "Contract not yet countersigned by procurement; re-request once the SOW is on file." },
];

const adminLog: LogEntry[] = Array.from({ length: 18 }, (_, i) => {
  const actions = [
    ["jit.grant", "target/" + LONG_HOST, JSON.stringify({ username: "ayse.yilmaz-demirtas", groups: ["dba"], duration: "8h", sudo: { commands: [{ path: "/usr/bin/systemctl", args: ["restart", "nginx"] }] } })],
    ["user.delete", "user/mehmet.kaya", "{\"reason\":\"left the company\"}"],
    ["target.create", "target/web-01", JSON.stringify({ host: "10.0.1.11", port: 22, fingerprint: "SHA256:I3mJ5osOLjwSlMDq4UpW+nBcTtBCjux2CiFcN0Mudns" })],
    ["session.terminate", "session/s-2026-09-13-0003", "{\"by\":\"panel\"}"],
    ["jit.revoke.failed", "target/" + LONG_HOST, JSON.stringify({ grant: "4", attempt: 4, error: "could not connect: " + LONG_ERR })],
    ["retention.prune", "recordings", "{\"deleted\":12,\"bytes\":734003200}"],
  ][i % 6];
  return { at: T(10 - Math.floor(i / 2), 59 - i), actor: i % 6 === 5 ? "postern" : i % 2 ? "ops" : "yigit.basalma", via: i % 6 === 5 ? "system" : i % 3 ? "web" : "cli", action: actions[0], entity: actions[1], details: actions[2] };
});

const base: Fixtures = {
  me: meAdmin,
  authMethods: { source: "ldap", oidc: false, local: false, ldap: true },
  authSource: {
    source: "ldap",
    stored: true,
    options: [
      { source: "local", eligible: true },
      { source: "oidc", eligible: false, why: "OIDC is not configured: set an issuer and a client id under Identity → OIDC first" },
      { source: "ldap", eligible: true },
    ],
    unseen_mappings: ["CN=Ops Team,OU=Groups,DC=example,DC=com", "sre-oncall"],
  },
  myTargets,
  myTarget: (name: string) => Promise.resolve({ ...(myTargets.find((t) => t.name === name) ?? myTargets[1]), sessions: sessions.slice(0, 6).map((s) => ({ id: s.id, started: s.started_at, ended: s.ended_at ?? undefined, os_user: s.os_user })), sessions_partial: true, sessions_scanned: 200 }),
  users,
  userDetail: (name: string) => Promise.resolve(userDetail(name)),
  roles,
  rolePaths: [
    { prefix: "/var/log", allow: true, can_write: false },
    { prefix: "/etc", allow: false, can_write: false },
    { prefix: "/srv/app/releases/current/very/long/prefix/that/should/wrap/somewhere", allow: true, can_write: true },
  ],
  targets,
  targetDetail: (name: string) => Promise.resolve(targetDetail(name)),
  grants: { grants, now: T(12) },
  allGrants: { grants: [...grants, { ...grants[0], id: "6", target: "web-01", username: "svc-backup-nightly-runner", os_user: "svcbackup", groups: ["backup-operators", "systemd-journal"] }], now: T(12) },
  targetGroups: (name: string) =>
    Promise.resolve({
      target: name, min_gid: 1000, checked_at: T(12),
      groups: [
        { name: "root", gid: 0, members: [], protected: true },
        { name: "wheel", gid: 10, members: ["ops"], protected: true },
        { name: "docker", gid: 998, members: ["veli"], protected: true },
        { name: "dba", gid: 1001, members: ["ayse"], protected: false },
        { name: "developer", gid: 1002, members: [], protected: false },
        ...(name === "web-01" ? [{ name: "web-deployers-with-a-long-group-name", gid: 1003, members: ["mkaya", "ayse"], protected: false }] : []),
      ],
    }),
  checkManagement: {
    target: LONG_HOST, stage: "done", manageable: true, ca_fingerprint: "SHA256:I3mJ5osOLjwSlMDq4UpW+nBcTtBCjux2CiFcN0Mudns", family: "rhel", missing: [],
    tools: { add_user: "/usr/sbin/useradd", add_group: "/usr/sbin/groupadd", mod_user: "/usr/sbin/usermod", del_user: "/usr/sbin/userdel", del_group: "/usr/sbin/groupdel", visudo: "/usr/sbin/visudo" },
    checked_at: T(10, 41),
  },
  mappings: [
    { group: "CN=SRE,OU=Groups,DC=example,DC=com", role: "sre", created_by: "yigit.basalma" },
    { group: "CN=Database Administrators EMEA,OU=Groups,DC=example,DC=com", role: "dba", created_by: "ops" },
    { group: "web-developers", role: "web", created_by: "ops" },
    { group: "ci-runners", role: "ci", created_by: "yigit.basalma" },
    { group: "external-auditors", role: "readonly-auditors-emea", created_by: "ops" },
  ],
  unmappedGroups: [
    { name: "CN=Platform Engineering EMEA,OU=Groups,DC=example,DC=com", seen_count: 41, last_seen: T(9, 55) },
    { name: "vpn-users", seen_count: 380, last_seen: T(9, 58) },
    { name: "all-staff", seen_count: 412, last_seen: T(9, 58) },
    { name: "contractors", seen_count: 3, last_seen: "2026-09-11T08:00:00Z" },
  ],
  settings: [
    { key: "ldap.url", value: "ldaps://ldap-primary.corp.example.internal:636", secret: false, updated_by: "yigit.basalma" },
    { key: "ldap.bind_dn", value: "CN=svc-postern-readonly,OU=Service Accounts,OU=Infrastructure,DC=corp,DC=example,DC=internal", secret: false, updated_by: "yigit.basalma" },
    { key: "ldap.bind_password", value: "", secret: true, updated_by: "yigit.basalma" },
    { key: "ldap.user_base", value: "OU=People,DC=corp,DC=example,DC=internal", secret: false, updated_by: "ops" },
    { key: "ldap.user_filter", value: "(&(objectClass=person)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", secret: false, updated_by: "ops" },
    { key: "ldap.group_attribute", value: "memberOf", secret: false, updated_by: "ops" },
    { key: "ldap.group_base", value: "OU=Groups,DC=corp,DC=example,DC=internal", secret: false, updated_by: "ops" },
    { key: "ldap.group_filter", value: "(objectClass=group)", secret: false, updated_by: "ops" },
    { key: "ldap.group_name_from", value: "cn", secret: false, updated_by: "ops" },
    { key: "ldap.admin_group", value: "postern-admins", secret: false, updated_by: "yigit.basalma" },
    { key: "auth.auto_create", value: "false", secret: false, updated_by: "ops" },
    { key: "sync.enabled", value: "true", secret: false, updated_by: "ops" },
    { key: "sync.interval", value: "15m", secret: false, updated_by: "ops" },
  ],
  oidcSettings: {
    issuer_url: "https://login.microsoftonline.com/9f8e7d6c-5b4a-3210-fedc-ba9876543210/v2.0",
    client_id: "3c7a1f4e-9b2d-4e8f-a1c6-5d2e8f9a0b1c",
    client_secret_set: true, groups_claim: "roles", scopes: "openid email profile groups", managed_in_db: true, configured: true, live: false,
  },
  syncSettings: { enabled: true, dry_run: false, interval: "15m", grace: "72h", max_zero_fraction: 0.2, min_zero_floor: 3, max_unknown_fraction: 0.1, max_revoke_per_run: 20, overridden: ["sync.interval"] },
  syncRuns: [
    { id: 61, started_at: T(9, 45), finished_at: T(9, 45), trigger: "timer", outcome: "ok", reason: "", considered: 42, unknown: 0, revoked: 0, roles_changed: 1, dry_run: false },
    { id: 60, started_at: T(9, 30), finished_at: T(9, 30), trigger: "manual", outcome: "refused", reason: "38 of 42 accounts came back with zero groups (90%); the ceiling is 20%. Nothing was changed — check the group base and filter before running again.", considered: 42, unknown: 0, revoked: 0, roles_changed: 0, dry_run: false },
    { id: 59, started_at: T(9, 15), finished_at: T(9, 16), trigger: "timer", outcome: "ok", reason: "", considered: 42, unknown: 2, revoked: 1, roles_changed: 3, dry_run: true },
    { id: 58, started_at: T(9, 0), finished_at: T(9, 0), trigger: "timer", outcome: "error", reason: "LDAP Result Code 200 \"Network Error\": dial tcp 10.0.0.53:636: i/o timeout", considered: 0, unknown: 0, revoked: 0, roles_changed: 0, dry_run: false },
  ],
  adminGroup: { group: "postern-admins", holders: [{ username: "yigit.basalma", via: "group" }, { username: "ops", via: "cli" }], enumerable: true },
  pending,
  sessions,
  sessionDetail: (id: string) => Promise.resolve(sessionDetail(id)),
  verifyRecording: { local: "verified", detail: "143 links, head matches the sealed chain", chain: "sha256:9f2c1e0b7d4a6c8e1f3b5d7a9c2e4f6081a3c5e7f9b1d3a5c7e9f1b3d5a7c9e1", stored_links: 143, links: 143, off_box: { state: "unchecked", detail: "no archive is configured on this bastion" } },
  storage: { recordings: { files: 1482, bytes: 73400320000, skipped: 2 }, archive: { pending: 12, oldest_at: "2026-09-10T08:00:00Z", oldest_age_seconds: 3 * 86400 + 7200, failing: 2, lost: 1 } },
  archiveStatus: { configured: true, endpoint: "https://s3.eu-central-1.amazonaws.com", bucket: "postern-recordings-production-eu-central-1", prefix: "bastion-1/", destination_managed_in: "postern.yaml", credential_source: "panel", access_key_id: "AKIAIOSFODNN7EXAMPLE", can_set_from_panel: true },
  adminLog,
  fileHistory: {
    path: "/etc", under: true, user: "", target: "", limit: 200, truncated: true,
    events: sessionDetail("s-2026-09-13-0003").files.map((f, i) => ({ ...f, session_id: "s-2026-09-13-0003", user: i % 2 ? "ayse.yilmaz-demirtas" : "", target: i % 2 ? LONG_HOST : "", os_user: "ayse", src_ip: "2001:db8:85a3::8a2e:370:7334" })),
  },
  myKeys: {
    keys: [
      { fingerprint: "SHA256:I3mJ5osOLjwSlMDq4UpW+nBcTtBCjux2CiFcN0Mudns", comment: "yigit@macbook-pro-16-2025 work laptop (ed25519)", added_at: "2026-08-01T10:00:00Z" },
      { fingerprint: "SHA256:QwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcdEFG", comment: "", added_at: T(3) },
    ],
    reauth_required: true, reauth_possible: true, reauth_totp: true,
  },
  webauthnList: { credentials: [{ id: "k1", name: "iş dizüstü — Touch ID", created_at: "2026-09-01T10:00:00Z", last_used_at: T(8, 30) }, { id: "k2", name: "YubiKey 5C NFC (kept in the office safe, second drawer)", created_at: "2026-09-05T10:00:00Z" }], only: false },
  totpStatus: { enrolled: true, pending: false, can_begin: true, needs_fresh_login: false, confirmed_at: "2026-08-15T10:00:00Z", last_used_at: T(9) },
};

/* ------------------------------------------------------------------ */
/* Sayfalar                                                            */
/* ------------------------------------------------------------------ */

beforeEach(() => {
  window.history.replaceState({}, "", "/");
  (window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential = function () {};
  Object.defineProperty(navigator, "credentials", { configurable: true, value: { create: vi.fn(), get: vi.fn() } });
});

afterEach(() => {
  cleanup();
  window.history.replaceState({}, "", "/");
});

const openSettings = async (section?: string | RegExp) => {
  render(<App />);
  await settle();
  click("Settings");
  await settle();
  if (section) {
    click(section);
    await settle();
  }
};

describe("sayfa düzeyinde görsel çıktı", () => {
  it("oturum öncesi ekranlar", async () => {
    mockAll({ ...base, me: () => Promise.reject(new ApiError(401, "unauthenticated")), authMethods: { source: "local", oidc: false, local: true, ldap: false } });
    render(<App />);
    await settle();
    page("signin-local");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: () => Promise.reject(new ApiError(401, "unauthenticated")), authMethods: { source: "oidc", oidc: true, local: false, ldap: false } });
    render(<App />);
    await settle();
    page("signin-oidc");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: () => Promise.reject(new ApiError(500, "pq: the database system is shutting down")) });
    render(<App />);
    await settle();
    page("unreachable");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: () => new Promise(() => {}) });
    render(<App />);
    await settle();
    page("loading");
  });

  it("ana ekran ve hedef sayfası", async () => {
    mockAll(base);
    render(<App />);
    await settle();
    page("home");
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "env: staging" } });
    await settle();
    page("home-nomatch");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: meUser, myTargets: [] });
    render(<App />);
    await settle();
    page("home-empty-user");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: { ...meUser, terminal_enabled: false, ssh_host: undefined } });
    render(<App />);
    await settle();
    tryClick(/shell options for web-01/i);
    await settle();
    page("home-user-noterminal-menu");
    cleanup();
    vi.restoreAllMocks();

    mockAll(base);
    window.history.pushState({}, "", "/target/" + encodeURIComponent(LONG_HOST));
    render(<App />);
    await settle();
    page("target-page");
  });

  it("profil ve zorunlu ekranlar", async () => {
    mockAll({ ...base, authMethods: { source: "local", oidc: false, local: true, ldap: false } });
    render(<App />);
    await settle();
    click("Profile");
    await settle();
    page("profile-local");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: { ...meUser, can_change_password: false, public_key_login: false }, myKeys: { keys: [], reauth_required: false, reauth_possible: false } });
    render(<App />);
    await settle();
    click("Profile");
    await settle();
    page("profile-sso-user");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: { ...meAdmin, must_change_password: true } });
    render(<App />);
    await settle();
    page("must-change-password");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: { ...meAdmin, must_enrol_totp: true }, totpStatus: { enrolled: false, pending: false, can_begin: true, needs_fresh_login: false } });
    render(<App />);
    await settle();
    page("must-enrol-totp");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: { ...meAdmin, setup_required: true }, authSource: { source: "local", stored: false, options: [{ source: "local", eligible: true }, { source: "oidc", eligible: false, why: "OIDC is not configured" }, { source: "ldap", eligible: false, why: "the directory settings are incomplete: ldap.url, ldap.bind_dn" }] } });
    render(<App />);
    await settle();
    page("setup-wizard");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: { ...meUser, setup_required: true } });
    render(<App />);
    await settle();
    page("not-set-up-user");
  });

  it("Settings bölümleri", async () => {
    const sections: [string, string | RegExp][] = [
      ["overview", "Overview"],
      ["users", "Users"],
      ["roles", "Roles"],
      ["mappings", "Mappings"],
      ["pending", "Pending"],
      ["targets", "Targets"],
      ["signin", "Sign-in"],
      ["oidc", "OIDC"],
      ["ldap", "LDAP"],
      ["sessions", "Sessions"],
      ["files", "File history"],
      ["log", "Admin log"],
    ];
    for (const [name, label] of sections) {
      mockAll(base);
      await openSettings(label);
      page(`settings-${name}`);
      cleanup();
      vi.restoreAllMocks();
    }
  });

  it("detay ve alt ekranlar", async () => {
    mockAll(base);
    await openSettings("Users");
    click(users[0].name);
    await settle();
    page("settings-users-detail");
    cleanup();
    vi.restoreAllMocks();

    mockAll(base);
    await openSettings("Targets");
    click(LONG_HOST);
    await settle();
    page("settings-targets-detail");
    tryClick(/check management access/i);
    await settle();
    page("settings-targets-detail-checked");
    cleanup();
    vi.restoreAllMocks();

    mockAll(base);
    await openSettings("Roles");
    if (tryClick(/path/i)) {
      await settle();
      page("settings-roles-paths");
    }
    cleanup();
    vi.restoreAllMocks();

    mockAll(base);
    await openSettings("File history");
    const pathBox = screen.queryByPlaceholderText("/etc/shadow");
    if (pathBox) {
      fireEvent.change(pathBox, { target: { value: "/etc" } });
      const form = pathBox.closest("form");
      if (form) fireEvent.submit(form);
      else tryClick(/search|find|look/i);
      await settle();
      page("settings-files-results");
    }
    cleanup();
    vi.restoreAllMocks();

    mockAll(base);
    await openSettings("Sessions");
    if (tryClick(/verify/i)) {
      await settle();
      page("settings-sessions-verify");
    }
    cleanup();
    vi.restoreAllMocks();

    // Hata hâli: listeler çekilemedi.
    mockAll({ ...base, users: () => Promise.reject(new ApiError(500, "pq: canceling statement due to statement timeout")), roles: () => Promise.reject(new ApiError(403, "forbidden")) });
    await openSettings("Users");
    page("settings-users-error");
    cleanup();
    vi.restoreAllMocks();

    // Boş hâller.
    mockAll({ ...base, users: [], targets: [], roles: [], mappings: [], unmappedGroups: [], pending: [], sessions: [], adminLog: [] });
    await openSettings("Users");
    page("settings-users-empty");
    click("Targets");
    await settle();
    page("settings-targets-empty");
    click("Sessions");
    await settle();
    page("settings-sessions-empty");
    click("Overview");
    await settle();
    page("settings-overview-empty");
  });

  it("geçici erişim sekmesi ve sihirbazı", async () => {
    mockAll(base);
    render(<App />);
    await settle();
    click("Temporary access");
    await settle();
    page("jit");

    click(/new temporary access/i);
    await settle();
    fireEvent.change(screen.getByLabelText(/^Person/), { target: { value: "ayse.yilmaz-demirtas" } });
    const pick = (box: HTMLElement, values: string[]) => {
      for (const o of Array.from((box as HTMLSelectElement).options)) o.selected = values.includes(o.value);
      fireEvent.change(box);
    };
    pick(screen.getByRole("listbox", { name: /^Hosts/ }), ["web-01", LONG_HOST]);
    click(/load groups from the selected hosts/i);
    await settle();
    pick(screen.getByRole("listbox", { name: /^Groups/ }), ["dba", "sre"]);
    fireEvent.change(screen.getByLabelText(/Commands the account may run/), {
      target: { value: "/usr/bin/systemctl restart nginx" },
    });
    page("jit-new");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, allGrants: { grants: [], now: T(12) } });
    render(<App />);
    await settle();
    click("Temporary access");
    await settle();
    page("jit-empty");
  });

  it("kabuk sayfası", async () => {
    // Terminal xterm'e (canvas) dayanıyor ve jsdom'da çizilemiyor; kabuk
    // çubuğu ve dosya düğmesi yine görünmeli.
    mockAll(base);
    window.history.pushState({}, "", "/shell/" + encodeURIComponent(LONG_HOST));
    render(<App />);
    await settle();
    page("shell-page");
  });

  it("ekleme pencereleri", async () => {
    for (const [name, label] of [["users", "Users"], ["targets", "Targets"], ["roles", "Roles"], ["mappings", "Mappings"]] as const) {
      mockAll(base);
      await openSettings(label);
      if (tryClick(/^(add|new|create|map)\b/i)) {
        await settle();
        page(`settings-${name}-add`);
      }
      cleanup();
      vi.restoreAllMocks();
    }
  });

  it("dizin yazıldı", () => {
    fs.mkdirSync(OUT, { recursive: true });
    fs.writeFileSync(path.join(OUT, "_index.json"), JSON.stringify(written, null, 1));
    fs.writeFileSync(path.join(OUT, "_gaps.json"), JSON.stringify(gaps, null, 1));
    /*
     * Koşucu: bütün sayfaları verilen genişliklerde iframe'e yükleyip her
     * birinin __check()'ini toplar. Dizin bir statik sunucudan açılınca
     * (aynı köken) tek çağrıyla 41 sayfa × 3 genişlik ölçülüyor; sayfa
     * sayfa gezip pencereyi yeniden boyutlamak 25-eylemlik gruplar
     * hâlinde bir öğleden sonra sürüyordu.
     */
    fs.writeFileSync(
      path.join(OUT, "_runner.html"),
      `<!doctype html><meta charset="utf-8"><title>visual runner</title>
<body style="margin:0;font:13px system-ui">
<p id="status">call <code>await sweep()</code> (optional: sweep([1280,820,390], "light"))</p>
<script>
async function sweep(widths, theme) {
  widths = widths || [1280, 820, 390];
  theme = theme || "light";
  var index = await (await fetch("_index.json")).json();
  var lines = [];
  for (var n = 0; n < index.length; n++) {
    for (var w = 0; w < widths.length; w++) {
      var f = document.createElement("iframe");
      f.style.cssText = "width:" + widths[w] + "px;height:900px;border:0;display:block";
      f.src = index[n] + "." + theme + ".html";
      document.body.appendChild(f);
      await new Promise(function (r) { f.onload = r; });
      var res = f.contentWindow.__check();
      var items = res.items.filter(function (i) { return !(i.k === "overlap" && /search > input/.test(i.el)); });
      if (res.pageScroll || items.length) {
        lines.push(index[n] + "@" + widths[w] + (res.pageScroll ? " PAGE-SCROLL" : "") + " n=" + items.length + " :: " +
          items.map(function (i) {
            return i.k + " " + i.el + (i.over ? "(+" + i.over + ")" : "") + (i.right ? "(r=" + i.right + ")" : "") +
              (i.with ? "(with " + i.with + " " + i.ox + "x" + i.oy + ")" : "") + ' "' + i.text.slice(0, 40) + '"';
          }).join(" | "));
      }
      f.remove();
    }
  }
  document.getElementById("status").textContent = lines.length + " findings";
  return lines.join("\\n");
}
</script>
</body>`,
    );
    expect(written.length).toBeGreaterThan(20);
  });
});

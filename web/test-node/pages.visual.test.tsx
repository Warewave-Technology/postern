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
  type Setting,
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

// Kayıt oynatıcısı xterm kuruyor ve xterm jsdom'da matchMedia istiyor;
// Terminal.test.tsx'teki taklidin aynısı.
vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    cols = 80;
    rows = 24;
    // Tema efekti term.options.theme'e yazıyor (Terminal.tsx:156).
    options: Record<string, unknown> = {};
    loadAddon() {}
    open() {}
    focus() {}
    write() {}
    writeln() {}
    reset() {}
    resize() {}
    onData() {
      return { dispose() {} };
    }
    dispose() {}
  },
}));
vi.mock("@xterm/addon-fit", () => ({
  FitAddon: class {
    activate() {}
    dispose() {}
    fit() {}
  },
}));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));

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
  /*
   * ⚠️ YAZILAN DEĞER ÖZNİTELİK DEĞİL, ÖZELLİK. innerHTML yalnızca
   * öznitelikleri taşıyor, bu yüzden doldurulmuş bir form anlık
   * görüntüde BOŞ çıkıyordu: etiket tablosunun yazılı satırı ile boş
   * satırı ayırt edilemiyor, tarama da dolu bir formu hiç ölçmemiş
   * oluyordu. Özellikler serileştirmeden önce özniteliğe basılıyor;
   * React denetimli girdilerde özellik değişmediği için ekrandaki
   * durum bozulmuyor.
   */
  for (const el of document.querySelectorAll("input, textarea")) {
    const f = el as HTMLInputElement;
    if (f.type === "checkbox" || f.type === "radio") {
      if (f.checked) f.setAttribute("checked", "");
      else f.removeAttribute("checked");
    } else if (f.value !== "") {
      f.setAttribute("value", f.value);
    }
  }
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
    document.querySelectorAll("button, a, [group=menuitem], input, select, textarea, summary"),
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

/*
 * showDialog, İSTENEN modalı açar — sayfadaki ilkini değil.
 *
 * ⚠️ ÖLÇÜLEN KUSUR: jsdom showModal() çalıştırmıyor, bu yüzden snapshot
 * için `open` elle veriliyordu; ama `querySelector("dialog")` DOM'daki
 * ilk modalı buluyor. Keşif ekranında bu "Edit source" modalı, yani
 * sihirbazın görüntüsüne 69 piksellik boş bir kutu giriyordu ve tarama
 * onu gerçek bir yerleşim kusuru gibi gösteriyordu. Başlığıyla seçiliyor;
 * öbür modallar kapatılıyor.
 */
const showDialog = (re: RegExp) => {
  const all = [...document.querySelectorAll("dialog")];
  for (const d of all) {
    if (re.test(d.textContent ?? "")) d.setAttribute("open", "");
    else d.removeAttribute("open");
  }
};

/** Varsa tıklar; yoksa sessizce false döner (düğme adı keşfediliyor). */
const tryClick = (re: RegExp): boolean => {
  const b = screen.queryAllByRole("button").find((el) => re.test(el.textContent ?? "") || re.test(el.getAttribute("aria-label") ?? ""));
  if (!b) return false;
  fireEvent.click(b);
  return true;
};

/*
 * goProfile, kullanıcı menüsünü açıp profile gider.
 *
 * ⚠️ PROFİL ARTIK SEKMEDE DEĞİL: hesaba ait her şey üst çubuğun
 * sağındaki tek düğmede toplandı (bkz. UserMenu).
 */
const goProfile = () => {
  const button = screen.queryAllByRole("button").find((el) => /^(yigit|ayse)/.test(el.textContent ?? ""));
  if (button) fireEvent.click(button);
  tryClick(/^profile$/i);
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
  { name: "db-primary", labels: { env: "prod", role: "database" }, server_version: "SSH-2.0-OpenSSH_9.3", last_seen_at: T(7), temporary: { until: T(21), granted_by: "ops", groups: ["dba"] } },
  { name: "cache-03", labels: {}, server_version: undefined, last_seen_at: undefined },
  { name: "build-runner-linux-amd64-07", labels: { env: "ci", pool: "linux-amd64-large-memory-runners" }, server_version: "SSH-2.0-OpenSSH_9.6", last_seen_at: T(6, 45) },
  { name: "demo-a", labels: { env: "demo" }, server_version: "SSH-2.0-OpenSSH_9.9", last_seen_at: T(10, 1) },
  { name: "demo-b", labels: { env: "demo" }, server_version: "SSH-2.0-OpenSSH_9.9" },
];

const groups = [
  { name: "sre", targets: ["web-01", LONG_HOST, "db-primary", "cache-03", "build-runner-linux-amd64-07"] },
  {
    name: "dba",
    targets: ["db-primary", LONG_HOST],
    // Kurallı rol: sütunun dolu hâli ve onaylanmış kaçış rozeti ölçülüyor.
    sudo: {
      commands: [
        { command: "/usr/bin/pg_ctl reload", run_as: "postgres" },
        // Riskli satır: işaretin ve sebebinin ekranda ölçülmesi için.
        {
          command: "/usr/bin/less /var/log/postgresql/postgresql.log",
          run_as: "root",
          escape: "escapes to a shell",
        },
      ],
      acknowledged: true,
      updated_by: "yigit.basalma",
      updated_at: T(9),
    },
  },
  { name: "readonly-auditors-emea", targets: [] },
  { name: "web", targets: ["web-01"] },
  { name: "ci", targets: ["build-runner-linux-amd64-07"] },
  { name: "demo", targets: ["demo-a", "demo-b"] },
];

const users: User[] = [
  { name: "yigit.basalma", os_user: "ybasalma", admin: true, groups: ["sre", "dba", "web", "ci", "demo", "readonly-auditors-emea"], keys: 3, state: "active", last_confirmed: T(9) },
  { name: "ayse.yilmaz-demirtas", os_user: "ayse", admin: false, groups: ["dba"], keys: 1, state: "active", last_confirmed: T(8) },
  { name: "veli", os_user: "veli", admin: false, groups: [], keys: 0, state: "active" },
  { name: "mehmet.kaya", os_user: "mkaya", admin: false, groups: ["web", "ci"], keys: 2, state: "inactive", last_confirmed: "2026-07-01T10:00:00Z" },
  { name: "svc-backup-nightly-runner", os_user: "svcbackup", admin: false, groups: ["sre"], keys: 1, state: "active", last_confirmed: T(1) },
  { name: "deleted.person", os_user: "dperson", admin: false, groups: [], keys: 0, state: "deleted" },
  { name: "ops", os_user: "ops", admin: true, groups: ["sre"], keys: 1, state: "active", last_confirmed: T(9, 30) },
  { name: "auditor.external.kpmg", os_user: "auditor", admin: false, groups: ["readonly-auditors-emea"], keys: 1, state: "active", last_confirmed: T(2) },
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
    { id: "f2", at: T(8, 42), op: "denied.remove", path: "/etc/shadow", read: 0, wrote: 0, ok: false, detail: "group dba: /etc is not allowed", in_recording: true },
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
    groups: groups.filter((r) => u.groups.includes(r.name)),
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
  /*
   * Salt-okunur yapılandırma: uzun bir yol, yazılmamış bir ayar ve
   * gizlenen iki alan — üçü de satırın biçimini farklı zorluyor.
   */
  config: {
    path: "/etc/postern/config.yaml",
    groups: [
      {
        title: "SSH listener",
        entries: [
          { key: "listen.addr", value: ":2222", note: "where the bastion listens for SSH" },
          { key: "listen.handshake_timeout", value: "30s", note: "how long a connection may take to authenticate" },
        ],
      },
      {
        title: "Recording",
        entries: [
          { key: "recording.dir", value: "/var/lib/postern/recordings", note: "where session recordings are written" },
          { key: "recording.archive.endpoint", value: "(not set)", note: "where recordings are copied off the box" },
          {
            key: "recording.archive.prefix",
            value: "bastion/eu-west-1/prod/session-recordings",
            note: "the key prefix used there",
          },
        ],
      },
    ],
    withheld: [
      { key: "database.dsn", value: "", note: "carries the database password" },
      { key: "oidc.client_secret", value: "", note: "is a secret" },
    ],
  },
  /*
   * Çan dolu: rozetin rengi ve listenin yerleşimi ancak bekleyen iş
   * varken taranabiliyor. Üç kaynak da temsil ediliyor, çünkü satırın
   * uzunluğu kaynağa göre değişiyor.
   */
  notifications: {
    count: 3,
    items: [
      {
        kind: "identity.pending",
        at: T(6),
        summary: "hasan.demir is waiting for approval",
        detail: "Signed in through dir and has no account here yet; approving one creates it.",
        section: "pending",
      },
      {
        kind: "discovery.new",
        at: T(10),
        summary: "web-01 is waiting to be registered",
        detail: "Found by lab cluster. It becomes a target — and reachable — only once you register it.",
        section: "discovery",
      },
      {
        kind: "grant.revoke_failed",
        at: T(11),
        summary: "ayse could not be removed from prod-eu-west-1-database-replica-02.internal.example.com",
        detail:
          "The access expired but the account is still there after 4 attempt(s): dial tcp 10.42.7.19:22: connect: no route to host",
        section: "jit",
      },
    ],
  },
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
  myTarget: (name: string) => Promise.resolve({ ...(myTargets.find((t) => t.name === name) ?? myTargets[1]), temporary: { until: T(21), granted_by: "ops", groups: ["dba", "developer"] }, sessions: sessions.slice(0, 6).map((s) => ({ id: s.id, started: s.started_at, ended: s.ended_at ?? undefined, os_user: s.os_user })), sessions_partial: true, sessions_scanned: 200 }),
  users,
  userDetail: (name: string) => Promise.resolve(userDetail(name)),
  groups,
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
    { directory_group: "CN=SRE,OU=Groups,DC=example,DC=com", group: "sre", created_by: "yigit.basalma" },
    { directory_group: "CN=Database Administrators EMEA,OU=Groups,DC=example,DC=com", group: "dba", created_by: "ops" },
    { directory_group: "web-developers", group: "web", created_by: "ops" },
    { directory_group: "ci-runners", group: "ci", created_by: "yigit.basalma" },
    { directory_group: "external-auditors", group: "readonly-auditors-emea", created_by: "ops" },
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
    /*
     * ⚠️ SAKLANMIŞ SIR "********" DÖNER, BOŞ DİZGE DEĞİL (store.Settings:
     * "maske boş bırakılmıyor ki arayüz 'değer var' ile 'değer yok'u
     * ayırt edebilsin"). Fikstür boş verdiği için ekran LDAP'ı
     * kurulmamış sayıyor ve kurulmuş hâli hiç taranmıyordu — teşhisi de
     * o yanılttı.
     */
    { key: "ldap.bind_password", value: "********", secret: true, updated_by: "yigit.basalma" },
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
    client_secret_set: true, groups_claim: "groups", scopes: "openid email profile groups", managed_in_db: true, configured: true, live: false,
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
  sessionRecording: '{"version":2,"width":80,"height":24}\n[0.5,"o","$ ls /srv/app\\r\\n"]\n[1.2,"o","releases  shared\\r\\n"]\n[39.0,"o","$ exit\\r\\n"]\n',
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

/*
 * ⚠️ VARSAYILAN 5 SANİYELİK SÜRE BURADA YETMİYOR — ölçüldü. Bu dosya
 * ellinin üzerinde sayfayı iki temada render edip diske yazıyor; tek
 * başına koşarken 3,5 saniye sürüyor, 53 dosyayla birlikte koşarken 5'i
 * aşıyordu. Süre aşımı testi ORTASINDA kesiyor, yani cleanup() hiç
 * çalışmıyor ve BİR SONRAKİ test önceki sayfanın DOM'u ekrandayken
 * başlıyor: ortaya, sebebi bambaşka görünen ikinci bir hata çıkıyor
 * ("yigit.basalma düğmesi bulunamadı"). Uzun bir testin süresini
 * uzatmak, ardından gelen testleri de dürüst tutuyor.
 */
describe("sayfa düzeyinde görsel çıktı", { timeout: 30_000 }, () => {
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
    /*
     * Kullanıcı menüsü AÇIK hâliyle de taranıyor: üst çubuğun sağ ucu
     * artık tek bir düğme ve menüsü, yani orada bir yerleşim kusuru
     * ancak menü açıkken görünür.
     */
    // Bildirim listesi açık hâliyle de taranıyor: rozetin rengi ve üç
    // satırlık düzeni ancak burada görünüyor.
    const bellButton = screen.queryAllByRole("button").find((el) => /waiting for you/i.test(el.getAttribute("aria-label") ?? ""));
    if (bellButton) {
      fireEvent.click(bellButton);
      await settle();
      page("home-notifications");
      fireEvent.click(bellButton);
      await settle();
    }
    const userButton = screen.queryAllByRole("button").find((el) => /^yigit/.test(el.textContent ?? ""));
    if (userButton) {
      fireEvent.click(userButton);
      await settle();
      page("home-usermenu");
      fireEvent.click(userButton);
      await settle();
    }
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
    goProfile();
    await settle();
    page("profile-local");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, me: { ...meUser, can_change_password: false, public_key_login: false }, myKeys: { keys: [], reauth_required: false, reauth_possible: false } });
    render(<App />);
    await settle();
    goProfile();
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
      ["groups", "Groups"],
      ["mappings", "Mappings"],
      ["pending", "Pending"],
      ["targets", "Targets"],
      ["signin", "Sign-in"],
      ["oidc", "OIDC"],
      ["ldap", "LDAP"],
      ["sessions", "Sessions"],
      ["files", "File history"],
      ["log", "Admin log"],
      ["config", "Configuration"],
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
    await openSettings("Groups");
    page("settings-groups");
    cleanup();
    vi.restoreAllMocks();

    /*
     * Rolün sayfası: hedefler, sudo kuralı ve yol kuralları bir arada.
     * Liste yalnızca sayıyor, bu sayfa gösteriyor — yüz hedefli bir rolde
     * ölçülmesi gereken yer burası.
     */
    mockAll(base);
    await openSettings("Groups");
    if (tryClick(/^dba$/i)) {
      await settle();
      page("settings-groups-detail");
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
    // Bir oturumu aç: künye + oynatıcı + dosya olayları listenin üstünde.
    if (tryClick(/watch the recording of veli on db-primary/i)) {
      await settle();
      page("settings-sessions-open");
    }
    if (tryClick(/verify/i)) {
      await settle();
      page("settings-sessions-verify");
    }
    cleanup();
    vi.restoreAllMocks();

    // Hata hâli: listeler çekilemedi.
    mockAll({ ...base, users: () => Promise.reject(new ApiError(500, "pq: canceling statement due to statement timeout")), groups: () => Promise.reject(new ApiError(403, "forbidden")) });
    await openSettings("Users");
    page("settings-users-error");
    cleanup();
    vi.restoreAllMocks();

    // Boş hâller.
    mockAll({ ...base, users: [], targets: [], groups: [], mappings: [], unmappedGroups: [], pending: [], sessions: [], adminLog: [] });
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
    fireEvent.click(screen.getByRole("checkbox", { name: "select all grants" }));
    await settle();
    page("jit-selected");

    click(/new temporary access/i);
    await settle();
    fireEvent.change(screen.getByLabelText(/^Person/), { target: { value: "ayse.yilmaz-demirtas" } });
    fireEvent.focus(screen.getByRole("combobox", { name: "Hosts" }));
    fireEvent.click(screen.getByRole("option", { name: /^web-01/ }));
    fireEvent.click(screen.getByRole("option", { name: new RegExp("^" + LONG_HOST) }));
    fireEvent.mouseDown(document.body);
    click(/load groups from the selected hosts/i);
    await settle();
    // Grup listesi AÇIK kalıyor: görüntüde liste de görünsün.
    fireEvent.focus(screen.getByRole("combobox", { name: "Host groups" }));
    fireEvent.click(screen.getByRole("option", { name: "dba" }));
    fireEvent.click(screen.getByRole("option", { name: "sre" }));
    // Sudo komutları tablo: bir satır dolu, hesabı yazılmış; ikincisi
    // hesabı boş (root) ve üçüncüsü kendiliğinden açılmış boş satır.
    fireEvent.change(screen.getByLabelText(/sudo command 1/i), {
      target: { value: "/usr/bin/systemctl restart nginx" },
    });
    fireEvent.change(screen.getByLabelText(/runs as 1/i), { target: { value: "root" } });
    fireEvent.change(screen.getByLabelText(/sudo command 2/i), {
      target: { value: "/usr/bin/pg_ctl reload" },
    });
    fireEvent.change(screen.getByLabelText(/runs as 2/i), { target: { value: "postgres" } });
    await settle();
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

  it("keşif", async () => {
    const run = {
      id: 7, source_id: "s1", trigger: "timer", actor: "system", started_at: T(11), finished_at: T(11),
      outcome: "ok", seen: 5, new_machines: 1, missing: 1, key_changed: 1, unreachable: 1,
    };
    const src = {
      id: "s1", name: "lab cluster", kind: "proxmox", url: "https://pve.example:8006", username: "postern@pve!d",
      secret_set: true, ca_pem: "", insecure: false, node: "", tag_key: "group", name_pattern: "web-*, db-*", port: 22,
      interval_seconds: 3600, enabled: true, created_by: "ops", created_at: T(10), updated_at: T(10), last_run: run, running: false,
    };
    const m = (ref: string, name: string, over: Record<string, unknown> = {}) => ({
      source_id: "s1", source: "lab cluster", ref, name, host: "10.0.0.5", tags: ["role_web", "env_prod"], running: true,
      group: "web", fingerprint: "SHA256:8eQzq1pRZo9hZ3ZC6uYb3f0mI2c9c7Ck4v3n2a1b0cd", ignored: false,
      first_seen: T(10), last_seen: T(11), ...over,
    });
    const discovery = {
      sources: [src, { ...src, id: "s2", name: "vcenter", kind: "vsphere", url: "https://vcenter.example", insecure: true, last_run: undefined, running: true, interval_seconds: 0 }],
      machines: [
        m("qemu/101", "web-01"), m("qemu/102", "db-01", { target: "db-01", group: "dba" }),
        m("lxc/200", "old-01", { missing_since: T(11) }),
        m("qemu/104", "bad-01", { fingerprint: undefined, problem: "no host key from 10.0.0.9:22 (dial tcp 10.0.0.9:22: i/o timeout)" }),
        m("qemu/105", "ign-01", { ignored: true }),
        m("qemu/106", "moved-01", { target: "moved-01", problem: "its host key SHA256:x differs from SHA256:y pinned on target moved-01; the target was left untouched" }),
        m("qemu/107", "off-01", { running: false }), m("qemu/108", "off-02", { running: false }),
      ],
      secrets_available: true, min_interval_seconds: 300,
    };
    mockAll({ ...base, discovery });
    await openSettings("Discovery");
    page("settings-discovery");
    fireEvent.click(screen.getByRole("checkbox", { name: /select web-01/i }));
    click(/register 1 selected/i);
    await settle();
    showDialog(/register 1 machine/i);
    page("settings-discovery-register");
    click(/^next$/i);
    await settle();
    fireEvent.change(screen.getByLabelText(/label key 1/i), { target: { value: "env" } });
    fireEvent.change(screen.getByLabelText(/label value 1/i), { target: { value: "prod" } });
    await settle();
    page("settings-discovery-labels");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, discovery });
    await openSettings("Discovery");
    click(/^add source$/i);
    await settle();
    showDialog(/add a discovery source/i);
    page("settings-discovery-source");
    cleanup();
    vi.restoreAllMocks();

    mockAll({ ...base, discovery: { sources: [], machines: [], secrets_available: false, min_interval_seconds: 300 } });
    await openSettings("Discovery");
    page("settings-discovery-empty");
  });

  /*
   * ⚠️ KURULMUŞ LDAP AYRI BİR SAYFA. Fikstür sırrı boş dizge verdiği
   * sürece ekran hep "kurulmamış" sayılıyordu ve operatörün günlük
   * gördüğü hâl hiç taranmıyordu. Burada grup süzgeci de geçerli: memberOf
   * kullanan bir kurulumda artakalan, %s taşımayan bir süzgeç kurulumu
   * bloke ediyor — o hâl de settings-ldap sayfasında duruyor.
   */
  it("kurulmuş LDAP", async () => {
    // Fixtures gevşek tipli (Record<..., unknown>); burada ne olduğunu
    // biliyoruz ve okuyucuya da söylüyoruz.
    const settings = (base.settings as Setting[]).map((s) =>
      s.key === "ldap.group_filter"
        ? { ...s, value: "(&(objectClass=group)(member=%s))" }
        : s,
    );
    mockAll({ ...base, settings });
    await openSettings("LDAP");
    page("settings-ldap-configured");
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
    for (const [name, label] of [["users", "Users"], ["targets", "Targets"], ["groups", "Groups"], ["mappings", "Mappings"]] as const) {
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

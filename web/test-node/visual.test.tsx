import { fireEvent, render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import SecurityKeys from "../src/SecurityKeys";
import ManageAccess from "../src/admin/ManageAccess";
import TemporaryAccess from "../src/admin/TemporaryAccess";
import { api, type Grant, type ManageCheck } from "../src/api";

/*
 * GÖRSEL KONTROL — birim testlerinin ölçmediği şey.
 *
 * ⚠️ NEDEN VAR: bu panelde üst üste kozmetik hata yapıldı ve hepsinin
 * ortak sebebi aynıydı — ekranı hiç görmeden yazmak. Birim testleri
 * yapıyı ölçüyor ("düğme var mı", "metin geçiyor mu") ve yerleşimi
 * ÖLÇMÜYOR: var olmayan bir CSS sınıfı, yanlış başlık seviyesi ya da
 * yan yana düşen bir etiket–düğme çifti testleri hiç bozmuyor.
 *
 * Bu dosya bileşenin ÜRETTİĞİ HTML'i alıp GERÇEK stil dosyasıyla
 * birleştiriyor ve diske yazıyor. Çıktı bir tarayıcıda açılıp
 * bakılabiliyor; yani "baktım" demek ölçülebilir bir adım oluyor.
 *
 * ⚠️ BU BİR TEST DEĞİL, BİR ARAÇ. Hiçbir şey iddia etmiyor —
 * yalnızca bakılabilir bir çıktı bırakıyor. Sınıfın var olup
 * olmadığını denetleyen kontrol ayrı (classnames.test.ts).
 */
describe("görsel kontrol çıktısı", () => {
  it("kartı gerçek stille birlikte diske yazıyor", async () => {
    vi.spyOn(api, "webauthnList").mockResolvedValue({
      credentials: [
        {
          id: "k1",
          name: "iş dizüstü",
          created_at: "2026-09-01T10:00:00Z",
          last_used_at: "2026-09-12T08:30:00Z",
        },
        { id: "k2", name: "yedek anahtar", created_at: "2026-09-05T10:00:00Z" },
      ],
      only: false,
    });
    (window as any).PublicKeyCredential = function () {};
    Object.defineProperty(navigator, "credentials", {
      configurable: true,
      value: { create: vi.fn(), get: vi.fn() },
    });

    const { container, findByText } = render(<SecurityKeys />);
    await findByText(/iş dizüstü/);

    const css = fs.readFileSync(path.resolve(process.cwd(), "src/styles.css"), "utf8");
    const out = path.resolve(process.cwd(), ".visual");
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(
      path.join(out, "security-keys.html"),
      `<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${css}</style>
<body class="app" style="padding:2rem;max-width:64rem">
${container.innerHTML}
</body>`,
    );

    expect(container.innerHTML).toContain("card-head");
  });
});

/*
 * Yönetim kartı dört hâliyle: kapalı, sonuçsuz, yönetilebilir ve
 * reddedilmiş. Reddedilmiş hâl uzun bir sunucu cümlesi ve ham hata
 * metni taşıyor — sarmayan bir kart tam orada taşar.
 */
describe("yönetim kartı görsel çıktısı", () => {
  const css = () => fs.readFileSync(path.resolve(process.cwd(), "src/styles.css"), "utf8");
  const base: ManageCheck = {
    target: "demo-a",
    stage: "done",
    manageable: true,
    ca_fingerprint: "SHA256:I3mJ5osOLjwSlMDq4UpW+nBcTtBCjux2CiFcN0Mudns",
    family: "alpine",
    missing: [],
    tools: {
      add_user: "/usr/sbin/useradd", add_group: "/usr/sbin/groupadd",
      mod_user: "/usr/sbin/usermod", del_user: "/usr/sbin/userdel",
      del_group: "/usr/sbin/groupdel", visudo: "/usr/sbin/visudo",
    },
    checked_at: "2026-09-13T10:41:00Z",
  };

  it("dört hâli yan yana diske yazıyor", async () => {
    const pieces: string[] = [];

    const off = render(<ManageAccess name="demo-a" enabled={false} />);
    pieces.push(off.container.innerHTML);
    off.unmount();

    const idle = render(<ManageAccess name="demo-a" enabled />);
    pieces.push(idle.container.innerHTML);
    idle.unmount();

    vi.spyOn(api, "checkManagement").mockResolvedValueOnce(base);
    const ok = render(<ManageAccess name="demo-a" enabled />);
    fireEvent.click(ok.getByRole("button"));
    await ok.findByText(/can manage this host/);
    pieces.push(ok.container.innerHTML);
    ok.unmount();

    vi.spyOn(api, "checkManagement").mockResolvedValueOnce({
      ...base,
      stage: "connect",
      manageable: false,
      family: undefined,
      tools: undefined,
      reason:
        "the target refused postern's management certificate. Either it does not trust this bastion's CA (compare the fingerprint below with the target's /etc/ssh/postern_ca.pub), or it has no management account — run the postern_target role with postern_manage_host: true",
      detail:
        "upstream.DialManagement: target demo-a: upstream: target refused our certificate: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain",
    });
    const bad = render(<ManageAccess name="demo-a" enabled />);
    fireEvent.click(bad.getByRole("button"));
    await bad.findByText(/refused postern/);
    pieces.push(bad.container.innerHTML);
    bad.unmount();

    const out = path.resolve(process.cwd(), ".visual");
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(
      path.join(out, "manage-access.html"),
      `<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${css()}</style>
<body class="app" style="padding:2rem;max-width:72rem;display:grid;gap:1.1rem">
${pieces
  .map(
    (p) =>
      `<div class="detail-grid"><div class="detail-main">${p}</div><div class="detail-side"></div></div>`,
  )
  .join("\n")}
</body>`,
    );

    expect(pieces).toHaveLength(4);
  });
});

/*
 * Geçici erişim kartı: form + dört durumlu liste + bir sonuç. Tablonun son
 * sütunu düğme; uzun bir "revocation failing" cümlesi kartı taşırmamalı.
 */
describe("geçici erişim kartı görsel çıktısı", () => {
  it("formu, listeyi ve sonucu diske yazıyor", async () => {
    const g = (over: Partial<Grant>): Grant => ({
      id: "g", username: "ayse", target: "demo-a", os_user: "ayse", groups: ["dba"],
      granted_by: "admin", granted_at: "2026-09-13T10:00:00Z", expires_at: "2026-09-13T18:00:00Z",
      applied_at: "2026-09-13T10:00:05Z", revoke_attempts: 0, ...over,
    });
    vi.spyOn(api, "users").mockResolvedValue([
      { name: "ayse", os_user: "ayse", admin: false, roles: [], keys: 1 } as never,
      { name: "veli", os_user: "veli", admin: true, roles: [], keys: 0 } as never,
    ]);
    vi.spyOn(api, "allGrants").mockResolvedValue({
      now: "2026-09-13T12:00:00Z",
      grants: [
        g({ id: "1" }),
        g({ id: "2", username: "veli", os_user: "veli", groups: [], expires_at: "2026-09-13T11:00:00Z" }),
        g({ id: "3", applied_at: undefined, apply_report: "1 applied, 1 failed, 2 not attempted" }),
        g({
          id: "4", expires_at: "2026-09-12T18:00:00Z", revoke_attempts: 4,
          revoke_error: "could not connect: upstream.DialManagement: target demo-a: upstream: target unreachable: dial tcp 10.0.0.9:22: connect: no route to host",
        }),
        g({ id: "5", revoked_at: "2026-09-13T11:30:00Z", revoke_report: "5 applied" }),
      ],
    });
    vi.spyOn(api, "revokeGrant").mockResolvedValue({
      grant: g({ id: "1", revoked_at: "2026-09-13T12:01:00Z" }),
      summary: "5 applied; left behind: /srv/build/ayse/out.log",
      steps: [
        { kind: "sudo.remove", command: "sudo -n rm -f /etc/sudoers.d/postern-user-ayse", why: "take the sudo rule away before anything else", outcome: "done" },
        { kind: "user.kill", command: "sudo -n pkill -KILL -u ayse || true", why: "kill what the account is still running", outcome: "done" },
        { kind: "user.delete", command: "sudo -n /usr/sbin/userdel -r ayse", why: "delete the temporary account and its home", outcome: "done" },
      ],
      sessions_closed: 1,
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);

    const { container, findByText, findAllByText, getAllByRole } = render(<TemporaryAccess />);
    await findAllByText("veli");
    fireEvent.click(getAllByRole("button", { name: /revoke ayse's temporary access/i })[0]);
    await findByText(/left behind/);

    const out = path.resolve(process.cwd(), ".visual");
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(
      path.join(out, "temporary-access.html"),
      `<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${fs.readFileSync(path.resolve(process.cwd(), "src/styles.css"), "utf8")}</style>
<body class="app" style="padding:2rem;max-width:72rem">
<div class="detail-grid"><div class="detail-main">${container.innerHTML}</div><div class="detail-side"></div></div>
</body>`,
    );
    expect(container.innerHTML).toContain("Temporary access");
  });
});

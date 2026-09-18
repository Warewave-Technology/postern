import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import Discovery, { labelsOf, machineState } from "./Discovery";
import {
  api,
  type DiscoveredMachine,
  type DiscoveryOverview,
  type DiscoverySource,
} from "../api";

const source = (over: Partial<DiscoverySource> = {}): DiscoverySource => ({
  id: "s1",
  name: "lab",
  kind: "proxmox",
  url: "https://pve.example:8006",
  username: "postern@pve!d",
  secret_set: true,
  ca_pem: "",
  insecure: false,
  node: "",
  tag_key: "group",
  name_pattern: "",
  port: 22,
  interval_seconds: 3600,
  enabled: true,
  created_by: "ops",
  created_at: "2026-09-13T10:00:00Z",
  updated_at: "2026-09-13T10:00:00Z",
  last_run: {
    id: 7,
    source_id: "s1",
    trigger: "timer",
    actor: "system",
    started_at: "2026-09-13T11:00:00Z",
    finished_at: "2026-09-13T11:00:09Z",
    outcome: "ok",
    seen: 5,
    new_machines: 1,
    missing: 1,
    key_changed: 0,
    unreachable: 1,
  },
  running: false,
  ...over,
});

const machine = (over: Partial<DiscoveredMachine> = {}): DiscoveredMachine => ({
  source_id: "s1",
  source: "lab",
  ref: "qemu/101",
  name: "web-01",
  host: "10.0.0.5",
  tags: ["role_web", "env_prod"],
  running: true,
  group: "web",
  fingerprint: "SHA256:abc",
  ignored: false,
  first_seen: "2026-09-13T10:00:00Z",
  last_seen: "2026-09-13T11:00:00Z",
  ...over,
});

const overview: DiscoveryOverview = {
  sources: [source()],
  machines: [
    machine(),
    machine({ ref: "qemu/102", name: "db-01", target: "db-01" }),
    machine({
      ref: "qemu/103",
      name: "old-01",
      missing_since: "2026-09-13T11:00:00Z",
    }),
    machine({
      ref: "qemu/104",
      name: "bad-01",
      fingerprint: undefined,
      problem: "no host key from 10.0.0.9:22 (timeout)",
    }),
    machine({ ref: "qemu/105", name: "ign-01", ignored: true }),
    machine({
      ref: "qemu/106",
      name: "moved-01",
      target: "moved-01",
      problem:
        "its host key SHA256:x differs from SHA256:y pinned on target moved-01; the target was left untouched",
    }),
  ],
  secrets_available: true,
  min_interval_seconds: 300,
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, "groups").mockResolvedValue([
    { name: "ops", targets: [], paths: [] } as never,
  ]);
});

it("durumu satırdan türetiyor: yalnızca yeni ve anahtarlı makine kaydedilebilir", () => {
  expect(machineState(machine()).text).toBe("new");
  expect(machineState(machine()).registrable).toBe(true);
  expect(machineState(machine({ target: "web-01" })).text).toBe("registered");
  expect(
    machineState(machine({ target: "web-01", problem: "differs" })).text,
  ).toBe("key changed");
  expect(machineState(machine({ missing_since: "x" })).text).toBe("missing");
  expect(
    machineState(machine({ ignored: true, missing_since: "x" })).text,
  ).toBe("ignored");
  expect(machineState(machine({ fingerprint: undefined })).text).toBe(
    "blocked",
  );
  expect(machineState(machine({ problem: "bad name" })).registrable).toBe(
    false,
  );
  expect(
    labelsOf([
      { key: "env", value: "prod" },
      { key: " team ", value: " platform " },
      { key: "", value: "" },
    ]).labels,
  ).toEqual({ env: "prod", team: "platform" });
  // ⚠️ SUNUCUNUN KURALIYLA AYNI: panelde daha gevşek bir kural, yazdırıp
  // sonra reddedilen bir etiket demek.
  expect(labelsOf([{ key: "", value: "prod" }]).error).toMatch(/has no key/);
  expect(labelsOf([{ key: "env prod", value: "x" }]).error).toMatch(
    /not allowed/,
  );
  expect(
    labelsOf([
      { key: "env", value: "a" },
      { key: "env", value: "b" },
    ]).error,
  ).toMatch(/written twice/);
});

/*
 * ⚠️ VARSAYILAN LİSTE YALNIZCA KARAR BEKLEYENLER. Altı durum birden tek
 * tabloda duruyordu; kaydedilmiş olanlar zaten Targets'ta, yok sayılmış,
 * kayıp ve engelli olanların ise bu ekranda yapılacak bir işi yok.
 * Yirmi dört makinelik bir kümede yirmi ikisi onlardı ve aranan iki
 * satır aralarında kayboluyordu (kullanıcı ekrana bakıp söyledi).
 */
it("varsayılanda yalnızca karar bekleyen makineleri listeliyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  render(<Discovery />);

  expect(await screen.findByText("web-01")).toBeTruthy();
  expect(screen.getByText("moved-01")).toBeTruthy();
  expect(screen.getByText("key changed").className).toContain("badge-danger");
  expect(screen.getByText(/differs from SHA256:y/)).toBeTruthy();

  for (const hiddenName of ["db-01", "old-01", "bad-01", "ign-01"]) {
    expect(screen.queryByText(hiddenName)).toBeNull();
  }
  // Seçim yokken kayıt düğmesi kapalı.
  expect(
    (
      screen.getByRole("button", {
        name: /register selected/i,
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
});

/*
 * ⚠️ GİZLEMEK, ANLAMINI DA GİZLEMEK OLMAMALI. "ignored" ile "blocked"ın
 * ne demek olduğunu kimse bilmiyordu (kullanıcı söyledi) — ve "blocked"
 * için akla gelen ilk anlam "postern bunu engelledi", oysa engelleyen
 * makinenin kendisi. Her durum, açıklamasıyla birlikte duruyor.
 */
it("gizlenen durumlar ne demek olduğuyla birlikte açılıyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  render(<Discovery />);
  await screen.findByText("web-01");

  // Açılır başlık: gömülü bir bağlantı değil, gerçekten açılan bir şey.
  const summary = screen.getByText(/4 machines not listed/i);
  expect(summary.tagName.toLowerCase()).toBe("summary");

  expect(
    screen.getByText(/never offered for registration again/i),
  ).toBeTruthy();
  // "blocked" makinenin durumu, postern'in kararı DEĞİL.
  expect(
    screen.getByText(
      /this is the machine's state, not a decision postern made/i,
    ),
  ).toBeTruthy();
  expect(screen.getByText(/they are on the Targets screen/i)).toBeTruthy();

  fireEvent.click(screen.getByRole("checkbox", { name: /ignored/i }));
  expect(await screen.findByText("ign-01")).toBeTruthy();
  // Yalnızca açılan durum geliyor; kalanlar hâlâ dışarıda.
  expect(screen.queryByText("bad-01")).toBeNull();
});

/*
 * ⚠️ SİHİRBAZ ÜÇ ADIM ve son adım parmak izini gösteriyor; istek yalnızca
 * son düğmede gidiyor ve seçilenlerden yalnızca KAYDEDİLEBİLİR olanları
 * taşıyor — kayıtlı ya da kayıp makine seçilse de gitmiyor.
 */
it("seçili yeni makineleri roller ve etiketlerle kaydediyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  const register = vi.spyOn(api, "registerDiscovered").mockResolvedValue({
    results: [
      {
        source_id: "s1",
        ref: "qemu/101",
        name: "web-01",
        target: "web-01",
        groups: ["web"],
        created_roles: ["web"],
      },
    ],
  });
  render(<Discovery />);
  await screen.findByText("web-01");

  fireEvent.click(screen.getByRole("checkbox", { name: /select web-01/i }));
  fireEvent.click(screen.getByRole("checkbox", { name: /select moved-01/i }));
  expect(
    screen.getByText(/1 of the selected cannot be registered/),
  ).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /register 1 selected/i }));

  expect(await screen.findByText(/step 1 of 3/i)).toBeTruthy();
  expect(screen.getByText(/web would be created/)).toBeTruthy();
  expect(register).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: /^next$/i }));
  expect(await screen.findByText(/step 2 of 3/i)).toBeTruthy();
  /*
   * ⚠️ ETİKET ARTIK TABLO: anahtar ve değer ayrı alanlar. Serbest metinde
   * eşittiri unutan satır sessizce düşüyordu ve yer tutucu yazılmış
   * sanılıyordu (kullanıcı söyledi).
   */
  await userEvent.type(screen.getByLabelText(/label key 1/i), "env");
  await userEvent.type(screen.getByLabelText(/label value 1/i), "prod");
  // Dolan satır yenisini açıyor: "ekle" düğmesi unutulacak bir adım olurdu.
  expect(screen.getByLabelText(/label key 2/i)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /^next$/i }));
  expect(await screen.findByText(/step 3 of 3/i)).toBeTruthy();
  expect(screen.getAllByText("SHA256:abc").length).toBeGreaterThan(0);
  expect(screen.getByText(/pinned as shown/)).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: /register 1 machine/i }));
  await waitFor(() =>
    expect(register).toHaveBeenCalledWith({
      machines: [{ source_id: "s1", ref: "qemu/101" }],
      groups: [],
      tag_roles: true,
      labels: { env: "prod" },
    }),
  );
  expect(await screen.findByText(/registered as/)).toBeTruthy();
  expect(screen.getByText(/created web/)).toBeTruthy();
});

it("seçilenleri yok sayıyor ve yok saymayı kaldırıyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  const ignore = vi
    .spyOn(api, "ignoreDiscovered")
    .mockResolvedValue({ changed: 1 });
  render(<Discovery />);
  await screen.findByText("web-01");

  // Engelli ve yok sayılmış makineler varsayılanda listede değil: yok
  // sayma kararı da onları görerek veriliyor.
  fireEvent.click(screen.getByRole("checkbox", { name: /blocked/i }));
  fireEvent.click(screen.getByRole("checkbox", { name: /ignored/i }));

  fireEvent.click(
    await screen.findByRole("checkbox", { name: /select bad-01/i }),
  );
  fireEvent.click(screen.getByRole("button", { name: /ignore selected/i }));
  await waitFor(() =>
    expect(ignore).toHaveBeenCalledWith(
      [{ source_id: "s1", ref: "qemu/104" }],
      true,
    ),
  );

  fireEvent.click(screen.getByRole("checkbox", { name: /select ign-01/i }));
  fireEvent.click(screen.getByRole("button", { name: /stop ignoring/i }));
  await waitFor(() =>
    expect(ignore).toHaveBeenCalledWith(
      [{ source_id: "s1", ref: "qemu/105" }],
      false,
    ),
  );
});

/*
 * ⚠️ ETİKETİN SÖYLEDİĞİ ROL SEÇİLİ GELİYOR ve özet onu İKİ KEZ yazmıyor.
 * Platformda "role_web" yazan bir makineyi kaydederken aynı rolü elle
 * seçtirmek, verilmiş bir bilgiyi ikinci kez sormaktı; seçilen rol ile
 * etiketin rolü aynı olunca da özet "web, web" diyordu.
 */
it("etiket rolünü seçili getiriyor ve özette tekrar etmiyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  vi.spyOn(api, "groups").mockResolvedValue([
    { name: "web", targets: [] },
    { name: "dba", targets: [] },
  ]);
  render(<Discovery />);
  await screen.findByText("web-01");

  fireEvent.click(screen.getByRole("checkbox", { name: /select web-01/i }));
  fireEvent.click(screen.getByRole("button", { name: /register 1 selected/i }));

  // 1. adım: rol kutusunda etiketin rolü çip olarak duruyor.
  expect(
    await screen.findByRole("button", { name: "remove web" }),
  ).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: /^next$/i }));
  await userEvent.type(await screen.findByLabelText(/label key 1/i), "env");
  await userEvent.type(screen.getByLabelText(/label value 1/i), "prod");
  expect(screen.getByText(/1 label will be attached/i)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /^next$/i }));

  // Arka plandaki liste de aynı adı taşıyor; özet tablosunun satırını
  // modal içinden al.
  const dialog = await screen.findByRole("dialog");
  const row = Array.from(dialog.querySelectorAll("tbody tr")).find((r) =>
    r.textContent?.includes("web-01"),
  )! as HTMLTableRowElement;
  expect(row.cells[4].textContent).toBe("web");
  // Makinenin platform etiketleri de özette.
  expect(row.cells[2].textContent).toContain("role_web");
  expect(screen.getByText(/labels attached to each machine/i)).toBeTruthy();
});

/*
 * ⚠️ SATIR DOLDUKÇA YENİSİ AÇILIYOR VE SİLİNEBİLİYOR. "Ekle" düğmeli bir
 * tabloda son satırı yazıp eklemeye basmamak, etiketi yazdığını sanarak
 * ilerlemek demek — serbest metin kutusunda yaşanan yanılgının aynısı.
 */
it("etiket tablosu doldukça büyüyor ve bozuk anahtarı ilerletmiyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  const register = vi
    .spyOn(api, "registerDiscovered")
    .mockResolvedValue({ results: [] });
  render(<Discovery />);
  await screen.findByText("web-01");

  fireEvent.click(screen.getByRole("checkbox", { name: /select web-01/i }));
  fireEvent.click(screen.getByRole("button", { name: /register 1 selected/i }));
  fireEvent.click(await screen.findByRole("button", { name: /^next$/i }));

  await userEvent.type(await screen.findByLabelText(/label key 1/i), "env");
  await userEvent.type(screen.getByLabelText(/label value 1/i), "prod");
  await userEvent.type(screen.getByLabelText(/label key 2/i), "team");
  await userEvent.type(screen.getByLabelText(/label value 2/i), "platform");
  expect(screen.getByLabelText(/label key 3/i)).toBeTruthy();
  expect(screen.getByText(/2 labels will be attached/i)).toBeTruthy();

  // Bozuk anahtar: sebebiyle söyleniyor ve ileri gidilmiyor.
  await userEvent.type(screen.getByLabelText(/label key 3/i), "env prod");
  expect(screen.getByText(/not allowed/i)).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: /^next$/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);

  fireEvent.click(screen.getByRole("button", { name: /remove label row 3/i }));
  fireEvent.click(screen.getByRole("button", { name: /^next$/i }));
  fireEvent.click(
    await screen.findByRole("button", { name: /register 1 machine/i }),
  );

  await waitFor(() =>
    expect(register).toHaveBeenCalledWith(
      expect.objectContaining({ labels: { env: "prod", team: "platform" } }),
    ),
  );
});

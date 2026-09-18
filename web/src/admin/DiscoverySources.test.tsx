import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import DiscoverySources from "./DiscoverySources";
import { api, type DiscoveryOverview, type DiscoverySource } from "../api";

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

const overview: DiscoveryOverview = {
  sources: [source()],
  machines: [],
  secrets_available: true,
  min_interval_seconds: 300,
};

beforeEach(() => {
  vi.restoreAllMocks();
});

/*
 * ⚠️ KAYNAKLAR KENDİ EKRANINDA. Makinelerle aynı sayfada alt alta iki
 * tablo olarak duruyorlardı ve hangisinin ne olduğu karışıyordu
 * (kullanıcı söyledi) — ki bu ekrandaki eylemlerden biri bir kaynağı,
 * bulduğu bütün makinelerle birlikte siliyor.
 */
it("kaynakları son koşularıyla listeliyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  render(<DiscoverySources />);

  await screen.findByText("Every hour");
  expect(screen.getByText("lab")).toBeTruthy();
  expect(
    screen.getByText(/5 seen, 1 new, 1 missing, 0 key changed, 1 unreachable/),
  ).toBeTruthy();
  expect(screen.getByRole("button", { name: /run lab now/i })).toBeTruthy();
});

/*
 * ⚠️ KAYNAĞI SİLMEK, BULDUĞU LİSTEYİ DE SİLİYOR ve onay cümlesi bunu
 * söylemek zorunda. Kaydedilmiş hedefler kalıyor — ikisi ayrı şeyler ve
 * cümle ikisini de söylemezse yönetici en kötüsünü varsayar.
 */
it("kaynağı silme onayı neyin gittiğini söylüyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  render(<DiscoverySources />);

  const remove = await screen.findByRole("button", { name: /remove lab/i });
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  fireEvent.click(remove);
  expect(confirm.mock.calls[0][0]).toMatch(
    /list of discovered machines goes with it/i,
  );
  expect(confirm.mock.calls[0][0]).toMatch(/already registered stay/i);
});

it("kaynak formu sırrı yalnızca yazıldığında gönderiyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue(overview);
  const create = vi
    .spyOn(api, "createDiscoverySource")
    .mockResolvedValue({ id: "s2" });
  const update = vi
    .spyOn(api, "updateDiscoverySource")
    .mockResolvedValue({ ok: true });
  const test = vi
    .spyOn(api, "testDiscoverySource")
    .mockResolvedValueOnce({
      machines: 3,
      running: 2,
      with_address: 1,
      matching: 3,
      tagged: 2,
      groups: ["ops", "dba"],
      tags: ["role_ops"],
      took_ms: 40,
    })
    .mockResolvedValueOnce({
      machines: 3,
      running: 2,
      with_address: 1,
      matching: 3,
      tagged: 0,
      groups: [],
      tags: ["rol_ops", "env_prod"],
      took_ms: 40,
    });
  render(<DiscoverySources />);
  await screen.findByText("Every hour");

  fireEvent.click(screen.getByRole("button", { name: /^add source$/i }));
  await userEvent.type(screen.getByLabelText(/^name$/i), "prod cluster");
  await userEvent.type(
    screen.getByLabelText(/^address$/i),
    "https://pve.prod:8006",
  );
  await userEvent.type(
    screen.getByLabelText(/api token id/i),
    "postern@pve!prod",
  );
  await userEvent.type(screen.getByLabelText(/api token secret/i), "gizli");

  // Test kaydetmeden bağlanıyor: sayımlar ve roller; anahtar tutmayınca sarı ve görülen etiketler.
  fireEvent.click(screen.getByRole("button", { name: /test connection/i }));
  await waitFor(() => expect(test).toHaveBeenCalledTimes(1));
  expect(test.mock.calls[0][0]).toMatchObject({
    url: "https://pve.prod:8006",
    secret: "gizli",
    id: undefined,
  });
  const first = await screen.findByText(/reached proxmox/i);
  expect(first.textContent).toMatch(
    /3 machine\(s\), 2 running, 1 with an address\. 2 carry a "group" tag \(groups: ops, dba\)/,
  );
  expect(first.className).toContain("msg-ok");
  expect(create).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: /test connection/i }));
  await waitFor(() =>
    expect(screen.getByText(/reached proxmox/i).className).toContain(
      "msg-warn",
    ),
  );
  expect(screen.getByText(/reached proxmox/i).textContent).toMatch(
    /tags actually seen were rol_ops, env_prod/,
  );

  fireEvent.click(screen.getByRole("button", { name: /save source/i }));
  await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
  expect(create.mock.calls[0][0]).toMatchObject({
    name: "prod cluster",
    kind: "proxmox",
    url: "https://pve.prod:8006",
    username: "postern@pve!prod",
    secret: "gizli",
    tag_key: "group",
    port: 22,
    interval_seconds: 3600,
    enabled: true,
    insecure: false,
  });

  fireEvent.click(screen.getByRole("button", { name: /edit lab/i }));
  const kind = (await screen.findByLabelText(/^kind$/i)) as HTMLSelectElement;
  expect(kind.disabled).toBe(true);
  expect(
    (screen.getByLabelText(/api token secret/i) as HTMLInputElement)
      .placeholder,
  ).toMatch(/unchanged/);
  // Düzenlemede test kayıtlı sırla: id gidiyor, sır boş.
  test.mockResolvedValueOnce({
    machines: 1,
    running: 1,
    with_address: 1,
    matching: 1,
    tagged: 1,
    groups: ["web"],
    tags: ["role_web"],
    took_ms: 5,
  });
  fireEvent.click(screen.getByRole("button", { name: /test connection/i }));
  await waitFor(() => expect(test).toHaveBeenCalledTimes(3));
  expect(test.mock.calls[2][0]).toMatchObject({ id: "s1", secret: "" });

  fireEvent.click(screen.getByRole("button", { name: /save changes/i }));
  await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
  expect(update.mock.calls[0][0]).toBe("s1");
  expect(update.mock.calls[0][1]).toMatchObject({ secret: "", name: "lab" });
});

it("mühür anahtarı yokken kaynak eklenemiyor ve sebebi yazıyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue({
    ...overview,
    sources: [],
    machines: [],
    secrets_available: false,
  });
  render(<DiscoverySources />);
  expect(await screen.findByText(/no secret key/)).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: /^add source$/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
});

it("mühür anahtarı yokken kaynak eklenemiyor ve sebebi yazıyor", async () => {
  vi.spyOn(api, "discovery").mockResolvedValue({
    ...overview,
    sources: [],
    secrets_available: false,
  });
  render(<DiscoverySources />);
  expect(await screen.findByText(/no secret key/)).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: /^add source$/i }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
});

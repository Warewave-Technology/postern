import { describe, it, expect } from "vitest";
import {
  joinPath,
  parentPath,
  crumbs,
  sortEntries,
  formatSize,
  formatMode,
  formatTime,
} from "./files";
import type { Entry } from "./sftp";

const entry = (name: string, isDir = false): Entry => ({
  name,
  longname: "",
  size: 0,
  mode: 0,
  mtime: 0,
  isDir,
  isLink: false,
});

describe("yol", () => {
  it("kökte çift eğik çizgi üretmiyor", () => {
    expect(joinPath("/", "etc")).toBe("/etc");
    expect(joinPath("/var", "log")).toBe("/var/log");
  });

  it("üst dizin kökte durur", () => {
    expect(parentPath("/var/log")).toBe("/var");
    expect(parentPath("/var")).toBe("/");
    expect(parentPath("/")).toBe("/");
    expect(parentPath("")).toBe("/");
  });

  it("sondaki eğik çizgi üst dizini kaydırmıyor", () => {
    // ⚠️ Aksi hâlde "/var/log/" için üst dizin "/var/log" çıkardı ve
    // yukarı düğmesi kullanıcıyı aynı yerde bırakırdı.
    expect(parentPath("/var/log/")).toBe("/var");
  });

  it("kırıntılar her adıma MUTLAK yol taşıyor", () => {
    expect(crumbs("/var/log")).toEqual([
      { label: "/", path: "/" },
      { label: "var", path: "/var" },
      { label: "log", path: "/var/log" },
    ]);
  });
});

describe("sıralama", () => {
  it("dizinler önce, sonra ad", () => {
    const list = [entry("zeta"), entry("beta", true), entry("alpha")];
    expect(sortEntries(list).map((e) => e.name)).toEqual([
      "beta",
      "alpha",
      "zeta",
    ]);
  });

  it("gelen diziyi DEĞİŞTİRMİYOR", () => {
    const list = [entry("b"), entry("a")];
    sortEntries(list);
    expect(list.map((e) => e.name)).toEqual(["b", "a"]);
  });
});

describe("biçimleme", () => {
  it("boyut 1024'lük basamakta", () => {
    expect(formatSize(512)).toBe("512 B");
    expect(formatSize(1024)).toBe("1.0 KiB");
    expect(formatSize(1536)).toBe("1.5 KiB");
    expect(formatSize(20 * 1024)).toBe("20 KiB");
    expect(formatSize(5 * 1024 * 1024 * 1024)).toBe("5.0 GiB");
  });

  it("kip ls -l biçiminde", () => {
    expect(formatMode(0o100644)).toBe("-rw-r--r--");
    expect(formatMode(0o040755)).toBe("drwxr-xr-x");
    expect(formatMode(0o120777)).toBe("lrwxrwxrwx");
  });

  it("bilinmeyen dosya tipi soru işareti", () => {
    expect(formatMode(0)[0]).toBe("?");
  });

  it("zaman yoksa 1970 yazmıyor", () => {
    expect(formatTime(0)).toBe("—");
    expect(formatTime(1757066400)).not.toBe("—");
  });
});

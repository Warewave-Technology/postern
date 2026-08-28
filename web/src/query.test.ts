import { describe, expect, it } from "vitest";
import { Fields, matches, parse, describe as explain } from "./query";

const web: Fields = {
  name: "web-server-01",
  labels: { env: "prod", team: "platform" },
  extra: { version: "SSH-2.0-OpenSSH_9.6p1 Debian-3" },
};
const db: Fields = {
  name: "db-01",
  labels: { env: "prod", team: "data" },
  extra: { version: "SSH-2.0-OpenSSH_8.4p1" },
};
const stage: Fields = {
  name: "web-stage",
  labels: { env: "staging" },
  extra: {},
};

const hit = (q: string, f: Fields) => matches(parse(q), f);

describe("sorgu dili", () => {
  it("bos sorgu her seyi eslestirir", () => {
    expect(hit("", web)).toBe(true);
    expect(hit("   ", web)).toBe(true);
  });

  it("alansiz terim her yerde arar", () => {
    expect(hit("platform", web)).toBe(true);
    expect(hit("platform", db)).toBe(false);
    // Etiketin anahtarı da aranabilir olmalı: "env" yazan biri etiketi
    // olanları görmek istiyor.
    expect(hit("env", stage)).toBe(true);
  });

  it("alan adiyla arar", () => {
    expect(hit("name: web", web)).toBe(true);
    expect(hit("name: web", db)).toBe(false);
    expect(hit("env: prod", db)).toBe(true);
    expect(hit("env: prod", stage)).toBe(false);
  });

  // Kullanıcı iki nokta etrafına boşluk koyuyor; bunu sözdizimi hatası
  // saymak dili kullanılmaz yapardı.
  it("iki nokta etrafindaki bosluklari yutar", () => {
    for (const q of ["env:prod", "env: prod", "env :prod", "env : prod"]) {
      expect(hit(q, db)).toBe(true);
    }
  });

  it("bosluk VE demek, and yazmak serbest", () => {
    expect(hit("name: web env: prod", web)).toBe(true);
    expect(hit("name: web and env: prod", web)).toBe(true);
    expect(hit("name: web and env: prod", stage)).toBe(false);
  });

  it("or ile obekler ayrilir", () => {
    expect(hit("env: prod or env: staging", stage)).toBe(true);
    expect(hit("env: prod or env: staging", web)).toBe(true);
    expect(hit("team: data or team: platform", stage)).toBe(false);
  });

  // ⚠️ and, or'dan SIKI bağlar: "a and b or c" = "(a ve b) veya c".
  // Ters olsaydı "name: web and env: prod or env: staging" sorgusu
  // staging'deki HER hedefi getirirdi — kullanıcının kastettiği bu değil.
  it("and or'dan siki baglar", () => {
    const q = "name: web and env: prod or env: staging";
    expect(hit(q, web)).toBe(true); // (web ve prod)
    expect(hit(q, stage)).toBe(true); // (staging)
    expect(hit(q, db)).toBe(false); // ne (web ve prod) ne staging
  });

  it("eksi ile olumsuzlanir", () => {
    expect(hit("-env: prod", stage)).toBe(true);
    expect(hit("-env: prod", db)).toBe(false);
    expect(hit("name: web -env: prod", stage)).toBe(true);
  });

  // Değersiz alan = etiketin VARLIĞI. Yarım yazılmış bir sorgunun
  // ("env:" henüz değeri gelmemiş) listeyi boşaltmaması da bundan.
  it("degersiz alan etiketin varligini sorar", () => {
    expect(hit("team:", web)).toBe(true);
    expect(hit("team:", stage)).toBe(false);
  });

  it("bilinmeyen alan etiket olarak denenir, yoksa eslesmez", () => {
    expect(hit("yokboyle: bir", web)).toBe(false);
  });

  it("ek alanlar aranabilir", () => {
    expect(hit("version: OpenSSH_9", web)).toBe(true);
    expect(hit("version: OpenSSH_9", db)).toBe(false);
  });

  it("buyuk kucuk harf ayirmaz", () => {
    expect(hit("ENV: PROD", db)).toBe(true);
    expect(hit("NAME: WEB", web)).toBe(true);
    expect(hit("env: prod OR env: staging", stage)).toBe(true);
  });

  // Yazarken her tuşta çalışıyor: yarım sorgu patlamamalı ve listeyi
  // sessizce boşaltmamalı.
  it("yarim sorgular patlamaz", () => {
    for (const q of ["name:", "-", "and", "or", "zzz or", "or zzz", ":"]) {
      expect(() => parse(q)).not.toThrow();
    }
    // Sondaki "or" boş bir öbek üretmemeli: üretseydi sorgu HER satırla
    // eşleşir ve yazmaya devam eden kullanıcı listenin bir anda
    // dolduğunu görürdü.
    expect(hit("zzz or", web)).toBe(false);
    expect(hit("and", web)).toBe(true); // yalnız "and" = boş sorgu
  });
});

describe("describe", () => {
  it("sorguyu insan diline cevirir", () => {
    expect(explain(parse("name: web and env: prod"))).toBe(
      "name contains “web” and env contains “prod”",
    );
    expect(explain(parse("env: prod or env: stage"))).toContain("— or —");
    expect(explain(parse("-env: prod"))).toBe("not env contains “prod”");
    expect(explain(parse("team:"))).toBe("has a team label");
    expect(explain(parse(""))).toBe("");
  });
});

import { describe, expect, it } from "vitest";
import { FX, Halted, SFTPError, newStop, type Entry } from "./sftp";
import {
  maxNoted,
  maxPathBytes,
  maxTreeDepth,
  maxTreeEntries,
  noteName,
  skipNote,
  walkTree,
  type Lister,
} from "./tree";

const DIR = 0o040755;
const FILE = 0o100644;
const LINK = 0o120777;
const FIFO = 0o010644;
const SOCK = 0o140755;

function ent(name: string, mode: number, size = 0): Entry {
  return {
    name,
    longname: "",
    size,
    mode,
    mtime: 0,
    isDir: (mode & 0o170000) === 0o040000,
    isLink: (mode & 0o170000) === 0o120000,
  };
}

/** lister, sahte bir hedef ağacı — ve HANGİ dizinlerin açıldığını sayar. */
function lister(tree: Record<string, Entry[]>): Lister & { opened: string[] } {
  const opened: string[] = [];

  return {
    opened,
    async readdir(p: string) {
      opened.push(p);
      const l = tree[p];
      if (!l) throw new SFTPError(FX.PERMISSION_DENIED, "postern: not allowed");

      return l;
    },
  };
}

const explain = (e: unknown) => (e instanceof Error ? e.message : String(e));

describe("ağaç gezintisi", () => {
  /*
   * ⚠️ BU DOSYADAKİ EN ÖNEMLİ İDDİA VE ÖZYİNELİ GEZİNMEDE YAZILAN İLK
   * HATA. Gerçek bir sftp-server READDIR sonucunda "." ve ".." GÖNDERİYOR
   * (OpenSSH gönderiyor). İçlerine inen bir gezgin ağacın dışına çıkıp
   * SONSUZA KADAR döner — ve dönerken dizin başına bir defter satırı
   * yazıp oturumun kaydını da şişirir.
   *
   * Ölçülen şey listede olmamaları değil, HİÇ AÇILMAMALARI.
   */
  it('"." ve ".." hiç açılmıyor', async () => {
    const t = lister({
      "/is": [ent(".", DIR), ent("..", DIR), ent("x.txt", FILE, 3)],
    });

    const tree = await walkTree(t, "/is", explain);

    expect(tree.files.map((f) => f.rel)).toEqual(["is/x.txt"]);
    expect(t.opened).toEqual(["/is"]);
  });

  /*
   * ⚠️ BAĞ İZLENMİYOR — üç şeyi birden kapatıyor: döngü, seçilen ağacın
   * dışına çıkmak, ve aynı dosyayı defalarca indirmek. Atlandığı
   * SÖYLENİYOR: sessizce eksik bir arşiv, reddedilen bir indirmeden kötü.
   */
  it("bağ izlenmiyor, atlandığı yazılıyor", async () => {
    const t = lister({
      "/is": [ent("guncel", LINK), ent("veri.txt", FILE, 5)],
      // Bağın işaret ettiği yer OKUNABİLİR olsa bile açılmamalı.
      "/is/guncel": [ent("gizli.txt", FILE, 9)],
    });

    const tree = await walkTree(t, "/is", explain);

    expect(t.opened).toEqual(["/is"]);
    expect(tree.files.map((f) => f.rel)).toEqual(["is/veri.txt"]);
    expect(tree.skipped).toEqual([
      {
        path: "/is/guncel",
        why: "symbolic link — postern does not follow links when it fetches a folder",
      },
    ]);
  });

  /*
   * ⚠️ FIFO OKUMAK SONSUZA KADAR BLOKLUYOR. Kuyruk sıralı, yani tek bir
   * adlandırılmış boru bütün indirmeyi asılı bırakır ve kullanıcı neyi
   * beklediğini göremez. Aygıt dosyaları da (/dev/zero) sonu gelmeyen
   * bir akış.
   */
  it("düzenli olmayan dosyalar atlanıyor", async () => {
    const t = lister({
      "/is": [ent("boru", FIFO), ent("soket", SOCK), ent("a.txt", FILE, 1)],
    });

    const tree = await walkTree(t, "/is", explain);

    expect(tree.files.map((f) => f.rel)).toEqual(["is/a.txt"]);
    expect(tree.skipped.map((s) => s.path)).toEqual(["/is/boru", "/is/soket"]);
    expect(tree.skipped[0].why).toBe("not a regular file");
  });

  /*
   * ⚠️ BU DOSYADAKİ EN CİDDİ GÜVENLİK İDDİASI VE İLK HÂLİ TERSİYDİ.
   *
   * İlk yazdığımda kipi sıfır olan girdi DÜZENLİ DOSYA sayılıyordu,
   * "hedef tip göndermemiş olabilir" gerekçesiyle. Ama tip bilgisini
   * göndermeyi HEDEF seçiyor: ATTRS'ın izin bayrağını (0x04) kapatan
   * bir sunucu, bir sembolik bağı isDir=false, isLink=false olarak
   * gönderiyor — ve "bağları izlemiyoruz" kuralı, onu delmek isteyenin
   * elinde TEK BİR BİT ile düşüyordu. Sonuç: /etc/shadow'a işaret eden
   * bir bağ, izin verilen bir yolun altında arşive giriyor, denetim
   * satırı da tertemiz görünüyor.
   *
   * Panelde tek bir dosyaya tıklamak kullanıcının kendi kararı; burada
   * dosyalar TEK TEK SEÇİLMİYOR, o yüzden ölçü sıkı olmak zorunda.
   */
  it("kipi bilinmeyen girdi indirilmiyor, sebebi yazılıyor", async () => {
    const tree = await walkTree(
      lister({ "/is": [ent("bilinmiyor", 0, 12), ent("a.txt", FILE, 1)] }),
      "/is",
      explain,
    );

    expect(tree.files.map((f) => f.rel)).toEqual(["is/a.txt"]);
    expect(tree.skipped).toEqual([
      {
        path: "/is/bilinmiyor",
        why: "the target did not say what kind of entry this is",
      },
    ]);
  });

  /*
   * ⚠️ KARŞI KANITI: aynı bağ, kipi GÖNDERİLDİĞİNDE de girmiyor.
   * İki yol da kapalı olmalı, yoksa kapının hangisinden geçildiği
   * hedefin seçimine kalıyor.
   */
  it("tip bilgisi gelse de gelmese de bağ arşive girmiyor", async () => {
    const withType = await walkTree(
      lister({ "/is": [ent("bag", LINK)] }),
      "/is",
      explain,
    );
    const without = await walkTree(
      lister({ "/is": [{ ...ent("bag", LINK), mode: 0, isLink: false }] }),
      "/is",
      explain,
    );

    expect(withType.files).toEqual([]);
    expect(without.files).toEqual([]);
  });

  /*
   * ⚠️ TAVANA KADAR İNDİRİP "tamamlandı" DEMEK YOK. Yarım bir arşiv,
   * kullanıcıya eksik olduğunu göremeyeceği bir kopya vermek olurdu.
   *
   * (Tavanın SEBEBİ ilk yazdığım gibi "journalCap aşılırsa oturum ölür"
   * değil — o tavan oturumun toplamını değil, iki saniyede bir boşalan
   * BİRİKİMİ sınırlıyor. Gerekçenin doğrusu tree.ts'in başında.)
   */
  it("tavanı aşan ağaç yarım indirilmiyor, reddediliyor", async () => {
    const many = Array.from({ length: maxTreeEntries + 10 }, (_, i) =>
      ent(`f${i}`, FILE, 1),
    );

    await expect(
      walkTree(lister({ "/buyuk": many }), "/buyuk", explain),
    ).rejects.toThrow(/more than 4,000 entries/);
  });

  // Ve sebep ne yapılacağını da söylüyor: cümle bir çıkış yolu içermeli.
  it("ret cümlesi ne yapılacağını söylüyor", async () => {
    const many = Array.from({ length: maxTreeEntries + 1 }, (_, i) =>
      ent(`f${i}`, FILE, 1),
    );

    await expect(
      walkTree(lister({ "/buyuk": many }), "/buyuk", explain),
    ).rejects.toThrow(/Pick a subfolder, or use an SFTP client/);
  });

  /*
   * ⚠️ 2 GiB SINIRI TARAMADA, İNDİRMEDE DEĞİL. Yarısını indirip sonra
   * vazgeçmek hem bant genişliği hem de kullanıcıya yarım bir arşiv
   * vermek olurdu.
   */
  it("2 GiB'ı aşan ağaç indirme başlamadan reddediliyor", async () => {
    const gib = 1024 * 1024 * 1024;
    const t = lister({
      "/is": [ent("a.bin", FILE, 1.5 * gib), ent("b.bin", FILE, 1.5 * gib)],
    });

    await expect(walkTree(t, "/is", explain)).rejects.toThrow(/more than 2 GiB/);
  });

  /*
   * ⚠️ SONSUZ DERİNLİK BAĞSIZ DA MÜMKÜN: bind-mount ve /proc gibi kendini
   * tekrar eden ağaçlar var. Derinlik tavanı olmadan gezinmek, tarayıcıyı
   * girdi tavanına çarpana kadar döndürür.
   */
  it("çok derin dallar atlanıyor, gezinti bitiyor", async () => {
    const tree: Record<string, Entry[]> = {};
    let path = "/is";
    for (let i = 0; i <= maxTreeDepth + 5; i++) {
      tree[path] = [ent("alt", DIR)];
      path += "/alt";
    }
    tree[path] = [];

    const got = await walkTree(lister(tree), "/is", explain);

    expect(got.skipped.at(-1)?.why).toBe(
      `nested deeper than ${maxTreeDepth} levels`,
    );
    // Kök de bir girdi: tavan kadar dizin açıldı, daha fazlası değil.
    expect(got.dirs.length).toBe(maxTreeDepth);
  });

  /*
   * ⚠️ OKUNAMAYAN TEK DİZİN BÜTÜN İNDİRMEYİ DÜŞÜRMÜYOR. Bir ağaçta izin
   * verilmeyen bir alt dizin yüzünden indirmeyi reddetmek, çalışan bir
   * şeyi çalışmaz yapardı. Ama eksik olduğu YAZILIYOR — ve postern'in
   * kendi gerekçesi olduğu gibi taşınıyor.
   */
  it("reddedilen alt dizin gezintiyi bitirmiyor", async () => {
    const t = lister({
      "/is": [ent("acik", DIR), ent("kapali", DIR)],
      "/is/acik": [ent("x.txt", FILE, 2)],
    });

    const tree = await walkTree(t, "/is", explain);

    expect(tree.files.map((f) => f.rel)).toEqual(["is/acik/x.txt"]);
    expect(tree.skipped).toEqual([
      { path: "/is/kapali", why: "postern: not allowed" },
    ]);
  });

  /*
   * ⚠️ AYNI ADIN İKİ KEZ GELMESİ HEDEFİN ELİNDE — ve arşivde bir dosya,
   * başka bir girdinin DİZİNİ hâline gelebiliyor. Bunu gerçek `unzip`
   * öğretti: çakışan girdilerde "üzerine yazayım mı" diye soruyor, yani
   * biri diğerini eziyor. Teklik kardeşler arasında aranıyor.
   */
  it("aynı seviyedeki çakışan adlar ayrılıyor", async () => {
    const t = lister({
      "/is": [ent("kayit", DIR), ent("kayit", FILE, 4)],
      "/is/kayit": [],
    });

    const tree = await walkTree(t, "/is", explain);

    expect(tree.dirs.map((d) => d.rel)).toEqual(["is", "is/kayit"]);
    expect(tree.files.map((f) => f.rel)).toEqual(["is/kayit (2)"]);
  });

  /*
   * ⚠️ KÖK GİRDİSİ HER ZAMAN VAR. Boş bir klasör indirildiğinde arşivde
   * hiçbir şey olmasaydı, kullanıcı indirmenin çalışmadığını sanardı.
   */
  it("boş dizinde bile kök girdisi çıkıyor", async () => {
    const tree = await walkTree(lister({ "/is/bos": [] }), "/is/bos", explain);

    expect(tree.dirs.map((d) => d.rel)).toEqual(["bos"]);
    expect(tree.files).toEqual([]);
    expect(tree.bytes).toBe(0);
  });

  /*
   * ⚠️ ATLANANLAR DA SINIRSIZ OLAMAZ: bağlar tavan SAYACINA girmiyor
   * (defterde satır bırakmıyorlar), yani hedefte bir milyon bağ açan biri
   * hem belleği hem arşivin içindeki notu şişirebilirdi. Liste kırpılıyor
   * ama SAYI tam veriliyor — kırpıldığını söylemeyen bir liste, eksiksiz
   * sanılır.
   */
  it("çok fazla atlama listesi kırpılıyor, sayısı kırpılmıyor", async () => {
    const links = Array.from({ length: maxNoted + 37 }, (_, i) =>
      ent(`bag${i}`, LINK),
    );

    const tree = await walkTree(lister({ "/is": links }), "/is", explain);

    expect(tree.skipped.length).toBe(maxNoted);
    expect(tree.skippedMore).toBe(37);
    expect(skipNote("/is", tree, [])).toContain("and 37 more, not listed here");
  });

  /*
   * ⚠️ DURDURMA GEZİNTİYİ DE KESMELİ, YALNIZCA İNDİRMEYİ DEĞİL. Tarama
   * bir ağaçta dakikalarca sürebiliyor ve o sırada Stop'a basan
   * kullanıcı, taramanın sonunu beklemek zorunda kalmamalı.
   */
  /*
   * ⚠️ LİSTELEME SIRASINDA DURDURULMAK "OKUNAMADI" DEĞİL. readdir
   * durdurma sinyalini de taşıyor, yani Halted oradan da gelebiliyor;
   * gezginin "okunamayan dizini atla ve devam et" dalı onu yutarsa,
   * kullanıcının bastığı Stop arşivin içinde "bu dizin okunamadı" diye
   * kaydedilir ve gezinti sürer.
   */
  it("listeleme sırasında durdurmak nota yazılmıyor", async () => {
    const { signal, stop } = newStop();
    const t: Lister & { opened: string[] } = {
      opened: [],
      async readdir(p: string) {
        this.opened.push(p);
        stop();
        throw new Halted();
      },
    };

    await expect(
      walkTree(t, "/is", explain, { signal }),
    ).rejects.toBeInstanceOf(Halted);
  });

  it("durdurulan gezinti Halted ile çıkıyor", async () => {
    const { signal, stop } = newStop();
    const t = lister({
      "/is": [ent("a", DIR), ent("b", DIR)],
      "/is/a": [ent("x.txt", FILE, 1)],
      "/is/b": [ent("y.txt", FILE, 1)],
    });

    await expect(
      walkTree(t, "/is", explain, {
        signal,
        // İlk girdiden sonra durduruluyor.
        onSeen: (n) => {
          if (n >= 2) stop();
        },
      }),
    ).rejects.toBeInstanceOf(Halted);
  });
});

describe("hedefin ürettiği tuzaklar", () => {
  /*
   * ⚠️ TAVAN İNCELENEN HER GİRDİYİ SAYIYOR. İlk hâli yalnızca ALINAN
   * dosya ve dizinleri sayıyordu; atlananlar sayaca hiç girmiyordu.
   * Oysa reddedilen her dizin defterde satır bırakıyor ve atlanan her
   * girdi notun adayı — yani hiçbir dosya vermeyen bir dizin bile
   * sınırsız iş yaptırabiliyordu.
   */
  it("atlanan girdiler de tavana sayılıyor", async () => {
    const links = Array.from({ length: maxTreeEntries + 5 }, (_, i) =>
      ent(`bag${i}`, LINK),
    );

    await expect(
      walkTree(lister({ "/is": links }), "/is", explain),
    ).rejects.toThrow(/more than 4,000 entries/);
  });

  /*
   * ⚠️ UZUN YOL DENETİM SATIRINI ZEHİRLİYOR. session_files.path btree
   * ile indeksli ve PostgreSQL ~2704 baytta reddediyor; postern ise yolu
   * 4096 bayta kadar saklıyor. Aradaki bir yol INSERT'i düşürüyor, o da
   * oturumu öldürüp satırı tamponun BAŞINA geri koyuyor — sonraki her
   * boşaltma aynı satıra çarpıyor. Hedefte iç içe dizin açan biri bunu
   * üretebilir.
   */
  it("kaydedilemeyecek kadar uzun yol atlanıyor", async () => {
    const long = "u".repeat(maxPathBytes + 10);
    const tree = await walkTree(
      lister({ "/is": [ent(long, FILE, 1), ent("a.txt", FILE, 1)] }),
      "/is",
      explain,
    );

    expect(tree.files.map((f) => f.rel)).toEqual(["is/a.txt"]);
    expect(tree.skipped[0].why).toBe("its path is too long to record");
  });

  /*
   * ⚠️ NOTUN ADI HEDEFE KAPTIRILMIYOR. Aynı adla bir dosya açan biri
   * bariz adı kendisi tutar, postern'in gerçek notu "… (2).txt" olurdu
   * ve denetçi saldırganın güvence metnini okurdu. Ad ÖNCEDEN ayrılıyor:
   * yeniden adlandırılan, hedefin dosyası oluyor.
   */
  it("hedefin aynı adlı dosyası notun adını kapamıyor", async () => {
    const tree = await walkTree(
      lister({ "/is": [ent(noteName, FILE, 4)] }),
      "/is",
      explain,
    );

    expect(tree.files.map((f) => f.rel)).toEqual([
      `is/POSTERN-NOT-INCLUDED (2).txt`,
    ]);
  });
});

describe("arşive konan not", () => {
  /*
   * ⚠️ NOT ARŞİVİN İÇİNE GİRİYOR, YALNIZCA EKRANA DEĞİL. Panel
   * kapandıktan sonra geriye yalnızca arşiv kalıyor; "şunlar eksik"
   * bilgisi ekranda kalırsa, altı ay sonra o arşive bakan denetçi tam bir
   * kopyaya baktığını sanar.
   */
  it("atlananları ve okunamayanları AYRI başlıklar altında yazıyor", () => {
    const note = skipNote(
      "/var/log",
      {
        files: [],
        dirs: [],
        skipped: [{ path: "/var/log/current", why: "symbolic link" }],
        skippedMore: 0,
        bytes: 0,
      },
      [{ path: "/var/log/auth.log", why: "permission denied" }],
    );

    expect(note).toContain("/var/log");
    expect(note).toContain("Skipped while listing the folder:");
    expect(note).toContain("/var/log/current: symbolic link");
    expect(note).toContain("Could not be read:");
    expect(note).toContain("/var/log/auth.log: permission denied");
  });

  /*
   * ⚠️ NOTUN SATIRLARINI HEDEF YAZAMAZ. Sebep metnini hedefin
   * sftp-server'ı yazıyor; içine bir satır sonu koyan biri notun KENDİ
   * başlıklarını uydurabilir ("Could not be read:" diye sahte bir
   * bölüm), bir ESC dizisi koyan biri de dosyayı `cat` ile açan
   * denetçinin ekranını boyayabilir.
   */
  it("hedefin metni notun satırlarını uyduramıyor", () => {
    const note = skipNote(
      "/is",
      { files: [], dirs: [], skipped: [], skippedMore: 0, bytes: 0 },
      [
        {
          path: "/is/a",
          why: "denied\nCould not be read:\n  /etc/shadow: fetched fine\u001b[2J",
        },
      ],
    );

    /*
     * Ölçülen şey metnin İÇİNDE o sözcüklerin geçmemesi değil — geçebilir
     * ve zararsız. Ölçülen şey, hedefin yeni bir SATIR başlatamaması:
     * notun başlıkları satırın tamamı, ve öyle bir satır bir tane.
     */
    const headings = note.split("\n").filter((l) => l === "Could not be read:");
    expect(headings).toHaveLength(1);
    expect(note).not.toMatch(/\u001b/);
    expect(note).toContain("deniedCould not be read:  /etc/shadow: fetched fine");
  });

  /*
   * ⚠️ SEBEPLERİN BİR KISMINI HEDEF YAZIYOR. Not, hedefin cümlesine
   * postern'in sesini ödünç veremez; kimin konuştuğunu ayıramıyorsak
   * bunu okuyana söylemek zorundayız.
   */
  it("sebeplerin kaynağını söylüyor", () => {
    const note = skipNote(
      "/is",
      { files: [], dirs: [], skipped: [], skippedMore: 0, bytes: 0 },
      [],
    );

    expect(note).toContain("come from the target");
  });

  /*
   * ⚠️ NOT KANITLAYAMADIĞINI İDDİA ETMİYOR. İlk hâli "geri kalan her şey
   * EKSİKSİZ okundu" ve "her dosyanın defterde bir satırı var" diyordu.
   * İkisini de bu kod bilemez: birincisi teslim edilen baytın
   * doğrulanmasına, ikincisi sunucunun defteri yazabilmiş olmasına
   * bağlı — ve defter dolduğunda olayı sessizce düşürebiliyor. Arşivin
   * içine konan hak edilmemiş bir onay, arşivin kendisinden kötü.
   */
  it("kanıtlayamadığını iddia etmiyor", () => {
    const note = skipNote(
      "/var/log",
      { files: [], dirs: [], skipped: [], skippedMore: 0, bytes: 0 },
      [],
    );

    expect(note).not.toMatch(/read in full/i);
    expect(note).not.toMatch(/has a row in the/i);
    // Ne yapılacağını söylüyor: doğrulamanın yeri burası değil.
    expect(note).toContain("postern session verify");
  });
});

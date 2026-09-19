import { useCallback, useEffect, useState } from "react";
import { api, PathRule, toMessage } from "../api";
import { ActionButton, ErrorLine } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";

/**
 * PathRules — bir rolün SFTP yol kuralları.
 *
 * ⚠️ NİYE PANELDE OLMASI GEREKİYORDU. Kurallar bugüne kadar yalnızca
 * `postern group path set` ile yazılabiliyordu ve panelin dosya
 * tarayıcısı, kuralı olmayan bir hesapta kendini KAPATIYOR. Yani panel,
 * kullanıcıyı ancak bir kabuğa girip komut çalıştırarak çözebileceği bir
 * duvara götürüyordu. Kuralı doğuran ekranla kuralı yazan ekran aynı
 * yerde olmalı.
 *
 * ⚠️ BOŞ LİSTE "ERİŞİM YOK" DEĞİL. Kuralsız rol kısıtsız; ekran bunu
 * böyle yazıyor. Boş bir tabloyu "hiçbir yere erişemez" diye okumak,
 * yöneticiye koymadığı bir korumayı koymuş gibi gösterirdi — ve bu,
 * yanlış tarafa düşen bir yanılgı.
 */
export default function PathRules({ group }: { group: string }) {
  const [rules, setRules] = useState<PathRule[] | null>(null);
  const [error, setError] = useState("");
  const [prefix, setPrefix] = useState("");
  const [mode, setMode] = useState<"read" | "write" | "deny">("read");
  const [adding, setAdding] = useState(false);

  const load = useCallback(() => {
    api
      .rolePaths(group)
      .then((r) => {
        setRules(r);
        setError("");
      })
      .catch((e: unknown) => setError(toMessage(e)));
  }, [group]);

  useEffect(load, [load]);

  // ⚠️ BAŞARIYI DÖNDÜRÜYOR: hata durumunda modal AÇIK kalmalı, yoksa
  // kapanan modal arkadaki hata satırını görmeyen kullanıcıya işlemin
  // tuttuğunu düşündürür.
  const add = () => {
    const p = prefix.trim();
    if (!p) return Promise.resolve(false);
    return api
      .setRolePath(group, {
        prefix: p,
        allow: mode !== "deny",
        can_write: mode === "write",
      })
      .then(() => {
        setPrefix("");
        load();
        return true;
      })
      .catch((e: unknown) => {
        setError(toMessage(e));
        return false;
      });
  };

  const remove = (p: string) =>
    api
      .deleteRolePath(group, p)
      .then(load)
      .catch((e: unknown) => setError(toMessage(e)));

  /*
   * ⚠️ SON KURALI SİLMEK KISITI KALDIRIYOR ve onay metni bunu SÖYLÜYOR.
   * "Remove /var/log?" diye sormak, tek kuralı silen yöneticiye
   * daraltma yaptığını düşündürürdü; oysa yaptığı şey rolü kısıtsız
   * bırakmak.
   */
  const columns: Column<PathRule>[] = [
    {
      key: "prefix",
      header: "Prefix",
      // wrap: uzun bir önek tek parça; sarmayınca tablo kartın
      // gövdesinden taşıyordu (ölçüldü).
      className: "wrap",
      value: (r) => r.prefix,
      render: (r) => <code>{r.prefix}</code>,
    },
    {
      key: "access",
      header: "Access",
      value: (r) =>
        !r.allow ? "denied" : r.can_write ? "read-write" : "read-only",
      render: (r) =>
        !r.allow ? (
          <span className="badge badge-danger">denied</span>
        ) : r.can_write ? (
          <span className="badge badge-warn">read-write</span>
        ) : (
          <span className="badge badge-ok">read-only</span>
        ),
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (r) => (
        <ActionButton
          variant="danger"
          onClick={() => remove(r.prefix)}
          confirm={removeConfirm(r.prefix)}
          label={`remove rule ${r.prefix} from group ${group}`}
        >
          Remove
        </ActionButton>
      ),
    },
  ];

  const removeConfirm = (p: string) =>
    rules?.length === 1
      ? `Remove "${p}"? It is the last rule on "${group}", so the group becomes unrestricted — every path opens for everyone holding it.`
      : `Remove the rule for "${p}" from the group "${group}"?`;

  return (
    <div>
      <ErrorLine msg={error} />

      {rules === null && <p className="muted">Loading…</p>}

      {rules?.length === 0 && (
        <p className="msg msg-warn" role="status">
          No rules — <strong>this group is unrestricted</strong> and reaches
          every path over SFTP. Adding the first rule starts the restriction.
        </p>
      )}

      {/*
        ⚠️ TABLO, ELLE ÇİZİLEN LİSTE DEĞİL. Bir rolde yüzlerce kural
        olabiliyor ve önceki hâlde aradığın öneki bulmanın yolu sayfada
        göz gezdirmekti (kullanıcı söyledi). DataTable arama, sıralama ve
        sayımı hazır getiriyor; sütunlar panelin geri kalanıyla aynı.
      */}
      {rules && rules.length > 0 && (
        <DataTable
          rows={rules}
          columns={columns}
          rowKey={(r) => r.prefix}
          initialSort={{ key: "prefix", dir: "asc" }}
          noun="rule"
          searchLabel={`search the SFTP path rules of ${group}`}
          searchPlaceholder="Search prefixes…"
        />
      )}

      <div className="form-actions">
        <ActionButton variant="primary" onClick={() => setAdding(true)}>
          Add rule
        </ActionButton>
      </div>

      {/*
        ⚠️ ÜÇ SÜRPRİZ BURADA YAZILI, çünkü üçü de kural yazarken fark
        edilmiyor ve sonradan "neden çalışmıyor" diye geliyor. Üçüncüsü —
        kuralsız rolün her şeyi açması — bağımsız bir denetimde eksik
        bulundu: README onu yazıyordu, kuralın YAZILDIĞI ekran yazmıyordu.
      */}
      <p className="pathrules-hint">
        The longest matching prefix wins, so <code>/home/dev/.ssh</code> as a
        deny carves a hole in an allowed <code>/home/dev</code>. Rules from all
        of a user's groups are pooled, and at equal length a deny beats an
        allow. A group with <strong>no rules at all is unrestricted</strong>,
        and one such group among a user's groups switches every rule here off.{" "}
        <strong>Links are resolved by the target, not by postern</strong>: a
        rule constrains the path the client writes, so a link inside an allowed
        directory can still lead somewhere no rule names.
      </p>

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        narrow
        title={`Add an SFTP path rule to "${group}"`}
        description="A prefix and what the group may do under it. The longest matching prefix wins, and at equal length a deny beats an allow."
      >
        <div className="form-grid cols-2">
          <label className="span-all">
            Prefix
            <input
              value={prefix}
              placeholder="/var/log or ~/uploads"
              onChange={(e) => setPrefix(e.target.value)}
            />
          </label>
          {/*
            ⚠️ İPUCU LABEL'IN DIŞINDA. İçine koyunca input'un erişilebilir
            adı "Prefix" olmaktan çıkıp bütün cümleyi kapsıyor — testler
            alanı bulamadı, yani ekran okuyucu da alanın adını iki
            cümlelik bir açıklama olarak okuyacaktı.

            ⚠️ AMA FORMDA DURUYOR. Bir grubun kuralında bir KİŞİNİN evini
            adıyla yazmak, o grubun geri kalan her üyesi için yanlış kural
            demek — demoda ölçüldü. Token'ı bilmeyen yönetici, bulacağı
            tek çözüm olarak kişi başına kural yazardı.
          */}
          <span className="hint span-all">
            <code>~</code> is each person&apos;s own home on that host, read
            from the host itself — one rule that is right for everyone in the
            group.
          </span>
          <label>
            Access
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as typeof mode)}
              aria-label={`access for the new rule on group ${group}`}
            >
              <option value="read">Read-only</option>
              <option value="write">Read-write</option>
              <option value="deny">Deny</option>
            </select>
          </label>
        </div>
        <div className="form-actions">
          <ActionButton
            variant="primary"
            onClick={() => add().then((ok) => ok && setAdding(false))}
            disabled={!prefix.trim()}
          >
            Add rule
          </ActionButton>
        </div>
      </Modal>
    </div>
  );
}

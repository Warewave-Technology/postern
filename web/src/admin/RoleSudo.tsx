import { useState } from "react";
import { api, RoleSudoRule, toMessage } from "../api";
import { ActionButton, ErrorLine } from "./common";

/**
 * RoleSudo — bir rolün sudo kuralı.
 *
 * ⚠️ BU EKRAN ROLÜN NE ANLAMA GELDİĞİNİ DEĞİŞTİRİYOR ve bunu yazıyor.
 * Kuralsız bir rol yalnızca "şu makinelere erişebilir" demek; kurallı bir
 * rol "şu komutları root olarak çalıştırabilir" de demek. Role birini
 * eklemek artık daha fazlasını veriyor, ve bunu ekranda görmeyen bir
 * yönetici farkında olmadan yetki dağıtır.
 *
 * ⚠️ KURAL HEDEFE TEMBEL İNİYOR. postern o makineye bir daha dokunduğunda
 * yazılıyor (bugün: orada geçici bir hesap açıldığında). Kaydetmek
 * "bütün makinelerde etkili oldu" demek değil; ekran bunu söylüyor, çünkü
 * tersini sanmak koyulmamış bir yetkiye güvenmek olurdu.
 *
 * ⚠️ KOMUTLAR SATIR SATIR, geçici erişim sihirbazındaki kutunun aynısı:
 * ilk kelime yol, kalanı argüman. İki ekranda iki farklı yazım biçimi
 * öğretmek, kuralı yanlış yazdıran en ucuz yol.
 */
export default function RoleSudo({
  role,
  rule,
  onChanged,
}: {
  role: string;
  rule?: RoleSudoRule;
  onChanged: () => Promise<unknown>;
}) {
  const [text, setText] = useState((rule?.commands ?? []).join("\n"));
  const [runAs, setRunAs] = useState(rule?.run_as ?? "");
  const [acknowledged, setAcknowledged] = useState(rule?.acknowledged ?? false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");

  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const save = async () => {
    setError("");
    setNote("");
    try {
      await api.setRoleSudo(role, {
        run_as: runAs.trim(),
        commands: lines.map((l) => {
          const [path, ...args] = l.split(/\s+/);
          return { path, args };
        }),
        acknowledged,
      });
      setNote(
        `Saved. A host gets this rule the next time postern works on it; the ones it has not touched yet still carry what they had.`,
      );
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const remove = async () => {
    setError("");
    setNote("");
    try {
      const r = await api.deleteRoleSudo(role);
      setText("");
      setRunAs("");
      setAcknowledged(false);
      setNote(r.note ?? "The rule is gone from postern.");
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  return (
    <>
      <p className="muted small">
        Written on each host as <code>%{role}</code> in{" "}
        <code>/etc/sudoers.d/postern-{role}</code>. Everyone in this role draws it
        from the group; what a temporary grant adds on top stays with that account
        and leaves with it.
      </p>

      {/* ⚠️ KUTU TAM GENİŞLİK: etiketin doğal genişliği kutuyu üçte bire
          düşürüyordu ve uzun yollar ortadan kırılıyordu (ekranda
          görüldü). Yollar okunmadan doğrulanamaz. */}
      <div className="form-grid">
        <label className="span-all">
          Commands, one per line
          <textarea
            rows={5}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"/usr/sbin/nginx -t\n/bin/systemctl reload nginx"}
          />
        </label>
        <label>
          Run as
          <input
            value={runAs}
            onChange={(e) => setRunAs(e.target.value)}
            placeholder="root"
          />
        </label>
      </div>

      {/*
        ⚠️ ONAY KUTUSU ÖNCEDEN İŞARETLİ DEĞİL ve olmayacak. Sunucu kaçış
        riski taşıyan kuralı reddedip SEBEBİNİ söylüyor; kutu ancak o
        cümleyi okuduktan sonra işaretleniyor.
      */}
      <label className="check">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(e) => setAcknowledged(e.target.checked)}
        />
        I accept that a command here may open a root shell (an editor, a pager,
        anything that runs another program), and that this rule hands that to
        everyone in the role
      </label>

      <ErrorLine msg={error} />
      {note !== "" && (
        <p className="msg msg-ok" role="status">
          {note}
        </p>
      )}

      <div className="form-actions">
        <ActionButton variant="primary" onClick={save} disabled={lines.length === 0}>
          Save rule
        </ActionButton>
        {rule && (
          <span className="form-push">
            <ActionButton
              variant="danger"
              onClick={remove}
              confirm={`Remove the sudo rule from the role "${role}"? Hosts that already have the file keep it until postern next works on them.`}
              label={`remove the sudo rule from role ${role}`}
            >
              Remove rule
            </ActionButton>
          </span>
        )}
      </div>

      {rule && (
        <p className="muted small">
          Last written by {rule.updated_by}.
        </p>
      )}
    </>
  );
}

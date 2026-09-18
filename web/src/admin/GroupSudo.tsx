import { useState } from "react";
import { api, ApiError, GroupSudoCommand, GroupSudoRule, toMessage } from "../api";
import { ActionButton, ErrorLine } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";

/**
 * GroupSudo — bir rolün sudo kuralı: komutlar tablo, düzenleme modalda.
 *
 * ⚠️ BU EKRAN ROLÜN NE ANLAMA GELDİĞİNİ DEĞİŞTİRİYOR ve bunu yazıyor.
 * Kuralsız bir rol yalnızca "şu makinelere erişebilir" demek; kurallı bir
 * rol "şu komutları root olarak çalıştırabilir" de demek. Group birini
 * eklemek artık daha fazlasını veriyor.
 *
 * ⚠️ KOMUTLAR TABLO, YAZIM KUTUSU DEĞİL. İlk hâl tek bir textarea'ydı:
 * iki yüz komutlu bir kuralda aradığın satırı bulmanın yolu yok, silmenin
 * yolu metni elle kesmek (kullanıcı söyledi). Tablo arıyor, satır satır
 * siliyor; toplu yazmak isteyen için kutu ayrı bir modalda duruyor.
 *
 * ⚠️ KURAL HEDEFE TEMBEL İNİYOR. postern o makineye bir daha dokunduğunda
 * yazılıyor (bugün: orada geçici bir hesap açıldığında). Kaydetmek
 * "bütün makinelerde etkili oldu" demek değil.
 */
export default function GroupSudo({
  group,
  rule,
  onChanged,
}: {
  group: string;
  rule?: GroupSudoRule;
  onChanged: () => Promise<unknown>;
}) {
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [adding, setAdding] = useState(false);
  /*
   * ⚠️ DÜZENLEME SATIR BAZINDA, TOPLU METİN DEĞİL.
   *
   * Önceki hâl bütün kuralı tek bir yazım kutusuna koyuyordu ve komutun
   * hesabı satır başındaki "(postgres)" önekinde taşınıyordu. ÖLÇÜLDÜ:
   * o öneki elle yeniden yazarken düşüren bir düzenleme, komutu sessizce
   * root'a çeviriyordu — yani yanlış yöne, ve hiçbir uyarı olmadan.
   * Hesap artık kendi alanında; kaybolabileceği bir yer yok.
   */
  const [editing, setEditing] = useState<GroupSudoCommand | null>(null);

  const commands: GroupSudoCommand[] = rule?.commands ?? [];

  const savedNote =
    "Saved. A host gets this rule the next time postern works on it; the ones it has not touched yet still carry what they had.";

  /*
   * write, kuralın TAMAMINI yazıyor — uç PUT, yama değil. Komut eklemek
   * ve silmek de buradan geçiyor, böylece "listede gördüğün şey kuralın
   * kendisi" kuralı bozulmuyor.
   */
  const write = async (next: GroupSudoCommand[], ack: boolean) => {
    setError("");
    setNote("");
    // Komutsuz kural hiçbir şey vermiyor ve sunucu da reddediyor: son
    // komutu silmek kuralı kaldırmak demek.
    if (next.length === 0) {
      await api.deleteRoleSudo(group);
      setNote("The last command went, so the rule is gone from postern.");
      await onChanged();
      return;
    }
    await api.setRoleSudo(group, {
      commands: next.map((c) => {
        const [path, ...args] = c.command.trim().split(/\s+/);
        return { path, args, run_as: c.run_as };
      }),
      acknowledged: ack,
    });
    setNote(savedNote);
    await onChanged();
  };

  const removeCommand = async (c: GroupSudoCommand) => {
    try {
      await write(
        commands.filter((x) => !(x.command === c.command && x.run_as === c.run_as)),
        rule?.acknowledged ?? false,
      );
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const removeRule = async () => {
    setError("");
    setNote("");
    try {
      const r = await api.deleteRoleSudo(group);
      setNote(r.note ?? "The rule is gone from postern.");
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const columns: Column<GroupSudoCommand>[] = [
    {
      key: "command",
      header: "Command",
      className: "wrap",
      // Arama sebebi de kapsıyor: "hangi komutlar kaçış yolu" sorusu tek
      // kutuya yazılabilsin.
      value: (c) => `${c.command} ${c.escape ?? ""}`,
      render: (c) => (
        <>
          {/*
            ⚠️ RİSK SATIRIN BAŞINDA. Tablonun altındaki not hangi komutun
            riskli olduğunu söylemiyordu; okuyan ya hepsinden şüpheleniyor
            ya hiçbirinden (kullanıcı ekrana bakıp söyledi). Sebep hem
            ipucunda hem ekran okuyucuya açık metinde.
          */}
          {c.escape && (
            <span className="risk" title={`${c.command} ${c.escape}`}>
              <span aria-hidden="true">!</span>
              <span className="sr-only">
                warning: {c.command} {c.escape}
              </span>
            </span>
          )}
          <code>{c.command}</code>
        </>
      ),
    },
    {
      /*
       * ⚠️ HESAP KENDİ SÜTUNUNDA. Komutun hangi hesapla çalıştığı yetkinin
       * yarısı: "pg_ctl reload" postgres olarak dar bir yetki, root olarak
       * makinenin tamamı. Komut metnine karıştırmak, sıralanabilir ve
       * aranabilir olmasını da engellerdi.
       */
      key: "run_as",
      header: "Runs as",
      value: (c) => c.run_as,
      render: (c) =>
        c.run_as === "root" ? (
          <span className="badge badge-warn">root</span>
        ) : (
          <code>{c.run_as}</code>
        ),
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (c) => (
        <>
        <ActionButton
          onClick={() => setEditing(c)}
          label={`edit command ${c.command} of group ${group}`}
        >
          Edit
        </ActionButton>
        <ActionButton
          variant="danger"
          onClick={() => removeCommand(c)}
          confirm={
            commands.length === 1
              ? `Remove "${c.command}"? It is the only command in the rule, so the rule itself goes and the group stops granting sudo.`
              : `Remove "${c.command}" (as ${c.run_as}) from the sudo rule of "${group}"? Everyone in the group loses it.`
          }
          label={`remove command ${c.command} from group ${group}`}
        >
          Remove
        </ActionButton>
        </>
      ),
    },
  ];

  return (
    <>
      <p className="muted small">
        Written on each host as <code>%{group}</code> in{" "}
        <code>/etc/sudoers.d/postern-{group}</code>. Everyone in this group draws
        it from the group; what a temporary grant adds on top stays with that
        account and leaves with it. Each command names the account it runs as —
        <code>root</code> unless you say otherwise.
      </p>

      <ErrorLine msg={error} />
      {note !== "" && (
        <p className="msg msg-ok" role="status">
          {note}
        </p>
      )}

      {commands.length === 0 ? (
        <p className="state">
          No rule — this group grants no sudo of its own. A temporary grant can
          still give one account commands of its own.
        </p>
      ) : (
        <DataTable
          rows={commands}
          columns={columns}
          rowKey={(c) => `${c.run_as} ${c.command}`}
          initialSort={{ key: "command", dir: "asc" }}
          noun="command"
          searchLabel={`search the sudo commands of ${group}`}
          searchPlaceholder="Search commands…"
          foot={
            commands.some((c) => c.escape) ? (
              <span className="muted small">
                A command marked <span className="risk">!</span> can start
                another program, so the group really gets{" "}
                {commands.length === 1 ? "that account" : "those accounts"} in
                full. Somebody accepted that when the rule was written.
              </span>
            ) : undefined
          }
        />
      )}

      <div className="form-actions">
        <ActionButton variant="primary" onClick={() => setAdding(true)}>
          Add command
        </ActionButton>
        {rule && (
          <span className="form-push">
            <ActionButton
              variant="danger"
              onClick={removeRule}
              confirm={`Remove the sudo rule from the group "${group}"? Hosts that already have the file keep it until postern next works on them.`}
              label={`remove the sudo rule from group ${group}`}
            >
              Remove rule
            </ActionButton>
          </span>
        )}
      </div>

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        narrow
        title={`Add a sudo command to "${group}"`}
        description="One command, with the arguments it is allowed to take. The first word is the path; the account it runs as is a separate field."
      >
        {adding && (
          <RuleForm
            group={group}
            initial=""
            initialRunAs="root"
            submitLabel="Add command"
            onSave={async (next, ack) => {
              await write([...commands, next], ack);
              setAdding(false);
            }}
          />
        )}
      </Modal>

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        narrow
        title={`Edit a sudo command of "${group}"`}
        description="The command and the account it runs as. Everything else in the rule stays as it is."
      >
        {editing && (
          <RuleForm
            group={group}
            initial={editing.command}
            initialRunAs={editing.run_as}
            submitLabel="Save command"
            onSave={async (next, ack) => {
              await write(
                commands.map((c) =>
                  c.command === editing.command && c.run_as === editing.run_as ? next : c,
                ),
                ack,
              );
              setEditing(null);
            }}
          />
        )}
      </Modal>
    </>
  );
}

function RuleForm({
  group,
  initial,
  initialRunAs,
  submitLabel,
  onSave,
}: {
  group: string;
  initial: string;
  initialRunAs: string;
  submitLabel: string;
  onSave: (command: GroupSudoCommand, acknowledged: boolean) => Promise<void>;
}) {
  const [text, setText] = useState(initial);
  const [runAs, setRunAs] = useState(initialRunAs);
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState("");
  /*
   * ⚠️ ONAY KUTUSU RET GELENE KADAR YOK.
   *
   * Her komut zaten root olarak çalışıyor (sudo'nun da varsayılanı), o
   * yüzden her kaydetmede duran bir "root olabilir" kutusu, kabul edilen
   * şeyi anlamsızlaştırıyordu: kullanıcı haklı olarak "bu kutunun anlamı
   * ne" diye sordu. Kabul edilen şey root DEĞİL, DAR YETKİDEN KAÇIŞ: bir
   * editör, bir sayfalayıcı ya da başka program çalıştıran bir komut,
   * verilen tek komutu o hesabın tamamına çeviriyor.
   *
   * Kutu yalnızca sunucu böyle bir komut yüzünden reddettiğinde ve
   * reddin SEBEBİNİN altında beliriyor; "onaylanabilir mi" kararını da
   * sunucu söylüyor (ApiError.acknowledgeable), çünkü joker ya da göreli
   * yol taşıyan bir ret onayla da geçmiyor.
   */
  const [canAcknowledge, setCanAcknowledge] = useState(false);

  /*
   * ⚠️ HESAP KENDİ ALANINDA, METNİN İÇİNDE DEĞİL. Metne gömülü bir hesap
   * ("(postgres) /usr/bin/pg_ctl") elle düzenlenirken düşürülebiliyor ve
   * düştüğünde komut sessizce root'a çıkıyordu — ölçüldü.
   */
  const command: GroupSudoCommand = {
    command: text.trim(),
    run_as: runAs.trim() || "root",
  };

  const save = async () => {
    setError("");
    try {
      await onSave(command, acknowledged);
    } catch (e: unknown) {
      setError(toMessage(e));
      if (e instanceof ApiError && e.acknowledgeable) {
        setCanAcknowledge(true);
      }
    }
  };

  return (
    <>
      <div className="form-grid cols-2">
        <label>
          Command
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="/usr/sbin/nginx -t"
          />
        </label>
        <label>
          Runs as
          <input
            value={runAs}
            onChange={(e) => setRunAs(e.target.value)}
            placeholder="root"
          />
        </label>
      </div>

      <ErrorLine msg={error} />

      {canAcknowledge && (
        <label className="check check-ack">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I understand this command can start another program, so what the group
          really gets is that account in full — not just the command written
          here. Write it anyway.
        </label>
      )}

      <div className="form-actions">
        <ActionButton variant="primary" onClick={save} disabled={command.command === ""}>
          {submitLabel}
        </ActionButton>
        <span className="muted small">
          {command.command === ""
            ? "Nothing to save yet."
            : `${command.command} as ${command.run_as}, for everyone in ${group}.`}
        </span>
      </div>
    </>
  );
}

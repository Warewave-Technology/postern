import { useState } from "react";
import { api, RoleSudoCommand, RoleSudoRule, toMessage } from "../api";
import { ActionButton, ErrorLine } from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";

/**
 * RoleSudo — bir rolün sudo kuralı: komutlar tablo, düzenleme modalda.
 *
 * ⚠️ BU EKRAN ROLÜN NE ANLAMA GELDİĞİNİ DEĞİŞTİRİYOR ve bunu yazıyor.
 * Kuralsız bir rol yalnızca "şu makinelere erişebilir" demek; kurallı bir
 * rol "şu komutları root olarak çalıştırabilir" de demek. Role birini
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
export default function RoleSudo({
  role,
  rule,
  onChanged,
}: {
  role: string;
  rule?: RoleSudoRule;
  onChanged: () => Promise<unknown>;
}) {
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState(false);

  const commands: RoleSudoCommand[] = rule?.commands ?? [];

  const savedNote =
    "Saved. A host gets this rule the next time postern works on it; the ones it has not touched yet still carry what they had.";

  /*
   * write, kuralın TAMAMINI yazıyor — uç PUT, yama değil. Komut eklemek
   * ve silmek de buradan geçiyor, böylece "listede gördüğün şey kuralın
   * kendisi" kuralı bozulmuyor.
   */
  const write = async (next: RoleSudoCommand[], ack: boolean) => {
    setError("");
    setNote("");
    // Komutsuz kural hiçbir şey vermiyor ve sunucu da reddediyor: son
    // komutu silmek kuralı kaldırmak demek.
    if (next.length === 0) {
      await api.deleteRoleSudo(role);
      setNote("The last command went, so the rule is gone from postern.");
      await onChanged();
      return;
    }
    await api.setRoleSudo(role, {
      commands: next.map((c) => {
        const [path, ...args] = c.command.trim().split(/\s+/);
        return { path, args, run_as: c.run_as };
      }),
      acknowledged: ack,
    });
    setNote(savedNote);
    await onChanged();
  };

  const removeCommand = async (c: RoleSudoCommand) => {
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
      const r = await api.deleteRoleSudo(role);
      setNote(r.note ?? "The rule is gone from postern.");
      await onChanged();
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  const columns: Column<RoleSudoCommand>[] = [
    {
      key: "command",
      header: "Command",
      className: "wrap",
      value: (c) => c.command,
      render: (c) => <code>{c.command}</code>,
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
        <ActionButton
          variant="danger"
          onClick={() => removeCommand(c)}
          confirm={
            commands.length === 1
              ? `Remove "${c.command}"? It is the only command in the rule, so the rule itself goes and the role stops granting sudo.`
              : `Remove "${c.command}" (as ${c.run_as}) from the sudo rule of "${role}"? Everyone in the role loses it.`
          }
          label={`remove command ${c.command} from role ${role}`}
        >
          Remove
        </ActionButton>
      ),
    },
  ];

  return (
    <>
      <p className="muted small">
        Written on each host as <code>%{role}</code> in{" "}
        <code>/etc/sudoers.d/postern-{role}</code>. Everyone in this role draws
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
          No rule — this role grants no sudo of its own. A temporary grant can
          still give one account commands of its own.
        </p>
      ) : (
        <DataTable
          rows={commands}
          columns={columns}
          rowKey={(c) => `${c.run_as} ${c.command}`}
          initialSort={{ key: "command", dir: "asc" }}
          noun="command"
          searchLabel={`search the sudo commands of ${role}`}
          searchPlaceholder="Search commands…"
          foot={
            rule?.acknowledged ? (
              <span className="chip warn">
                a command here was accepted as a way out to a root shell
              </span>
            ) : undefined
          }
        />
      )}

      <div className="form-actions">
        <ActionButton variant="primary" onClick={() => setAdding(true)}>
          Add command
        </ActionButton>
        <ActionButton onClick={() => setEditing(true)}>
          {commands.length === 0 ? "Write the rule" : "Edit all commands"}
        </ActionButton>
        {rule && (
          <span className="form-push">
            <ActionButton
              variant="danger"
              onClick={removeRule}
              confirm={`Remove the sudo rule from the role "${role}"? Hosts that already have the file keep it until postern next works on them.`}
              label={`remove the sudo rule from role ${role}`}
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
        title={`Add a sudo command to "${role}"`}
        description="One command, with the arguments it is allowed to take. The first word is the path; the account it runs as is a separate field."
      >
        {adding && (
          <RuleForm
            role={role}
            initial=""
            single
            onSave={async (next, ack) => {
              await write([...commands, ...next], ack);
              setAdding(false);
            }}
          />
        )}
      </Modal>

      <Modal
        open={editing}
        onClose={() => setEditing(false)}
        title={`Sudo commands of "${role}"`}
        description="The whole rule, one command per line. Start a line with (account) to run that one as somebody other than root. What is here replaces what the role carries."
      >
        {editing && (
          <RuleForm
            role={role}
            initial={commands.map(writeLine).join("\n")}
            onSave={async (next, ack) => {
              await write(next, ack);
              setEditing(false);
            }}
          />
        )}
      </Modal>
    </>
  );
}

/*
 * parseLines, yazım kutusunu komutlara çevirir.
 *
 * ⚠️ SATIR BAŞINDAKİ (hesap) sudoers'ın kendi yazımı. Kutuya ayrı bir
 * "hesap" alanı koymak, satır satır farklı hesap yazmayı imkânsız
 * kılardı; bu önek dosyada göreceği biçimin aynısı, yani öğrenilen şey
 * iki yerde de aynı.
 */
function parseLines(text: string): RoleSudoCommand[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const m = /^\(([^)]*)\)\s*(.+)$/.exec(l);
      if (m) {
        return { run_as: m[1].trim() || "root", command: m[2].trim() };
      }
      return { run_as: "root", command: l };
    });
}

// writeLine, parseLines'ın tersi: kutuya konan satır.
function writeLine(c: RoleSudoCommand): string {
  return c.run_as === "root" ? c.command : `(${c.run_as}) ${c.command}`;
}

/**
 * RuleForm — komut yazma kutusu, modalların içinde.
 *
 * ⚠️ ONAY KUTUSU ÖNCEDEN İŞARETLİ DEĞİL. Sunucu kaçış riski taşıyan
 * kuralı reddedip SEBEBİNİ söylüyor; kutu ancak o cümle ekrana geldikten
 * sonra işaretleniyor, yani onaylayan neyi onayladığını okumuş oluyor.
 */
function RuleForm({
  role,
  initial,
  single = false,
  onSave,
}: {
  role: string;
  initial: string;
  single?: boolean;
  onSave: (commands: RoleSudoCommand[], acknowledged: boolean) => Promise<void>;
}) {
  const [text, setText] = useState(initial);
  const [runAs, setRunAs] = useState("root");
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState("");

  /*
   * Tek komut kipinde hesap ayrı bir alan; toplu kipte satır başındaki
   * (hesap) öneki taşıyor, çünkü orada her satırın hesabı farklı olabiliyor
   * ve tek bir alan hepsini aynı hesaba zorlardı.
   */
  const commands = single
    ? parseLines(text).map((c) => ({ ...c, run_as: runAs.trim() || "root" }))
    : parseLines(text);

  const save = async () => {
    setError("");
    try {
      await onSave(commands, acknowledged);
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  return (
    <>
      <div className="form-grid cols-2">
        <label className={single ? "" : "span-all"}>
          {single ? "Command" : "Commands, one per line"}
          {single ? (
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="/usr/sbin/nginx -t"
            />
          ) : (
            <textarea
              rows={6}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={"/usr/sbin/nginx -t\n(postgres) /usr/bin/pg_ctl reload"}
            />
          )}
        </label>
        {single && (
          <label>
            Runs as
            <input
              value={runAs}
              onChange={(e) => setRunAs(e.target.value)}
              placeholder="root"
            />
          </label>
        )}
      </div>

      {/*
        ⚠️ ONAY KUTUSU ÖNCEDEN İŞARETLİ DEĞİL. Sunucu kaçış riski taşıyan
        kuralı reddedip SEBEBİNİ söylüyor; kutu ancak o cümle ekrana
        geldikten sonra işaretleniyor, yani onaylayan neyi onayladığını
        okumuş oluyor.
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

      <div className="form-actions">
        <ActionButton variant="primary" onClick={save} disabled={commands.length === 0}>
          {single ? "Add command" : "Save rule"}
        </ActionButton>
        <span className="muted small">
          {commands.length === 0
            ? "Nothing to save yet."
            : `${commands.length} command${commands.length === 1 ? "" : "s"} for ${role}.`}
        </span>
      </div>
    </>
  );
}

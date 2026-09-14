import { useState } from "react";
import { api, RoleSudoRule, toMessage } from "../api";
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

  const commands = rule?.commands ?? [];
  const runAs = rule?.run_as?.trim() || "root";

  const savedNote =
    "Saved. A host gets this rule the next time postern works on it; the ones it has not touched yet still carry what they had.";

  /*
   * write, kuralın TAMAMINI yazıyor — uç PUT, yama değil. Komut eklemek
   * ve silmek de buradan geçiyor, böylece "listede gördüğün şey kuralın
   * kendisi" kuralı bozulmuyor.
   */
  const write = async (next: string[], nextRunAs: string, ack: boolean) => {
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
      run_as: nextRunAs.trim(),
      commands: next.map((l) => {
        const [path, ...args] = l.trim().split(/\s+/);
        return { path, args };
      }),
      acknowledged: ack,
    });
    setNote(savedNote);
    await onChanged();
  };

  const removeCommand = async (c: string) => {
    try {
      await write(
        commands.filter((x) => x !== c),
        runAs,
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

  const columns: Column<{ command: string }>[] = [
    {
      key: "command",
      header: "Command",
      className: "wrap",
      value: (c) => c.command,
      render: (c) => <code>{c.command}</code>,
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (c) => (
        <ActionButton
          variant="danger"
          onClick={() => removeCommand(c.command)}
          confirm={
            commands.length === 1
              ? `Remove "${c.command}"? It is the only command in the rule, so the rule itself goes and the role stops granting sudo.`
              : `Remove "${c.command}" from the sudo rule of "${role}"? Everyone in the role loses it.`
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
        <code>/etc/sudoers.d/postern-{role}</code>, run as <code>{runAs}</code>.
        Everyone in this role draws it from the group; what a temporary grant
        adds on top stays with that account and leaves with it.
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
          rows={commands.map((command) => ({ command }))}
          columns={columns}
          rowKey={(c) => c.command}
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
        description="One command, with the arguments it is allowed to take. The first word is the path."
      >
        {adding && (
          <RuleForm
            role={role}
            initial=""
            runAs={runAs}
            single
            onSave={async (text, nextRunAs, ack) => {
              await write([...commands, ...splitLines(text)], nextRunAs, ack);
              setAdding(false);
            }}
          />
        )}
      </Modal>

      <Modal
        open={editing}
        onClose={() => setEditing(false)}
        title={`Sudo commands of "${role}"`}
        description="The whole rule, one command per line. What is here replaces what the role carries."
      >
        {editing && (
          <RuleForm
            role={role}
            initial={commands.join("\n")}
            runAs={runAs}
            onSave={async (text, nextRunAs, ack) => {
              await write(splitLines(text), nextRunAs, ack);
              setEditing(false);
            }}
          />
        )}
      </Modal>
    </>
  );
}

function splitLines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
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
  runAs: initialRunAs,
  single = false,
  onSave,
}: {
  role: string;
  initial: string;
  runAs: string;
  single?: boolean;
  onSave: (text: string, runAs: string, acknowledged: boolean) => Promise<void>;
}) {
  const [text, setText] = useState(initial);
  const [runAs, setRunAs] = useState(initialRunAs);
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState("");

  const lines = splitLines(text);

  const save = async () => {
    setError("");
    try {
      await onSave(text, runAs, acknowledged);
    } catch (e: unknown) {
      setError(toMessage(e));
    }
  };

  return (
    <>
      <div className="form-grid">
        <label className="span-all">
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
              placeholder={"/usr/sbin/nginx -t\n/bin/systemctl reload nginx"}
            />
          )}
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
        <ActionButton variant="primary" onClick={save} disabled={lines.length === 0}>
          {single ? "Add command" : "Save rule"}
        </ActionButton>
        <span className="muted small">
          {lines.length === 0
            ? "Nothing to save yet."
            : `${lines.length} command${lines.length === 1 ? "" : "s"} for ${role}.`}
        </span>
      </div>
    </>
  );
}

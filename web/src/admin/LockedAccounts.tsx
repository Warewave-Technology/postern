import { useCallback } from "react";
import { LockedAccount, api } from "../api";
import { ActionButton, ListState, Timestamp, useList } from "./common";
import DataTable, { Column } from "./DataTable";

/**
 * LockedAccounts — hedeflerde kilitlenmiş, karar bekleyen hesaplar.
 *
 * ⚠️ BU EKRAN OLMADAN KİLİT YARIM KALIYOR. Kişi son grubunu kaybettiğinde
 * hesabı hedefte kilitleniyor ama SİLİNMİYOR: o yolda insan yok ve silme
 * geri alınamaz (spec K3). Kararı verecek kişi listeyi göremezse, kilitli
 * hesaplar veritabanında birikir ve kimse onlara dönmez — yani "erişimi
 * kapattık" cümlesi yarım kalır.
 *
 * ⚠️ HER SATIR HESABI KİMİN AÇTIĞINI SÖYLÜYOR. Silmenin anlamı buna göre
 * değişiyor: postern'in açtığı bir hesabı silmek onu geri almak, başka
 * bir aracın açtığını silmek o aracın sahibi olduğu bir şeyi yok etmek.
 * İkisini aynı düğmeye indiren bir ekran, ikincisini kazayla yaptırır.
 */
export default function LockedAccounts() {
  const list = useList<LockedAccount>(
    useCallback(() => api.lockedAccounts().then((r) => r.accounts), []),
  );

  const columns: Column<LockedAccount>[] = [
    {
      key: "os_user",
      header: "Account",
      value: (a) => `${a.os_user} ${a.username}`,
      render: (a) => (
        <>
          <code>{a.os_user}</code>
          <span className="muted small"> — {a.username}</span>
        </>
      ),
    },
    { key: "target", header: "Target", value: (a) => a.target },
    {
      key: "origin",
      header: "Opened by",
      value: (a) => a.origin,
      render: (a) =>
        a.origin === "created" ? (
          <span className="badge badge-info">postern</span>
        ) : (
          /*
            ⚠️ "something else" BİR UYARI. Bu hesap postern'den önce
            vardı; silmek, başka bir aracın sahibi olduğu bir şeyi yok
            etmek demek ve postern onu geri getiremez.
          */
          <span className="badge badge-warn">something else</span>
        ),
    },
    {
      key: "locked_at",
      header: "Locked",
      value: (a) => a.locked_at,
      render: (a) => <Timestamp value={a.locked_at} />,
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (a) => (
        <>
          <ActionButton
            onClick={() => api.keepLockedAccount(a.target, a.username).then(list.refresh)}
            label={`keep ${a.os_user} locked on ${a.target}`}
          >
            Keep locked
          </ActionButton>
          <ActionButton
            variant="danger"
            onClick={() => api.deleteLockedAccount(a.target, a.username).then(list.refresh)}
            confirm={
              a.origin === "created"
                ? `Delete ${a.os_user} from ${a.target}? The account and its home directory go, and this cannot be undone.`
                : `Delete ${a.os_user} from ${a.target}? This account was already there when postern first saw it — something else created it. The account and its home directory go, and postern cannot put them back.`
            }
            label={`delete ${a.os_user} from ${a.target}`}
          >
            Delete
          </ActionButton>
        </>
      ),
    },
  ];

  return (
    <section>
      <div className="page-head">
        <h2>Locked accounts</h2>
        <p>
          These accounts are locked on their targets: no group grants that target
          any more, so postern expired them. Nothing else has happened — the home
          directory and everything in it is still there, and the account comes
          back on its own if the person is put back in a group that reaches the
          target. What is waiting is the decision to delete.
        </p>
      </div>

      <ListState
        loading={list.loading}
        denied={list.denied}
        failed={list.failed}
        empty={list.items.length === 0}
        emptyText="No account is waiting for a decision. Accounts postern locks on a target appear here until somebody says whether they go for good."
      />

      {list.items.length > 0 && (
        <DataTable<LockedAccount>
          rows={list.items}
          columns={columns}
          rowKey={(a) => `${a.target}/${a.username}`}
          initialSort={{ key: "locked_at", dir: "asc" }}
          noun="locked account"
          searchLabel="search locked accounts by account, target or who opened them"
          searchPlaceholder="Search locked accounts…"
        />
      )}
    </section>
  );
}

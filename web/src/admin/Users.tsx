import { useState } from "react";
import { IssuedCredential, api, Role, User, toMessage } from "../api";
import {
  ActionButton,
  ErrorLine,
  ListState,
  OkLine,
  WarnLine,
  useList,
} from "./common";
import DataTable, { Column } from "./DataTable";
import Modal from "./Modal";
import UserDetail from "./UserDetail";

/**
 * Kullanıcı LİSTESİ.
 *
 * ⚠️ BU SAYFA ARTIK BİR LİSTE, BİR KONSOL DEĞİL.
 *
 * Dokuz sütuna çıkmıştı ve her satır üç ayrı eylem taşıyordu: rol atama
 * kutusu, aktifleştirme, anahtar paneli, sıfırlama, silme. Sonuç, hiçbir
 * soruyu iyi cevaplamayan bir ekrandı — "kimler var" diye bakan kişi
 * yatay kaydırıyor, "şu kişiyi düzenleyeyim" diyen kişi doğru satırı
 * bulup içindeki doğru kutuyu arıyordu. Üstelik satır başına çizilen
 * her kutu, yanlış satırda çalıştırılabilecek bir eylemdi.
 *
 * Liste artık tek bir soruyu cevaplıyor: kimler var, yönetici mi, durumu
 * ne, hangi rolleri var. Tek bir kişi üzerinde yapılacak her şey o
 * kişinin sayfasında (UserDetail). Aynı karar hedeflerde zaten
 * verilmişti; bu onun eşi.
 */
export default function Users({
  publicKeyLogin,
  localSource,
}: {
  publicKeyLogin: boolean;
  /** ⚠️ Yerel kapı kapalıyken giriş bilgisi diye bir şey yok: dizin ya
   *  da kimlik sağlayıcı açıkken üretilen bir değer hiçbir zaman
   *  kullanılamaz, yalnızca sızdırılabilecek fazladan bir sır olurdu. */
  localSource: boolean;
}) {
  const { items, error, denied, loading, refresh, setError } = useList<User>(
    api.users,
  );
  // Roller ayrıca çekiliyor — burada yalnızca "hiç rol yok" uyarısı
  // için. Atama detay sayfasında.
  const roles = useList<Role>(api.roles);

  const [selected, setSelected] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [osUser, setOsUser] = useState("");
  const [email, setEmail] = useState("");
  // Ekleme formu MODALDA: sayfanın işi listeyi göstermek.
  const [adding, setAdding] = useState(false);
  const [notice, setNotice] = useState("");

  /*
   * Verilen değer BİR KEZ gösteriliyor ve hiçbir yerde saklanmıyor.
   *
   * ⚠️ Modal DEĞİL: mevcut Modal, Esc ve arka plana tıklamayla
   * kapanıyor (Modal.tsx) ve o davranış burada, kaydedilmemiş bir
   * kimlik bilgisini kazara yok etmek demek. Değer sayfanın kendisinde,
   * kullanıcı KAPAT diyene kadar duruyor.
   */
  const [issued, setIssued] = useState<IssuedCredential | null>(null);

  const fail = (e: unknown) => {
    setNotice("");
    setError(toMessage(e));
  };

  // ⚠️ BAŞARIYI DÖNDÜRÜYOR. Hata durumunda modal AÇIK kalmalı: kapanan
  // bir modal, arkadaki hata satırını görmeyen kullanıcıya işlemin
  // tuttuğunu düşündürür ve aynı adı bir daha yazdırır.
  const create = () =>
    api
      .createUser({
        name: name.trim(),
        os_user: osUser.trim(),
        email: email.trim() || undefined,
      })
      .then((res) => {
        const created = name.trim();
        setName("");
        setOsUser("");
        setEmail("");
        /*
         * ⚠️ SIR VARSA BİLDİRİM YERİNE KUTU.
         *
         * Değer bir daha gösterilemiyor, dolayısıyla kaybolan bir
         * bildirim satırında duramaz. Kutu sayfanın akışında ve
         * yönetici kapatana kadar orada.
         */
        if (res?.secret) {
          setIssued({ username: res.username ?? created, secret: res.secret });
          setNotice("");
        } else {
          setNotice(
            res?.credential_error
              ? `${created} created, but ${res.credential_error}`
              : `${created} created — open it to give it a role and a key, or it reaches nothing.`,
          );
        }
        return refresh().then(() => true);
      })
      .catch((e: unknown) => {
        fail(e);
        return false;
      });

  const remove = (user: string) =>
    api
      .deleteUser(user)
      .then(() => {
        setNotice("");
        return refresh();
      })
      .catch(fail);

  const columns: Column<User>[] = [
    {
      key: "name",
      header: "Name",
      value: (u) => u.name,
      // Ad bir BAĞLANTI: hedeflerdeki kararın aynısı. Satırın tamamını
      // tıklanabilir yapmak, satırdaki sil düğmesiyle çakışırdı.
      render: (u) => (
        <button className="link-cell" onClick={() => setSelected(u.name)}>
          {u.name}
        </button>
      ),
    },
    { key: "os_user", header: "OS user", value: (u) => u.os_user },
    {
      /*
       * ⚠️ HÜCRE "admin" DEĞİL, "yes" YAZIYOR.
       *
       * Başlığı "Admin" olan bir sütunda rozetin "admin" demesi, soruyu
       * soruyla cevaplamaktı — ve okuyanda "burası bir etiket mi, bir
       * cevap mı" tereddüdü bırakıyordu. Sütunun sorduğu şey bir
       * evet/hayır; hücre onu cevaplamalı.
       *
       * true/false DEĞİL: bu paneldeki her hücre düz İngilizce konuşuyor
       * ("active", "never", "no roles"). Tek bir yerde makine dilinden
       * bir değişmez göstermek, o hücreyi ürünün geri kalanından
       * koparırdı.
       *
       * Rozet YALNIZCA "yes"te — yan sütundaki kuralın aynısı: olağan
       * değer sessiz, dikkat isteyen değer rozetli. Sıralama da
       * yöneticileri BİR ARADA topluyor, "kimler yönetici" tek tıkla
       * cevaplansın diye.
       *
       * Yöneticiliğin NEREDEN geldiği (host mu, dizin grubu mu) burada
       * yok: o, panelin neyi kaldırabildiğini belirleyen ayrı bir soru
       * ve kişinin kendi sayfasında yazıyor.
       */
      key: "admin",
      header: "Admin",
      value: (u) => (u.admin ? "1" : "0"),
      render: (u) =>
        u.admin ? (
          <span className="badge badge-accent">yes</span>
        ) : (
          <span className="muted">no</span>
        ),
    },
    {
      /*
       * ⚠️ DURUM GÖRÜNÜR OLMAK ZORUNDA.
       *
       * Kaynağın bir süredir doğrulamadığı hesaplar kendiliğinden
       * pasifleşiyor. Bunu göstermeyen bir liste "neden giremiyorum"
       * sorusunu cevaplayamaz ve yönetici postern'de bir arıza arar —
       * oysa cevap "kaynak bu kişiyi doğrulamıyor".
       */
      key: "state",
      header: "State",
      value: (u) => u.state ?? "active",
      render: (u) => {
        const st = u.state ?? "active";
        const seen = u.last_confirmed
          ? new Date(u.last_confirmed).toLocaleDateString()
          : "never";
        if (st === "active") {
          return <span className="muted">active</span>;
        }
        return (
          <span
            className="badge badge-warn"
            title={`the source last confirmed this account on ${seen}`}
          >
            {st}
          </span>
        );
      },
    },
    {
      /*
       * ⚠️ ROLLER OKUNUR, DÜZENLENİR DEĞİL.
       *
       * Satır içindeki "revoke" düğmeleri, listeyi tarayan kişinin
       * yanlış satırda tıklayabileceği bir eylemdi — ve bir rolü geri
       * almak, o kişinin eriştiği her hedefi anında kapatıyor. Böyle
       * bir karar, kimin üzerinde çalıştığını gördüğün sayfada
       * verilmeli.
       */
      key: "roles",
      header: "Roles",
      className: "wrap",
      value: (u) => u.roles.join(" "),
      render: (u) =>
        u.roles.length === 0 ? (
          <span className="muted">no roles</span>
        ) : (
          <span className="chips">
            {u.roles.map((r) => (
              <span key={r} className="chip">
                <code>{r}</code>
              </span>
            ))}
          </span>
        ),
    },
    {
      key: "actions",
      header: "Actions",
      srHeader: true,
      className: "actions",
      render: (u) => (
        <ActionButton
          variant="danger"
          onClick={() => remove(u.name)}
          confirm={`Delete the user "${u.name}"? Their SSH keys and role assignments go with them. If ${u.name} has recorded sessions the server refuses this outright — revoking their keys and roles is how access is cut without losing the audit trail.`}
          label={`delete user ${u.name}`}
        >
          Delete
        </ActionButton>
      ),
    },
  ];

  if (selected) {
    return (
      <UserDetail
        name={selected}
        publicKeyLogin={publicKeyLogin}
        localSource={localSource}
        onBack={() => {
          setSelected(null);
          // Detay sayfasında rol, anahtar ya da durum değişmiş olabilir:
          // listeye eski hâliyle dönmek yanlış bilgi verirdi.
          refresh();
        }}
      />
    );
  }

  return (
    <section>
      {issued && (
        <div className="issued-card">
          <h3>
            Sign-in value for <b>{issued.username}</b>
          </h3>
          <p>The account is created and can sign in to the panel with this.</p>
          <pre className="issued-secret">{issued.secret}</pre>
          <p className="msg warn">
            This is the only time it is shown. postern stores a verifier, not
            the value — it cannot be looked up or printed again. Give it to{" "}
            {issued.username} over a channel you trust; they must choose their
            own password before the panel opens for them.
          </p>
          <button className="btn btn-primary" onClick={() => setIssued(null)}>
            I have copied it
          </button>
        </div>
      )}

      <div className="page-bar">
        <div className="page-head">
          <h2>Users</h2>
          <p className="page-sub">
            Accounts postern knows. Open one to give it a role, manage its keys
            or reset how it signs in. The admin flag is read-only everywhere in
            the panel: it comes from the bastion&apos;s own CLI, or from the
            directory group set on the Sign-in screen.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setAdding(true)}>
          New user
        </button>
      </div>
      <ErrorLine msg={error} />
      <OkLine msg={notice} />

      {/* Rol listesi düşerse detay sayfasındaki atama kutusu boş kalır;
          sebebini söylemezsek operatör hiç rol tanımlı olmadığını sanar. */}
      <WarnLine
        msg={
          roles.error &&
          `Roles could not be loaded (${roles.error}) — nothing can be assigned until that list comes back.`
        }
      />
      {!roles.loading && !roles.error && roles.items.length === 0 && (
        <WarnLine msg="No roles exist yet — create one on the Roles tab, otherwise every user here reaches nothing." />
      )}

      <ListState
        loading={loading}
        denied={denied}
        empty={items.length === 0}
        emptyText="No users yet. A user created here still needs a role and an SSH key before anyone can connect as them."
      />

      {items.length > 0 && (
        <DataTable
          rows={items}
          columns={columns}
          rowKey={(u) => u.name}
          initialSort={{ key: "name", dir: "asc" }}
          noun="user"
          searchLabel="search users by name, OS user or role"
          searchPlaceholder="Search users, or a role like sysadmin…"
        />
      )}

      {!publicKeyLogin && (
        <p className="note">
          Key-based sign-in is switched off on this bastion (
          <code>auth.public_key_login</code>), so keys are not managed here.
          Everyone signs in through the identity provider — which is also what
          makes an account disabled there actually lose access.
        </p>
      )}

      <Modal
        open={adding}
        onClose={() => setAdding(false)}
        title="New user"
        description="The OS user is the account postern opens on the target host; it is not the name people sign in with."
      >
        <div className="field-row">
          <label>
            Name
            {/* trim: baştaki/sondaki boşluk gözle görünmüyor ama SSH
                tarafında ad birebir eşleşiyor — "ops " kullanıcısına
                hiç kimse bağlanamazdı. */}
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label>
            OS user
            <input value={osUser} onChange={(e) => setOsUser(e.target.value)} />
          </label>
          <label>
            Email (optional)
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </label>
          <ActionButton
            variant="primary"
            onClick={() => create().then((ok) => ok && setAdding(false))}
            disabled={!name.trim() || !osUser.trim()}
          >
            Create user
          </ActionButton>
        </div>
      </Modal>
    </section>
  );
}

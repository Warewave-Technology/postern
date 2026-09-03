package store

import (
	"context"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

/*
 * OpenSessions, bitişi kaydedilmemiş bütün oturumları döner.
 *
 * ⚠️ AYRI BİR SORGU, Sessions(...200) ÜZERİNDE SÜZGEÇ DEĞİL.
 *
 * ÖLÇÜLEN ARIZA: panel "Active sessions" kartını en yeni 200 satırı
 * çekip istemcide `!ended_at` diye süzerek kuruyordu (Overview.tsx:158,
 * admin.go:739). Sabahtan beri açık duran bir oturumun üstüne 200 yeni
 * oturum bindiğinde, o oturum karttan tamamen düşüyor: yönetici onu
 * göremiyor, dolayısıyla kesemiyor da. Açık oturumları saymak için
 * geçmişin ilk 200 satırına bakmak, yanlış soruyu sormaktı.
 *
 * ⚠️ SINIRSIZ DEĞİL. Açık oturum sayısı bağlantı sınırlarıyla zaten
 * bağlı (listen.max_conns), ama uzlaştırılmamış hayalet satırlar
 * birikebiliyor (bkz. CloseOrphanSessions). Tavan, panelin bir kazayla
 * bütün tabloyu çekmesini engelliyor.
 */
func (s *Store) OpenSessions(ctx context.Context) ([]model.Session, error) {
	const openSessionCap = 1000

	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	queryStr := `
		SELECT s.id,
		       u.username,
		       t.name,
		       s.os_user,
		       s.src_ip,
		       s.started_at,
		       s.recording_path
		FROM sessions s
		JOIN users   u ON u.id = s.user_id
		JOIN targets t ON t.id = s.target_id
		WHERE s.ended_at IS NULL
		ORDER BY s.started_at DESC, s.id DESC` + limitClause(openSessionCap, "$1") + `;
	`

	rows, err := s.db.QueryContext(ctx, queryStr, limitArgs(openSessionCap)...)
	if err != nil {
		return nil, translateErr("store.OpenSessions", err)
	}
	defer rows.Close()

	var out []model.Session
	for rows.Next() {
		var sess model.Session
		var startedAt int64
		if err := rows.Scan(&sess.ID, &sess.User, &sess.Target, &sess.OSUser,
			&sess.SrcIP, &startedAt, &sess.RecordingPath); err != nil {
			return nil, translateErr("store.OpenSessions", err)
		}
		sess.StartedAt = time.Unix(startedAt, 0)
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.OpenSessions", err)
	}
	return out, nil
}

/*
 * CloseOrphanSessions, açılışta sahipsiz kalmış oturum satırlarını kapatır.
 *
 * ⚠️ ÖLÇÜLEN ARIZA: postern SIGKILL alırsa (çökme, güç kesintisi,
 * `kill -9`) açık oturumların ended_at'i SONSUZA DEK NULL kalıyor.
 * Ölçüldü: bir oturum açıkken süreç öldürülüp yeniden başlatıldıktan
 * sonra satır hâlâ açıktı. Panel onu süresiz "çalışıyor" gösteriyor.
 * Kesme düğmesi bunu pasif bir görüntü hatasından aktif bir yalana
 * çeviriyordu: yönetici var olmayan bir oturumu kesmeye çalışırdı.
 *
 * ⚠️ YENİ BAŞLAYAN SÜREÇ HİÇBİR OTURUMA SAHİP DEĞİLDİR — kuralın
 * dayandığı tek önerme bu ve TEK DÜĞÜM varsayımıyla geçerli. İkinci bir
 * postern aynı veritabanına bağlıysa bu çağrı ONUN canlı oturumlarını
 * kapatır. 1.0 tek düğüm olduğu için kabul ediliyor; belgelerde
 * "bilinen sınırlar" altında yazılı.
 *
 * ⚠️ SATIR SİLİNMİYOR, KAPATILIYOR. Denetim izi kalmalı: "ne zaman
 * bittiğini bilmiyoruz" ile "hiç olmadı" ayrı şeyler. ended_at
 * açılış anı — gerçek bitişten sonra, yani süre OLDUĞUNDAN UZUN
 * görünebilir; bu yüzden çağıran kaç satır kapandığını LOG'A yazmalı.
 */
func (s *Store) CloseOrphanSessions(ctx context.Context, at time.Time) (closed, queued int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, translateErr("store.CloseOrphanSessions", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit sonrası no-op

	/*
	 * ⚠️ ÖNCE ARŞİV KUYRUĞUNA YAZ, SONRA KAPAT — ve eskiden HİÇ
	 * yazmıyordu.
	 *
	 * ÖLÇÜLEN ARIZA: temiz olmayan bir çıkışta (SIGKILL, OOM, güç
	 * kesintisi) Session.Close hiç çalışmıyor, yani QueueArchive de
	 * çağrılmıyor — o kuyruğa yazan TEK üretim yolu orası. Satır burada
	 * kapatılıyordu ama kuyruğa hiç girmiyordu: kayıt bir daha asla
	 * yüklenmiyor, ArchiveBacklog onu saymıyor (panel "bekleyen yok"
	 * diyor) ve budayıcı arşivlenmemiş diye dokunmuyor. Yani süreci
	 * öldüren olayın kayıtları, tam da ölen makinenin diskinde kalıyor
	 * ve operatör "hepsi güvende" sanıyor.
	 *
	 * Yüklem, göç 029'un tohumlamada kullandığının aynısı: kaydı olan
	 * ama kuyrukta satırı olmayan oturumlar. ON CONFLICT ile idempotent.
	 * INSERT, UPDATE'ten ÖNCE çünkü yüklem hâlâ ended_at IS NULL'a
	 * bakıyor.
	 */
	qres, err := tx.ExecContext(ctx, `
		INSERT INTO session_archives (session_id)
		SELECT id FROM sessions
		WHERE ended_at IS NULL AND recording_path <> ''
		ON CONFLICT DO NOTHING;`)
	if err != nil {
		return 0, 0, translateErr("store.CloseOrphanSessions", err)
	}
	queued, _ = qres.RowsAffected()

	cres, err := tx.ExecContext(ctx,
		`UPDATE sessions SET ended_at=$1 WHERE ended_at IS NULL;`, at.Unix())
	if err != nil {
		return 0, 0, translateErr("store.CloseOrphanSessions", err)
	}
	closed, err = cres.RowsAffected()
	if err != nil {
		return 0, 0, translateErr("store.CloseOrphanSessions", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, translateErr("store.CloseOrphanSessions", err)
	}
	return closed, queued, nil
}

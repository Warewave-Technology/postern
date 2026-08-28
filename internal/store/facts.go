package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/warewave/postern/internal/model"
)

// RecordTargetSeen, başarılı bir bağlantıdan sonra öğrenilenleri yazar.
//
// ⚠️ ÇAĞIRAN BU HATAYI OTURUMA YANSITMAMALI. Burası bir gözlem kaydı;
// yazılamaması can sıkıcıdır ama kullanıcının oturumunu düşürmek için
// sebep değil. Denetim kaydı (sessions, admin_log) başka bir şey ve
// onun yazılamaması oturumu düşürür — ayrım kasıtlı.
func (s *Store) RecordTargetSeen(ctx context.Context, targetName string, f model.TargetFacts) error {
	id, err := s.rowID(ctx, "store.RecordTargetSeen", "targets", "name", targetName)
	if err != nil {
		return err
	}

	// Başarı, önceki HATAYI SİLMİYOR: "en son ne zaman çalıştı" ile
	// "en son neden çalışmadı" ayrı sorular.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO target_facts (target_id, server_version, host_key_type, last_seen_at, connect_ms)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (target_id) DO UPDATE SET
			server_version = EXCLUDED.server_version,
			host_key_type  = EXCLUDED.host_key_type,
			last_seen_at   = EXCLUDED.last_seen_at,
			connect_ms     = EXCLUDED.connect_ms;`,
		id, f.ServerVersion, f.HostKeyType, time.Now().Unix(), f.ConnectMS)
	if err != nil {
		return translateErr("store.RecordTargetSeen", err)
	}
	return nil
}

// RecordTargetError, başarısız bir bağlantı denemesini işaretler.
func (s *Store) RecordTargetError(ctx context.Context, targetName, reason string) error {
	id, err := s.rowID(ctx, "store.RecordTargetError", "targets", "name", targetName)
	if err != nil {
		return err
	}

	// ⚠️ SEBEP KIRPILIYOR. Bir hedef hata dizesinin uzunluğunu
	// belirleyebilir (düşmanca bir sunucu afişi hataya girebilir) ve
	// sınırsız metin hem tabloyu hem paneli şişirir.
	if len(reason) > 300 {
		reason = reason[:300] + "…"
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO target_facts (target_id, last_error_at, last_error)
		VALUES ($1, $2, $3)
		ON CONFLICT (target_id) DO UPDATE SET
			last_error_at = EXCLUDED.last_error_at,
			last_error    = EXCLUDED.last_error;`,
		id, time.Now().Unix(), reason)
	if err != nil {
		return translateErr("store.RecordTargetError", err)
	}
	return nil
}

// TargetFacts, tek bir hedefin gözlemleri. Hiç bağlanılmamışsa sıfır
// değer döner — ErrNotFound DEĞİL: "henüz bağlanılmadı" bir hata değil,
// hedefin geçerli bir hâli.
func (s *Store) TargetFacts(ctx context.Context, targetName string) (model.TargetFacts, error) {
	id, err := s.rowID(ctx, "store.TargetFacts", "targets", "name", targetName)
	if err != nil {
		return model.TargetFacts{}, err
	}

	var (
		f         model.TargetFacts
		seenAt    sql.NullInt64
		connectMS sql.NullInt64
		lastErrAt sql.NullInt64
	)
	var probedAt sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
		SELECT server_version, host_key_type, last_seen_at, connect_ms,
		       last_error_at, last_error, kernel, os_name, probed_at
		FROM target_facts WHERE target_id = $1;`, id).
		Scan(&f.ServerVersion, &f.HostKeyType, &seenAt, &connectMS,
			&lastErrAt, &f.LastError, &f.Probe.Kernel, &f.Probe.OSName, &probedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.TargetFacts{}, nil
	}
	if err != nil {
		return model.TargetFacts{}, translateErr("store.TargetFacts", err)
	}

	if seenAt.Valid {
		f.LastSeenAt = time.Unix(seenAt.Int64, 0).UTC()
	}
	if connectMS.Valid {
		f.ConnectMS = int(connectMS.Int64)
	}
	if lastErrAt.Valid {
		f.LastErrorAt = time.Unix(lastErrAt.Int64, 0).UTC()
	}
	if probedAt.Valid {
		f.ProbedAt = time.Unix(probedAt.Int64, 0).UTC()
	}
	return f, nil
}

/*
 * RecordTargetProbe, hedefte KOMUT ÇALIŞTIRILARAK öğrenilenleri yazar.
 *
 * ⚠️ Yalnızca target_probe.enabled ile çağrılır. probed_at ayrı bir
 * damga: last_seen_at "bağlandık" demek, probed_at "makineye dokunduk"
 * demek ve ikisi aynı şey değil.
 */
func (s *Store) RecordTargetProbe(ctx context.Context, targetName string, p model.TargetProbe) error {
	id, err := s.rowID(ctx, "store.RecordTargetProbe", "targets", "name", targetName)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO target_facts (target_id, kernel, os_name, probed_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (target_id) DO UPDATE SET
			kernel    = EXCLUDED.kernel,
			os_name   = EXCLUDED.os_name,
			probed_at = EXCLUDED.probed_at;`,
		id, p.Kernel, p.OSName, time.Now().Unix())
	if err != nil {
		return translateErr("store.RecordTargetProbe", err)
	}
	return nil
}

// AllTargetFacts, hedef adı → gözlemler.
//
// TEK SORGU: hedef başına ayrı sorgu, ana ekranı çizerken kullanıcının
// erişebildiği her hedef için bir gidiş dönüş demekti (N+1). Etiketlerde
// aynı gerekçeyle allTargetLabels var.
func (s *Store) AllTargetFacts(ctx context.Context) (map[string]model.TargetFacts, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.name, f.server_version, f.host_key_type,
		       f.last_seen_at, f.connect_ms, f.last_error_at, f.last_error,
		       f.kernel, f.os_name, f.probed_at
		FROM target_facts f
		JOIN targets t ON t.id = f.target_id;`)
	if err != nil {
		return nil, translateErr("store.AllTargetFacts", err)
	}
	defer rows.Close()

	out := map[string]model.TargetFacts{}
	for rows.Next() {
		var (
			name      string
			f         model.TargetFacts
			seenAt    sql.NullInt64
			connectMS sql.NullInt64
			lastErrAt sql.NullInt64
			probedAt  sql.NullInt64
		)
		if err := rows.Scan(&name, &f.ServerVersion, &f.HostKeyType,
			&seenAt, &connectMS, &lastErrAt, &f.LastError,
			&f.Probe.Kernel, &f.Probe.OSName, &probedAt); err != nil {
			return nil, translateErr("store.AllTargetFacts", err)
		}
		if seenAt.Valid {
			f.LastSeenAt = time.Unix(seenAt.Int64, 0).UTC()
		}
		if connectMS.Valid {
			f.ConnectMS = int(connectMS.Int64)
		}
		if lastErrAt.Valid {
			f.LastErrorAt = time.Unix(lastErrAt.Int64, 0).UTC()
		}
		if probedAt.Valid {
			f.ProbedAt = time.Unix(probedAt.Int64, 0).UTC()
		}
		out[name] = f
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.AllTargetFacts", err)
	}
	return out, nil
}

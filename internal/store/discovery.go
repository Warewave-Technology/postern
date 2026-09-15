package store

/*
 * Keşif kaynakları, koşuları ve bulunan makineler (göç 045).
 *
 * ⚠️ SIR BU PAKETTEN ÇIKMIYOR, YALNIZCA KEŞİF KOŞUSUNA. DiscoverySource
 * yapısında sırrın kendisi hiç yok, yalnızca "kayıtlı mı" biti var; sır
 * DiscoverySourceSecret ile ayrı ve bilinçli bir çağrıyla açılıyor. Yapı
 * API'ye olduğu gibi gidebiliyor, çünkü sızdıracağı bir alan taşımıyor.
 */

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Keşif koşusunun sonuçları.
const (
	DiscoveryRunning = "running"
	DiscoveryOK      = "ok"
	DiscoveryFailed  = "failed"
)

// DiscoverySource, panelden kaydedilen bir keşif kaynağı.
type DiscoverySource struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Username string `json:"username"`
	// SecretSet: kaynağın sırrı kayıtlı mı. Sırrın kendisi burada YOK.
	SecretSet       bool      `json:"secret_set"`
	CAPEM           string    `json:"ca_pem"`
	Insecure        bool      `json:"insecure"`
	Node            string    `json:"node"`
	TagKey          string    `json:"tag_key"`
	NamePattern     string    `json:"name_pattern"`
	Port            int       `json:"port"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	LastRunAt       time.Time `json:"last_run_at,omitzero"`
}

// DiscoveryRun, bir kaynağın tek koşusu.
type DiscoveryRun struct {
	ID          int64     `json:"id"`
	SourceID    string    `json:"source_id"`
	Trigger     string    `json:"trigger"`
	Actor       string    `json:"actor"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at,omitzero"`
	Outcome     string    `json:"outcome"`
	Reason      string    `json:"reason,omitempty"`
	Seen        int       `json:"seen"`
	NewMachines int       `json:"new_machines"`
	Missing     int       `json:"missing"`
	KeyChanged  int       `json:"key_changed"`
	Unreachable int       `json:"unreachable"`
}

// DiscoveredMachine, bir kaynağın bildirdiği makinenin son hâli.
type DiscoveredMachine struct {
	SourceID string
	// Source, kaynağın adı (okurken birleştiriliyor).
	Source   string
	Ref      string
	Name     string
	Host     string
	Tags     []string
	Running  bool
	Role     string
	Tagged   bool
	HostKey  string
	Problem  string
	TargetID string
	// Target ve TargetHostKey, bağlı hedefin adı ve SABİTLENMİŞ anahtarı
	// (okurken birleştiriliyor; yazılmıyor).
	Target        string
	TargetHostKey string
	Ignored       bool
	FirstSeen     time.Time
	LastSeen      time.Time
	MissingSince  time.Time
}

// TargetKey, keşfin bir makineyi kayıtlı hedefle eşleştirmek için
// baktığı üç alan.
type TargetKey struct {
	ID, Name, HostKey string
}

// SecretsAvailable, sır mühürleyen anahtar yüklü mü. Yoksa kaynak
// kaydedilemez; panel bunu formu açmadan söylüyor.
func (s *Store) SecretsAvailable() bool { return s.box != nil }

const discoverySourceCols = `id, name, kind, url, username, secret <> '', ca_pem, insecure,
	node, tag_key, name_pattern, port, interval_seconds, enabled, created_by,
	created_at, updated_at, last_run_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanDiscoverySource(sc rowScanner) (DiscoverySource, error) {
	var d DiscoverySource
	var created, updated int64
	var last sql.NullInt64
	err := sc.Scan(&d.ID, &d.Name, &d.Kind, &d.URL, &d.Username, &d.SecretSet, &d.CAPEM,
		&d.Insecure, &d.Node, &d.TagKey, &d.NamePattern, &d.Port, &d.IntervalSeconds,
		&d.Enabled, &d.CreatedBy, &created, &updated, &last)
	if err != nil {
		return d, err
	}
	d.CreatedAt = time.Unix(created, 0).UTC()
	d.UpdatedAt = time.Unix(updated, 0).UTC()
	if last.Valid {
		d.LastRunAt = time.Unix(last.Int64, 0).UTC()
	}
	return d, nil
}

// sealSourceSecret, kaynağın sırrını mühürler; anahtar yoksa REDDEDER —
// düz metin yazıp "sakladım" demek SetSetting'in reddettiği şeyin aynısı.
func (s *Store) sealSourceSecret(op, secret string) (string, error) {
	if s.box == nil {
		return "", fmt.Errorf("%s: %w: the bastion has no secret key (secret_key_file), "+
			"so a source's credentials cannot be stored", op, ErrInvalid)
	}
	sealed, err := s.box.Seal(secret)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return sealed, nil
}

// CreateDiscoverySource, kaynağı sırrı mühürlenmiş olarak yazar.
func (s *Store) CreateDiscoverySource(ctx context.Context, d DiscoverySource, secret string) (string, error) {
	const op = "store.CreateDiscoverySource"
	id, err := newID()
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	sealed, err := s.sealSourceSecret(op, secret)
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO discovery_sources (id, name, kind, url, username, secret, ca_pem, insecure,
			node, tag_key, name_pattern, port, interval_seconds, enabled, created_by,
			created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16);`,
		id, d.Name, d.Kind, d.URL, d.Username, sealed, d.CAPEM, d.Insecure, d.Node, d.TagKey,
		d.NamePattern, d.Port, d.IntervalSeconds, d.Enabled, d.CreatedBy, now)
	if err != nil {
		return "", translateErr(op, err)
	}
	return id, nil
}

/*
 * UpdateDiscoverySource, kaynağı günceller. secret boşsa kayıtlı sır
 * KALIR: panel sırrı hiç görmediği için "değiştirmedim" ile "sildim"i
 * ayırmanın tek yolu bu. Tür değişmiyor — makine kimlikleri türe özgü.
 */
func (s *Store) UpdateDiscoverySource(ctx context.Context, d DiscoverySource, secret string) error {
	const op = "store.UpdateDiscoverySource"
	sealed := ""
	if secret != "" {
		var err error
		if sealed, err = s.sealSourceSecret(op, secret); err != nil {
			return err
		}
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE discovery_sources SET
			name = $2, url = $3, username = $4, ca_pem = $5, insecure = $6, node = $7,
			tag_key = $8, name_pattern = $9, port = $10, interval_seconds = $11,
			enabled = $12, updated_at = $13,
			secret = CASE WHEN $14 = '' THEN secret ELSE $14 END
		WHERE id = $1;`,
		d.ID, d.Name, d.URL, d.Username, d.CAPEM, d.Insecure, d.Node, d.TagKey, d.NamePattern,
		d.Port, d.IntervalSeconds, d.Enabled, time.Now().Unix(), sealed)
	if err != nil {
		return translateErr(op, err)
	}
	return oneRow(op, res)
}

// DeleteDiscoverySource, kaynağı siler ve adını döner. Koşuları ve
// makine satırları onunla gidiyor; hedefler KALIYOR.
func (s *Store) DeleteDiscoverySource(ctx context.Context, id string) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM discovery_sources WHERE id = $1 RETURNING name;`, id).Scan(&name)
	if err != nil {
		return "", translateErr("store.DeleteDiscoverySource", err)
	}
	return name, nil
}

// DiscoverySources, kaynaklar ada göre sıralı.
func (s *Store) DiscoverySources(ctx context.Context) ([]DiscoverySource, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+discoverySourceCols+` FROM discovery_sources ORDER BY lower(name), id;`)
	if err != nil {
		return nil, translateErr("store.DiscoverySources", err)
	}
	defer rows.Close()
	out := []DiscoverySource{}
	for rows.Next() {
		d, err := scanDiscoverySource(rows)
		if err != nil {
			return nil, translateErr("store.DiscoverySources", err)
		}
		out = append(out, d)
	}
	return out, translateErr("store.DiscoverySources", rows.Err())
}

// DiscoverySource, tek kaynak.
func (s *Store) DiscoverySource(ctx context.Context, id string) (DiscoverySource, error) {
	d, err := scanDiscoverySource(s.db.QueryRowContext(ctx,
		`SELECT `+discoverySourceCols+` FROM discovery_sources WHERE id = $1;`, id))
	if err != nil {
		return d, translateErr("store.DiscoverySource", err)
	}
	return d, nil
}

// DiscoverySourceSecret, kaynağın sırrını AÇIK olarak döner — yalnızca
// koşunun hipervizöre bağlanması için.
func (s *Store) DiscoverySourceSecret(ctx context.Context, id string) (string, error) {
	const op = "store.DiscoverySourceSecret"
	var sealed string
	if err := s.db.QueryRowContext(ctx,
		`SELECT secret FROM discovery_sources WHERE id = $1;`, id).Scan(&sealed); err != nil {
		return "", translateErr(op, err)
	}
	if s.box == nil {
		return "", fmt.Errorf("%s: secret key not configured", op)
	}
	plain, err := s.box.Unseal(sealed)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return plain, nil
}

// TouchDiscoverySource, elle başlatılan koşunun zamanını yazar ki
// zamanlayıcı hemen ardından aynı kaynağı bir daha koşturmasın.
func (s *Store) TouchDiscoverySource(ctx context.Context, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE discovery_sources SET last_run_at = $2 WHERE id = $1;`, id, now.Unix())
	if err != nil {
		return translateErr("store.TouchDiscoverySource", err)
	}
	return oneRow("store.TouchDiscoverySource", res)
}

/*
 * ClaimDiscoverySource, zamanı gelmiş kaynağın koşusunu SAHİPLENİR:
 * last_run_at ancak hâlâ dueBefore'dan eskiyse ilerliyor. İki bastion
 * aynı veritabanını paylaşıyorsa aynı dakikada ikisi birden koşturmasın.
 */
func (s *Store) ClaimDiscoverySource(ctx context.Context, id string, now, dueBefore time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE discovery_sources SET last_run_at = $2
		WHERE id = $1 AND enabled AND interval_seconds > 0
		  AND (last_run_at IS NULL OR last_run_at <= $3);`,
		id, now.Unix(), dueBefore.Unix())
	if err != nil {
		return false, translateErr("store.ClaimDiscoverySource", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// StartDiscoveryRun, koşu satırını açar.
func (s *Store) StartDiscoveryRun(ctx context.Context, r DiscoveryRun) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO discovery_runs (source_id, trigger, actor, started_at, outcome)
		VALUES ($1, $2, $3, $4, 'running') RETURNING id;`,
		r.SourceID, r.Trigger, r.Actor, r.StartedAt.Unix()).Scan(&id)
	if err != nil {
		return 0, translateErr("store.StartDiscoveryRun", err)
	}
	return id, nil
}

// FinishDiscoveryRun, koşu satırını sonucuyla kapatır.
func (s *Store) FinishDiscoveryRun(ctx context.Context, r DiscoveryRun) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE discovery_runs SET finished_at = $2, outcome = $3, reason = $4, seen = $5,
			new_machines = $6, missing = $7, key_changed = $8, unreachable = $9
		WHERE id = $1;`,
		r.ID, r.FinishedAt.Unix(), r.Outcome, r.Reason, r.Seen, r.NewMachines, r.Missing,
		r.KeyChanged, r.Unreachable)
	if err != nil {
		return translateErr("store.FinishDiscoveryRun", err)
	}
	return oneRow("store.FinishDiscoveryRun", res)
}

const discoveryRunCols = `id, source_id, trigger, actor, started_at, finished_at, outcome,
	reason, seen, new_machines, missing, key_changed, unreachable`

func scanDiscoveryRun(sc rowScanner) (DiscoveryRun, error) {
	var r DiscoveryRun
	var started int64
	var finished sql.NullInt64
	err := sc.Scan(&r.ID, &r.SourceID, &r.Trigger, &r.Actor, &started, &finished, &r.Outcome,
		&r.Reason, &r.Seen, &r.NewMachines, &r.Missing, &r.KeyChanged, &r.Unreachable)
	r.StartedAt = time.Unix(started, 0).UTC()
	if finished.Valid {
		r.FinishedAt = time.Unix(finished.Int64, 0).UTC()
	}
	return r, err
}

// DiscoveryRuns, kaynağın koşuları, en yeni önce.
func (s *Store) DiscoveryRuns(ctx context.Context, sourceID string, limit int) ([]DiscoveryRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+discoveryRunCols+`
		FROM discovery_runs WHERE source_id = $1 ORDER BY id DESC LIMIT $2;`, sourceID, limit)
	if err != nil {
		return nil, translateErr("store.DiscoveryRuns", err)
	}
	defer rows.Close()
	out := []DiscoveryRun{}
	for rows.Next() {
		r, err := scanDiscoveryRun(rows)
		if err != nil {
			return nil, translateErr("store.DiscoveryRuns", err)
		}
		out = append(out, r)
	}
	return out, translateErr("store.DiscoveryRuns", rows.Err())
}

// LatestDiscoveryRuns, her kaynağın son koşusu.
func (s *Store) LatestDiscoveryRuns(ctx context.Context) (map[string]DiscoveryRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ON (source_id) `+discoveryRunCols+`
		FROM discovery_runs ORDER BY source_id, id DESC;`)
	if err != nil {
		return nil, translateErr("store.LatestDiscoveryRuns", err)
	}
	defer rows.Close()
	out := map[string]DiscoveryRun{}
	for rows.Next() {
		r, err := scanDiscoveryRun(rows)
		if err != nil {
			return nil, translateErr("store.LatestDiscoveryRuns", err)
		}
		out[r.SourceID] = r
	}
	return out, translateErr("store.LatestDiscoveryRuns", rows.Err())
}

const discoveredMachineSelect = `
	SELECT m.source_id, s.name, m.ref, m.name, m.host, m.tags, m.running, m.role, m.tagged,
	       m.host_key, m.problem, COALESCE(m.target_id, ''), COALESCE(t.name, ''),
	       COALESCE(t.host_key, ''), m.ignored, m.first_seen, m.last_seen, m.missing_since
	FROM discovered_machines m
	JOIN discovery_sources s ON s.id = m.source_id
	LEFT JOIN targets t ON t.id = m.target_id`

func scanDiscoveredMachine(sc rowScanner) (DiscoveredMachine, error) {
	var m DiscoveredMachine
	var tags string
	var first, last int64
	var missing sql.NullInt64
	err := sc.Scan(&m.SourceID, &m.Source, &m.Ref, &m.Name, &m.Host, &tags, &m.Running, &m.Role,
		&m.Tagged, &m.HostKey, &m.Problem, &m.TargetID, &m.Target, &m.TargetHostKey, &m.Ignored,
		&first, &last, &missing)
	if err != nil {
		return m, err
	}
	if jerr := json.Unmarshal([]byte(tags), &m.Tags); jerr != nil {
		return m, fmt.Errorf("tags of %s: %w", m.Ref, jerr)
	}
	m.FirstSeen = time.Unix(first, 0).UTC()
	m.LastSeen = time.Unix(last, 0).UTC()
	if missing.Valid {
		m.MissingSince = time.Unix(missing.Int64, 0).UTC()
	}
	return m, nil
}

// DiscoveredMachines, bulunan makineler; sourceID boşsa bütün kaynaklar.
func (s *Store) DiscoveredMachines(ctx context.Context, sourceID string) ([]DiscoveredMachine, error) {
	rows, err := s.db.QueryContext(ctx, discoveredMachineSelect+`
		WHERE ($1 = '' OR m.source_id = $1)
		ORDER BY lower(m.name), m.source_id, m.ref;`, sourceID)
	if err != nil {
		return nil, translateErr("store.DiscoveredMachines", err)
	}
	defer rows.Close()
	out := []DiscoveredMachine{}
	for rows.Next() {
		m, err := scanDiscoveredMachine(rows)
		if err != nil {
			return nil, translateErr("store.DiscoveredMachines", err)
		}
		out = append(out, m)
	}
	return out, translateErr("store.DiscoveredMachines", rows.Err())
}

// DiscoveredMachine, tek makine.
func (s *Store) DiscoveredMachine(ctx context.Context, sourceID, ref string) (DiscoveredMachine, error) {
	m, err := scanDiscoveredMachine(s.db.QueryRowContext(ctx, discoveredMachineSelect+`
		WHERE m.source_id = $1 AND m.ref = $2;`, sourceID, ref))
	if err != nil {
		return m, translateErr("store.DiscoveredMachine", err)
	}
	return m, nil
}

/*
 * SaveDiscoveredMachine, koşunun gördüğü hâli yazar.
 *
 * ⚠️ İKİ ALAN KOŞUNUN DEĞİL İNSANIN: ignored hiç güncellenmiyor ve
 * target_id yalnızca DOLDURULABİLİYOR, boşaltılamıyor. Koşu satırı
 * okuduktan sonra bir yönetici makineyi kaydedip ya da yok sayıp
 * koşu yazarken eski hâli geri koysaydı, verilen karar sessizce
 * silinirdi. Bağ yalnızca hedef silindiğinde kopuyor (ON DELETE SET NULL).
 */
func (s *Store) SaveDiscoveredMachine(ctx context.Context, m DiscoveredMachine) error {
	tags := m.Tags
	if tags == nil {
		tags = []string{}
	}
	tagJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("store.SaveDiscoveredMachine: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO discovered_machines (source_id, ref, name, host, tags, running, role, tagged,
			host_key, problem, target_id, ignored, first_seen, last_seen, missing_since)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''), FALSE, $12, $12, NULL)
		ON CONFLICT (source_id, ref) DO UPDATE SET
			name = excluded.name, host = excluded.host, tags = excluded.tags,
			running = excluded.running, role = excluded.role, tagged = excluded.tagged,
			host_key = excluded.host_key, problem = excluded.problem,
			target_id = COALESCE(excluded.target_id, discovered_machines.target_id),
			last_seen = excluded.last_seen, missing_since = NULL;`,
		m.SourceID, m.Ref, m.Name, m.Host, string(tagJSON), m.Running, m.Role, m.Tagged,
		m.HostKey, m.Problem, m.TargetID, m.LastSeen.Unix())
	return translateErr("store.SaveDiscoveredMachine", err)
}

// MarkDiscoveredMachineMissing, kaynağın artık bildirmediği makineyi
// işaretler; satır ve hedef kalıyor.
func (s *Store) MarkDiscoveredMachineMissing(ctx context.Context, sourceID, ref string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE discovered_machines SET missing_since = $3
		WHERE source_id = $1 AND ref = $2 AND missing_since IS NULL;`, sourceID, ref, now.Unix())
	return translateErr("store.MarkDiscoveredMachineMissing", err)
}

// LinkDiscoveredMachine, makineyi kaydedildiği hedefe bağlar.
func (s *Store) LinkDiscoveredMachine(ctx context.Context, sourceID, ref, targetID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE discovered_machines SET target_id = $3, ignored = FALSE
		WHERE source_id = $1 AND ref = $2;`, sourceID, ref, targetID)
	if err != nil {
		return translateErr("store.LinkDiscoveredMachine", err)
	}
	return oneRow("store.LinkDiscoveredMachine", res)
}

// SetDiscoveredMachineIgnored, yok sayma bayrağını çevirir; değiştiyse
// makinenin adını döner.
func (s *Store) SetDiscoveredMachineIgnored(ctx context.Context, sourceID, ref string, ignored bool) (string, bool, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `
		UPDATE discovered_machines SET ignored = $3
		WHERE source_id = $1 AND ref = $2 AND ignored <> $3 RETURNING name;`,
		sourceID, ref, ignored).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, translateErr("store.SetDiscoveredMachineIgnored", err)
	}
	return name, true, nil
}

// TargetKeys, bütün hedeflerin kimliği, adı ve sabitlenmiş anahtarı.
func (s *Store) TargetKeys(ctx context.Context) ([]TargetKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, host_key FROM targets;`)
	if err != nil {
		return nil, translateErr("store.TargetKeys", err)
	}
	defer rows.Close()
	var out []TargetKey
	for rows.Next() {
		var t TargetKey
		if err := rows.Scan(&t.ID, &t.Name, &t.HostKey); err != nil {
			return nil, translateErr("store.TargetKeys", err)
		}
		t.HostKey = strings.TrimSpace(t.HostKey)
		out = append(out, t)
	}
	return out, translateErr("store.TargetKeys", rows.Err())
}

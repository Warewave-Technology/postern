package proxy

// Oturumun yaşam döngüsü: yetki → bağlantı → kayıt → denetim → broker.
//
// Bu dosyanın varlık sebebi TEK KAYNAK. SSH (sshd/channel.go) ve web
// terminali (httpapi/terminal.go) aynı oturumu iki farklı kapıdan açıyor;
// aradaki tek fark istemci tarafındaki kanalın ne olduğu. Akışı her iki
// kapıda ayrı ayrı yazsaydık, "kayıt açılamazsa oturum reddedilir" ya da
// "denetim satırı kapanmalı" gibi kararlar iki kopyada yaşar ve er geç
// ayrışırdı — kimlik/yetki için verdiğimiz tek-kaynak kararının aynısı.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/policy"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/upstream"
)

var (
	// ErrAccessDenied: kimlik ya da yetki reddi — bir arıza DEĞİL,
	// güvenlik olayı. Çağıran bunu istemciye "access denied" olarak
	// yansıtır (SSH reject sebebi / HTTP 403).
	ErrAccessDenied = errors.New("proxy: access denied")

	// ErrUnavailable: hedefe ulaşılamadı, kayıt açılamadı, veritabanı
	// erişilemiyor. Kullanıcının suçu değil; birinin müdahale etmesi
	// gerekir. Çağıran "connection failed" / HTTP 503 der.
	ErrUnavailable = errors.New("proxy: session unavailable")
)

// Deps, oturum açmak için gereken altyapı. Hem sshd.Server hem
// httpapi.Server bunu kurar.
type Deps struct {
	Store       *store.Store
	Records     *record.Store
	Authority   *ca.CA
	Logger      *slog.Logger
	RecordInput bool
}

// Request, açılacak oturumun kim/nereye bilgisi.
type Request struct {
	// Username, DOĞRULANMIŞ postern kullanıcı adıdır — istemcinin iddia
	// ettiği değil. SSH tarafında Permissions'tan, web tarafında oturum
	// kaydından gelir; ikisi de kimliği kendi kapısında doğrulamış olur.
	Username   string
	TargetName string
	SrcIP      string
}

// Session, açılmış ama henüz sürülmemiş bir oturum: hedefe bağlanılmış,
// kayıt dosyası açılmış, denetim satırı yazılmıştır. Run ile sürülür,
// Close ile kapatılır.
type Session struct {
	// ID, denetim satırının ve .cast dosyasının ortak anahtarı.
	ID string

	// OSUser, policy'nin verdiği karar — çağıran log'a yazsın diye açık.
	OSUser string

	deps Deps
	log  *slog.Logger

	conn *upstream.Conn
	up   ssh.Channel
	upR  <-chan *ssh.Request
	rec  *record.Writer

	start time.Time
}

// Open, yetkiyi denetler ve oturumu hedefe kadar kurar.
//
// Hata döndüğünde HİÇBİR ŞEY açık kalmaz: kısmi kurulum kendi içinde
// temizlenir, çağıranın Close çağırmasına gerek yoktur (ve Session nil'dir).
//
// TODO(yigit): implement.
//
// Sıra channel.go'daki ile aynı — o kodu buraya taşıyorsun:
//
//  1. deps.Store.Target(ctx, req.TargetName) → ErrNotFound ise
//     ErrAccessDenied ("böyle bir hedef yok" istemciye ayrıntı vermez),
//     başka hata ise ErrUnavailable. Log'da AYRIŞSINLAR: Warn "target not
//     found" / Error "target lookup failed".
//  2. deps.Store.User(ctx, req.Username) → aynı ayrım.
//  3. policy.Authorize(u, target, "") → !Allowed ise Warn "access denied
//     by policy" + Reason, dönen hata ErrAccessDenied.
//  4. upstream.DialWithCert → hata ErrUnavailable.
//  5. conn.OpenSession() → hata ErrUnavailable. ⚠️ Buradan sonra hata
//     yolunda conn.Close() ÇAĞIR: bağlantı açık kaldı.
//  6. record.NewSessionID + deps.Records.Create + record.NewWriter →
//     hata ErrUnavailable. Kayıt açılamazsa oturum AÇILMAZ (S1.8 kararı).
//  7. deps.Store.StartSession → hata ErrUnavailable.
//
// Her hata yolunda o ana kadar açılanları geri sar. Go'da bunun temiz
// yolu: başarı bayrağı + defer. Fonksiyonun başında
//
//	var opened bool
//	defer func() { if !opened { /* temizle */ } }()
//
// ve en sonda opened = true. Böylece yedi ayrı hata dalına yedi ayrı
// temizlik yazmazsın.
func Open(ctx context.Context, deps Deps, req Request) (*Session, error) {
	return nil, fmt.Errorf("proxy.Open: not implemented")
}

// Run, istemci kanalını hedefe bağlar ve oturum bitene kadar sürer.
//
// down/downR istemci tarafı: SSH'ta kabul edilmiş ssh.Channel, web'de
// WebSocket'i ssh.Channel gibi giydiren adaptör. Broker ikisini ayırt
// etmez — arayüz sözleşmesinin bütün faydası bu.
//
// TODO(yigit): implement. (Tek satır: New(...).Run(ctx) — alanlar
// Session'da hazır.)
func (s *Session) Run(ctx context.Context, down ssh.Channel, downR <-chan *ssh.Request) error {
	return fmt.Errorf("proxy.Session.Run: not implemented")
}

// Close, oturumu kapatır: kayıt dosyası, denetim satırı, hedef bağlantısı.
//
// TODO(yigit): implement.
//
// ⚠️ EndSession için context.WithoutCancel(ctx) — oturum bittiğinde asıl
// ctx de iptal olur ve iptal edilmiş ctx ile yapılan kapanış denetim
// satırını sonsuza dek "running" bırakır (channel.go'da öğrendiğimiz ders).
//
// ⚠️ rec.Err() ancak Close'dan SONRA anlamlıdır: yapışkan hata oturum
// boyunca birikir. Bu satır olmazsa bozuk kayıt tamamen sessiz kalır.
//
// Close idempotent olmalı: Run hata verse de vermese de çağrılacak.
func (s *Session) Close(ctx context.Context) {
}

// unused, taşıma bitene kadar import'ları canlı tutar.
// TODO(yigit): Open'ı yazınca bu satırı sil.
var _ = []any{model.Target{}, policy.Authorize, store.SessionStart{}, upstream.Identity{}, record.NewSessionID, ca.CA{}}

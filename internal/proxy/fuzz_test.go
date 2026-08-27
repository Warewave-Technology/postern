package proxy

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/record"
)

// Bu dosyadaki hedefler "panik atmıyor" DEMİYOR. Her biri bir ÖZELLİK
// iddia ediyor: referans ayrıştırıcıyla birebir uyum, kayıpsızlık,
// whitelist'in hedefin gördüğü adla aynı adı süzdüğü, kabul kümesinin
// literal haritanın dışına taşmadığı ve kayda düşen "r" olayının bir
// terminal boyutu olduğu. Panik zaten go test'in verdiği en ucuz sinyal;
// asıl risk sessizce YANLIŞ cevap veren bir ayrıştırıcı.

// --- 1) parseString: x/crypto'ya karşı diferansiyel ---

// refLeadingString, elle yazılmış parseString'in referans karşılığı.
//
// ⚠️ `ssh:"rest"` ETİKETİ TAŞIYICI: etiket olmadan []byte alanı bir SSH
// string'i olarak okunur (4 baytlık ikinci bir uzunluk beklerdi) ve
// karşılaştırma anlamsızlaşırdı. Etiketle birlikte Unmarshal baştaki
// string'i tüketip GERİ KALAN HER ŞEYİ Rest'e koyar — yani parseString'in
// kabul ettiği dilin tam olarak aynısını kabul eder. Etiketi silen biri
// bu testi "yeşil ama boş" hale getirir.
type refLeadingString struct {
	S    string
	Rest []byte `ssh:"rest"`
}

func FuzzParseString(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	// Uydurma uzunluk: dilim sınırının dışına taşma denemesi.
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00, 0x00, 0x00, 0x01})
	f.Add(sshString("LANG"))
	f.Add(append(sshString("LANG"), []byte("artik-cop")...))
	f.Add(envPayload("LANG", "tr_TR.UTF-8"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		name, rest, ok := parseString(payload)

		var ref refLeadingString
		err := ssh.Unmarshal(payload, &ref)

		if (err == nil) != ok {
			t.Fatalf("kabul kümesi ayrıştı: parseString ok=%v, ssh.Unmarshal err=%v, payload=%x", ok, err, payload)
		}
		if !ok {
			return
		}

		if name != ref.S {
			t.Errorf("ad ayrıştı: parseString=%q, ssh.Unmarshal=%q, payload=%x", name, ref.S, payload)
		}
		if !bytes.Equal(rest, ref.Rest) {
			t.Errorf("kalan ayrıştı: parseString=%x, ssh.Unmarshal=%x, payload=%x", rest, ref.Rest, payload)
		}

		// Yapısal değişmezler: kabul edilen her payload tam olarak
		// 4 + ad + kalan'dır. Bu tutmazsa ya bir bayt kayboldu ya da
		// iki kez sayıldı — ikisi de aktarılan payload'ı kaydırır.
		if 4+len(name)+len(rest) != len(payload) {
			t.Errorf("bayt muhasebesi tutmuyor: 4+%d+%d != %d, payload=%x",
				len(name), len(rest), len(payload), payload)
		}
		// Ad KOPYA değil, payload'ın o aralığının birebir aynısı olmalı:
		// broker payload'ı hedefe olduğu gibi iletiyor, dolayısıyla
		// postern'in okuduğu ad ile telde giden baytlar aynı olmalı.
		if !bytes.Equal([]byte(name), payload[4:4+len(name)]) {
			t.Errorf("ad payload'ın kendi baytları değil: %q vs %x", name, payload[4:4+len(name)])
		}
	})
}

// --- 2) env whitelist'inde ad karışıklığı ---

// cName, hedefin C-string semantiğiyle göreceği adı taklit eder: ilk NUL
// baytında keser. OpenSSH tarafındaki ayrıştırıcı bunu yapar.
func cName(s string) string {
	if index := strings.IndexByte(s, 0); index >= 0 {
		return s[:index]
	}
	return s
}

// Whitelist'in tek anlamı, postern'in gördüğü AD ile hedefin göreceği ADIN
// aynı olması. broker.relayRequests req.Payload'ı hedefe OLDUĞU GİBİ
// iletiyor (broker.go: forwardRequest → dst.SendRequest(..., req.Payload));
// yani iki tarafın adı farklı okuduğu her payload doğrudan bir whitelist
// atlatmasıdır. Whitelist LD_PRELOAD ve BASH_ENV'i dışarıda tutmak için var
// — atlatılırsa geriye hiçbir şey kalmaz.
func FuzzEnvRequestNoNameConfusion(f *testing.F) {
	f.Add(envPayload("LANG", "tr_TR.UTF-8"))
	f.Add(envPayload("LC_ALL", "C"))
	f.Add(envPayload("LD_PRELOAD", "/tmp/evil.so"))
	f.Add(envPayload("BASH_ENV", "/tmp/evil.sh"))
	// NUL enjeksiyonu: postern'in "LC_X\x00LD_PRELOAD" gördüğü yerde
	// hedefin "LC_X" görmesi beklenir. Kesilen ad da whitelist'e uymalı.
	f.Add(envPayload("LC_ALL\x00LD_PRELOAD", "/tmp/evil.so"))
	f.Add(envPayload("LANG\x00LD_PRELOAD", "x"))
	// Ad geçerli ama değer eksik / fazladan çöp var: allow() yalnız adı
	// okuyor, payload'ın geri kalanı denetlenmiyor.
	f.Add(sshString("LANG"))
	f.Add(append(envPayload("LANG", "C"), 0xFF))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		var p RequestPolicy // varsayılan whitelist: LANG, LC_*

		ok, reason := p.allow(fromClient, &ssh.Request{Type: "env", Payload: payload})
		if !ok {
			if reason == "" {
				t.Errorf("env reddedildi ama sebep boş — denetim log'u işe yaramaz, payload=%x", payload)
			}
			return
		}

		name, nameOK := envName(payload)
		if !nameOK {
			t.Fatalf("allow=true ama envName ayrıştıramıyor — imkânsız durum, payload=%x", payload)
		}

		// Hedefin C-string okumasıyla kesilen ad da whitelist'e uymalı.
		// Uymuyorsa postern "LC_ALL" sanıp geçiriyor, hedef başka bir
		// değişken kuruyor demektir.
		if trimmed := cName(name); !envAllowed(trimmed, p.acceptEnv()) {
			t.Errorf("NUL kesmesi whitelist'i atlatıyor: postern %q gördü, hedef %q görecek; payload=%x",
				name, trimmed, payload)
		}

		var strict struct{ Name, Value string }
		if err := ssh.Unmarshal(payload, &strict); err != nil {
			// Katı ayrıştırma reddediyor ama postern geçiriyor: hedef
			// muhtemelen request'i düşürecek. Ad karışıklığı değil,
			// bu yüzden hata değil.
			return
		}
		if strict.Name != name {
			t.Errorf("ad karışıklığı: whitelist %q ile eşleşti, katı ayrıştırma %q veriyor; payload=%x",
				name, strict.Name, payload)
		}
	})
}

// --- 3) varsayılan reddet ---

// Kabul kümesi literal haritanın DIŞINA taşamaz. Taşarsa "SSH'a yarın
// eklenen bir uzantı bu köprüden geçemez" iddiası çöker.
func FuzzPolicyDefaultDeny(f *testing.F) {
	f.Add("pty-req", []byte{}, false)
	f.Add("env", envPayload("LANG", "C"), false)
	f.Add("env", envPayload("LD_PRELOAD", "/tmp/x.so"), false)
	f.Add("subsystem", sshString("sftp"), false)
	f.Add("exit-status", []byte{0, 0, 0, 0}, true)
	f.Add("pty-req", []byte{}, true)
	f.Add("", []byte{}, false)
	f.Add("x11-req", []byte{}, false)
	f.Add("auth-agent-req@openssh.com", []byte{}, false)
	f.Add("PTY-REQ", []byte{}, false)
	f.Add("pty-req\x00", []byte{}, false)
	f.Add(" pty-req", []byte{}, false)

	f.Fuzz(func(t *testing.T, reqType string, payload []byte, targetSide bool) {
		dir := fromClient
		allowedTypes := clientRequests
		if targetSide {
			dir = fromTarget
			allowedTypes = targetRequests
		}

		var p RequestPolicy
		ok, reason := p.allow(dir, &ssh.Request{Type: reqType, Payload: payload})

		if ok && !allowedTypes[reqType] {
			t.Errorf("varsayılan reddet delindi: %s yönünde %q geçti ama listede yok", dir, reqType)
		}
		if !ok && reason == "" {
			t.Errorf("reddedildi ama sebep boş: %s / %q — operatör log'dan hiçbir şey öğrenemez", dir, reqType)
		}
	})
}

// --- 4a) pty-req kayıpsız gidiş-dönüş ---

// pty-req payload'ı hedefe olduğu gibi iletiliyor; ParsePty'nin okuduğu
// değerler ise kayda düşüyor. İkisi ayrışırsa kayıt oturumu YANLIŞ
// boyutta oynatır. Kayıpsızlık burada denetim doğruluğu demek.
func FuzzParsePtyRoundTrip(f *testing.F) {
	f.Add("xterm-256color", uint32(80), uint32(24), uint32(640), uint32(480), "\x81\x00\x00\x25\x80\x00")
	f.Add("", uint32(0), uint32(0), uint32(0), uint32(0), "")
	f.Add("vt100", uint32(0xFFFFFFFF), uint32(0xFFFFFFFF), uint32(0xFFFFFFFF), uint32(0xFFFFFFFF), "")
	f.Add("\xff\xfe", uint32(1), uint32(1), uint32(1), uint32(1), "\x00")

	f.Fuzz(func(t *testing.T, term string, cols, rows, width, height uint32, modes string) {
		p := PtyRequest{Term: term, Columns: cols, Rows: rows, Width: width, Height: height, Modes: modes}

		wire := ssh.Marshal(p)

		got, err := ParsePty(wire)
		if err != nil {
			t.Fatalf("kendi ürettiğimiz payload ayrıştırılamadı: %v, wire=%x", err, wire)
		}
		if got != p {
			t.Errorf("gidiş-dönüş kayıplı: %+v != %+v, wire=%x", got, p, wire)
		}

		// Fazladan tek bayt REDDEDİLMELİ. Kabul edilirse payload'ın
		// sonuna istediğini ekleyen bir istemci postern'e bir şey,
		// hedefe başka bir şey söyleyebilir.
		trailing := make([]byte, 0, len(wire)+1)
		trailing = append(trailing, wire...)
		trailing = append(trailing, 0)
		if _, err := ParsePty(trailing); err == nil {
			t.Errorf("sondaki fazladan bayt kabul edildi: %x", trailing)
		}
	})
}

// --- 4b) kayda düşen "r" olayı gerçek bir terminal boyutu olmalı ---

var resizeEvent = regexp.MustCompile(`^[0-9]+x[0-9]+$`)

// maxTerminalDim, bir terminal boyutunun makul üst sınırı. SSH telde
// uint32 taşıyor ama gerçek bir terminal 65535 sütundan geniş değil.
//
// ⚠️ İŞARET KONTROLÜ YETMEZ: int(uint32(0xFFFFFFFF)) amd64'te
// 4294967295, 32-bit derlemede -1'dir. "negatif mi" diye sormak CI'da
// yeşil kalır, 32-bit'te bozuk kayıt üretir. Bu yüzden MUTLAK sınır.
// Sabit ÜRETİM KODUNDAN geliyor (bkz. broker.go / wschannel.go):
// testin kendi kopyasını tutması, sınır değişince testin sessizce
// eski değeri doğrulamaya devam etmesi demek olurdu.
var _ = maxTerminalDim

func FuzzRecordResize(f *testing.F) {
	f.Add(true, ssh.Marshal(PtyRequest{Term: "xterm", Columns: 80, Rows: 24}))
	f.Add(false, ssh.Marshal(WindowChangeRequest{Columns: 120, Rows: 30}))
	f.Add(false, []byte{})
	f.Add(true, []byte{0xFF})
	// Bilinen kırıcı: istemcinin gönderdiği uint32 sınırsız int'e
	// çevriliyor (broker.go recordResize → int(p.Columns)).
	f.Add(false, ssh.Marshal(WindowChangeRequest{Columns: 0xFFFFFFFF, Rows: 0xFFFFFFFF}))
	f.Add(true, ssh.Marshal(PtyRequest{Term: "xterm", Columns: 0xFFFFFFFF, Rows: 0xFFFFFFFF}))

	f.Fuzz(func(t *testing.T, isPty bool, payload []byte) {
		reqType := "window-change"
		if isPty {
			reqType = "pty-req"
		}

		sink := &memCloser{}
		rec, err := record.NewWriter(sink, 80, 24, nil)
		if err != nil {
			t.Fatalf("record.NewWriter: %v", err)
		}

		// recordResize yalnızca rec ve logger'a dokunuyor; kanallar nil
		// kalabilir. Hedef SAF ve BELLEK İÇİ: soket yok, dosya yok.
		b := New(nil, nil, nil, nil, rec, false, RequestPolicy{}, testLogger())
		b.recordResize(&ssh.Request{Type: reqType, Payload: payload})

		if err := rec.Close(); err != nil {
			t.Fatalf("rec.Close: %v", err)
		}

		for _, line := range strings.Split(strings.TrimRight(sink.String(), "\n"), "\n") {
			if !strings.HasPrefix(line, "[") {
				continue // başlık satırı
			}

			var event []any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatalf("kayıt satırı geçerli JSON değil: %q (%v)", line, err)
			}
			if len(event) != 3 {
				t.Fatalf("asciicast olayı 3 alanlı olmalı: %q", line)
			}

			kind, _ := event[1].(string)
			if kind != "r" {
				continue
			}

			data, _ := event[2].(string)
			if !resizeEvent.MatchString(data) {
				t.Fatalf("kayda geçersiz boyut olayı düştü: %q (payload=%x)", data, payload)
			}

			cols, rows, _ := strings.Cut(data, "x")
			for _, dim := range []string{cols, rows} {
				value, err := strconv.ParseUint(dim, 10, 64)
				if err != nil {
					t.Fatalf("boyut sayı değil: %q", dim)
				}
				if value > maxTerminalDim {
					t.Fatalf("istemcinin uydurduğu boyut denetim kaydına girdi: %q > %d (payload=%x)",
						data, maxTerminalDim, payload)
				}
			}
		}
	})
}

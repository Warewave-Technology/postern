GO ?= go

# VERSION, ikiliye basılan sürüm etiketi.
#
# ⚠️ `git describe` KULLANILIYOR, elle yazılan bir sabit DEĞİL. Elle
# tutulan bir sürüm satırı, etiketlemeyi unutan ya da etiketten sonra
# commit atan her derlemede yalan söyler. describe ikisini de anlatıyor:
# "v1.0.0" tam etiketli bir ağaç, "v1.0.0-3-gab12cd" etiketten üç commit
# sonrası.
#
# ⚠️ `--always` YOK — VE ÖNCE VARDI. Onunla describe, etiket
# bulamadığında çıplak commit hash'ine düşüyor; o hash de ikiliye
# BASILIYOR, yani ikili kendini "etiketlenmiş" sanıyor ve "bu bir sürüm
# derlemesi değil" uyarısı hiç çıkmıyordu. Ölçüldü: etiketsiz bir ağaçta
# `postern version`, uyarısız bir şekilde "15911df-dirty" diyordu.
#
# Etiket yoksa VERSION boş kalıyor ve ikili kendini "dev" diye tanıtıyor.
# Kendini sürüm sanan bir geliştirme derlemesi, "yamalı mıyım" sorusuna
# verilebilecek en kötü cevap.
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null)
LDFLAGS := -X github.com/warewave/postern/internal/version.version=$(VERSION)


# Araç sürümleri sabitlenmiş: "@latest" ile koşan bir CI, aracın yeni bir
# sürümü çıktığında hiçbir şey değişmemişken kırmızıya döner. Yükseltme
# bilinçli bir commit olmalı.
GOSEC_VERSION        ?= v2.29.0
GOVULNCHECK_VERSION  ?= v1.7.0

.PHONY: build test test-race test-short test-integration vet fmt lint sec vuln fuzz audit ci web web-test web-check clean

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/postern ./cmd/postern

# ⚠️ Docker gerektirir: store'a dokunan testler gerçek bir PostgreSQL'e
# karşı koşuyor (internal/testdb). Konteynersiz koşmak için: make test-short
test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Docker'sız çalışan alt küme. Yeşil olması store'un sınandığı anlamına
# GELMEZ — sadece ondan bağımsız paketlerin geçtiğini söyler.
test-short:
	$(GO) test -short ./...

# S1.9: testcontainers ile gerçek bir OpenSSH sunucusuna karşı koşar.
test-integration:
	$(GO) test -race -tags integration -count=1 -timeout 30m ./...

vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./test/...

fmt:
	gofmt -l -w .

# Arayüzü kur. Çıktı (web/dist) REPOYA GİRER: go:embed onu derleme
# zamanında gömüyor ve Go tarafını derlemek için Node kurulu olmasın
# istiyoruz.
web:
	cd web && npm ci && npm run build

# Arayüz testleri (vitest + jsdom).
#
# ⚠️ npm bağımlılıklarını ne gosec ne govulncheck tarıyor; test
# bağımlılıkları da öyle. Bu yüzden liste dar tutuldu ve yeni bir paket
# eklemek bilinçli bir karar olmalı.
web-test:
	cd web && npm ci && npm test

# web/dist kaynağıyla uyumlu mu? Bu kontrol olmazsa web/src'i değiştirip
# yeniden kurmayı unutan bir commit, gömülü arayüzü sessizce eskitir —
# testler geçer, panel eski kodu gösterir.
web-check: web
	@test -z "$$(git status --porcelain web/dist)" || \
		(echo "web/dist kaynakla uyumsuz: 'make web' çalıştırıp sonucu commit'le"; \
		 git --no-pager diff --stat web/dist; exit 1)

# gofmt bir şey değiştirecek mi? CI'da "değiştirdi" demek yerine düşmeli.
lint:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt gerekli"; exit 1)

# gosec: statik güvenlik taraması.
#
# G104 (unhandled errors) HARİÇ TUTULUYOR. Sebebi: 22 bulgunun tamamı
# temizlik yolundaki Close()/Reject() çağrıları — hata döndüğünde
# yapılacak bir şey olmayan yerler. Kural başına gerekçeli 22 açıklama
# yazmak, gerçek bulguları o gürültünün içinde kaybederdi. Diğer bütün
# kurallar AÇIK ve kalan yanlış pozitifler kodda tek tek "#nosec <kural>
# -- gerekçe" satırlarıyla işaretli: yarın eklenen gerçek bir bulgu
# susturulmuş olmaz.
sec:
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) \
		-exclude=G104 -exclude-generated -quiet ./...

# govulncheck: bağımlılıklarda ve standart kütüphanede BİLİNEN açıklar.
# Yalnız gerçekten ÇAĞRILAN kod yollarını sayar, o yüzden çıktısı
# eyleme dönüştürülebilir.
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# Fuzz kampanyası.
#
# -fuzz TEK bir hedef ve TEK bir paket alır, ./... biçimi yok — bu yüzden
# liste elle yazılı. Listenin elle olması ayrıca ENVANTER: neyin
# gerçekten fuzz'landığı burada görünüyor, joker bir desen gizlerdi.
#
# ⚠️ ci hedefine EKLENMEDİ. Tohum korpusu zaten her `go test` koşusunda
# çalışıyor (yani test-race hepsini -race altında sınıyor); süreli ve
# rastgele bir iş ise PR kapısında insanları kırmızıyı görmezden gelmeye
# alıştırır. Kampanya haftalık cron'da.
FUZZTIME ?= 60s

FUZZ_TARGETS = \
	internal/proxy:FuzzParseString \
	internal/proxy:FuzzEnvRequestNoNameConfusion \
	internal/proxy:FuzzPolicyDefaultDeny \
	internal/proxy:FuzzParsePtyRoundTrip \
	internal/proxy:FuzzRecordResize \
	internal/sftpaudit:FuzzDecoderSurvivesHostileStreams \
	internal/sftpaudit:FuzzFinishIsAlwaysSafe \
	internal/record:FuzzWriterChunking \
	internal/record:FuzzSplitIncompleteUTF8 \
	internal/record:FuzzWriterStreamSeparation \
	internal/sshd:FuzzParseUsername \
	internal/policy:FuzzAuthorizeContract \
	internal/policy:FuzzAuthorizeRolelessNeverAllowed \
	internal/store:FuzzDSN \
	internal/httpapi:FuzzHandleControl \
	internal/httpapi:FuzzSameOriginURL \
	internal/httpapi:FuzzSPAPath

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; target=$${t##*:}; \
		echo "=== $$pkg $$target ==="; \
		$(GO) test -run=^$$ -fuzz=^$$target$$ -fuzztime=$(FUZZTIME) ./$$pkg || exit 1; \
	done

audit: sec vuln

# CI'ın koştuğunun aynısı — bir şeyi bozmadan önce yerelde koş.
#
# ⚠️ web-test VE web-check DAHİL, ve eksiklikleri ölçüldü. Bu hedef
# "CI'ın koştuğunun aynısı" diye duruyordu ama panelin 312 testini
# koşmuyordu: yerelde yeşil gören biri, CI'da arayüz testlerinden
# düşüyordu. web-check'in eksikliği daha sinsiydi — web/src'i değiştirip
# yeniden kurmayı unutan bir commit'i yakalayan tek kontrol o, ve
# yakalamadığında gömülü panel sessizce eskiyor (bu depoda bir kez oldu:
# kaldırılmış bir metni hâlâ gösteren bir paket commit'lendi).
#
# ⚠️ SIRA: web-check `make web` çalıştırıyor, yani npm kurulumu ve
# derleme. Go testlerinden SONRA duruyor ki hızlı geri bildirim önce
# gelsin — lint'te düşecek bir değişiklik için npm ci beklemek gerekmez.
ci: lint vet test-race audit test-integration web-test web-check

clean:
	rm -rf bin

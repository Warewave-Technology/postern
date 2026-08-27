GO ?= go

# Araç sürümleri sabitlenmiş: "@latest" ile koşan bir CI, aracın yeni bir
# sürümü çıktığında hiçbir şey değişmemişken kırmızıya döner. Yükseltme
# bilinçli bir commit olmalı.
GOSEC_VERSION        ?= v2.29.0
GOVULNCHECK_VERSION  ?= v1.7.0

.PHONY: build test test-race test-short test-integration vet fmt lint sec vuln audit ci clean

build:
	$(GO) build -o bin/postern ./cmd/postern

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

audit: sec vuln

# CI'ın koştuğunun aynısı — bir şeyi bozmadan önce yerelde koş.
ci: lint vet test-race audit test-integration

clean:
	rm -rf bin

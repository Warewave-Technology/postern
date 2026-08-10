GO ?= go

.PHONY: build test test-race test-integration vet fmt clean

build:
	$(GO) build -o bin/postern ./cmd/postern

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# S1.9: testcontainers ile gerçek bir OpenSSH sunucusuna karşı koşar.
test-integration:
	$(GO) test -tags integration -count=1 ./test/integration/...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf bin

# postern'in tek ikilisi, iki aşamada.
#
# ⚠️ NEDEN VAR: depoyu bulan birinin postern'i denemesi, kendi
# PostgreSQL'ini kurmasına bağlıydı. Ölçüldü: indirilen tarball'dan
# çalışan bir panele kadar olan yol, bir akşamı değerlendirmeye ayıran
# birinin sekmeyi kapatmasına yetiyor.
#
# ⚠️ web/dist DEPODA DURUYOR ve ikiliye gömülü (go:embed). Bu yüzden
# burada Node yok: panel derlemesi CI'ın işi (make web-check), imajın
# değil. Node eklemek, imajı büyütmenin yanında paneli iki ayrı yerde
# derlenebilir yapardı.
FROM golang:1.26-alpine AS build
WORKDIR /src

# Önce bağımlılıklar: kaynak değiştiğinde modül katmanı yeniden
# indirilmesin.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO yok: tek statik ikili, alpine'de de distroless'ta da koşar.
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/postern ./cmd/postern

FROM alpine:3.22
# ca-certificates: OIDC ve nesne deposu HTTPS uçları için.
# wget: compose sağlık kontrolü /healthz'i çağırıyor.
RUN apk add --no-cache ca-certificates wget && \
    adduser -D -H -u 10001 postern
COPY --from=build /out/postern /usr/local/bin/postern

# ⚠️ root DEĞİL. postern ayrıcalıklı bir port dinlemiyor (2222/8080),
# dolayısıyla root olmak için bir sebep yok; olsaydı konteyner kaçışının
# bedeli hedeflerin tamamı olurdu.
USER postern
WORKDIR /var/lib/postern
ENTRYPOINT ["postern"]
CMD ["serve", "--config", "/etc/postern/postern.yaml"]

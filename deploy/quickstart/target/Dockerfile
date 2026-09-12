# Hızlı başlangıcın "hedef makinesi": postern'in CA'sına güvenen sshd.
#
# ⚠️ ÜRÜN DEĞİL, DEMO. Gerçek bir hedefte bu dosyanın yaptığı tek şey
# sshd_config'e TrustedUserCAKeys satırını eklemek olur; buradaki
# kullanıcılar ve örnek dosyalar yalnızca ilk on dakikada gösterecek bir
# şey olsun diye var.
FROM alpine:3.22

RUN apk add --no-cache openssh-server openssh-keygen

# ⚠️ PAROLA YOK, ANAHTAR YOK. Bu hesaplara girmenin tek yolu postern'in
# bastığı sertifika: authorized_keys dosyaları bilerek boş. Demoda bile
# "hedefte duran anahtar" bırakmak, ürünün iddiasının tersini gösterirdi.
RUN adduser -D -s /bin/sh ayse && adduser -D -s /bin/sh veli && \
    passwd -u ayse && passwd -u veli

# Dosya tarayıcısında görülecek bir şeyler.
RUN mkdir -p /home/ayse/raporlar /home/ayse/gunlukler && \
    printf 'ceyrek kapanis raporu\n' > /home/ayse/raporlar/2026-Q3.txt && \
    printf 'musteri listesi\n' > /home/ayse/raporlar/musteriler.csv && \
    printf 'servis baslatildi\n' > /home/ayse/gunlukler/servis.log && \
    dd if=/dev/urandom of=/home/ayse/yedek.bin bs=1k count=64 2>/dev/null && \
    chown -R ayse:ayse /home/ayse

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

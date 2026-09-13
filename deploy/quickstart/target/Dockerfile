# Hızlı başlangıcın "hedef makinesi": postern'in CA'sına güvenen sshd.
#
# ⚠️ ÜRÜN DEĞİL, DEMO. Gerçek bir hedefte yapılacak iş
# deploy/ansible/roles/postern_target'ta: CA'ya güven, principal dosyaları
# ve (isteğe bağlı) yönetim hesabı. Bu yorum önceden "tek şey
# TrustedUserCAKeys satırını eklemek" diyordu — principal dosyası olmadan
# yönetim hesabının kişilere açılabildiği ölçülünce yanlış oldu. Buradaki
# kullanıcılar ve örnek dosyalar yalnızca ilk on dakikada gösterecek bir
# şey olsun diye var.
FROM alpine:3.22

# sudo ve shadow yönetim hesabı için: visudo sudo paketinde, useradd /
# groupadd / usermod shadow'da. postern busybox adduser'ı yönetmiyor ve
# onsuz makineyi "yönetilemez" diye adlandırıyor.
RUN apk add --no-cache openssh-server openssh-keygen sudo shadow

# ⚠️ PAROLA YOK, ANAHTAR YOK. Bu hesaplara girmenin tek yolu postern'in
# bastığı sertifika: authorized_keys dosyaları bilerek boş. Demoda bile
# "hedefte duran anahtar" bırakmak, ürünün iddiasının tersini gösterirdi.
#
# ⚠️ KİLİT "*" İLE AÇILIYOR, `passwd -u` İLE DEĞİL — ÖLÇÜLDÜ. adduser -D
# hesabı "!" ile kilitli açıyor ve OpenSSH kilitli hesaba sertifikayla da
# girmiyor. Bu satır önceden busybox `passwd -u` kullanıyordu; o "!"yi
# silip parola alanını BOŞ bırakıyordu ("ayse:") — yani "parola yok" değil
# "parola gerekmez". Bu imajda su suid olmadığı için yerelde
# kullanılamıyordu, ama yukarıdaki iddianın tersiydi. shadow paketi
# eklenince passwd değişti ve boş parolaya kilit açmayı reddetti; kurulum
# bu yüzden düştü ve boşluk ortaya çıktı. "*" kilitli değil, ama hiçbir
# parolayla da eşleşmiyor.
RUN adduser -D -s /bin/sh ayse && adduser -D -s /bin/sh veli && \
    sed -i -e 's/^ayse:!/ayse:*/' -e 's/^veli:!/veli:*/' /etc/shadow

# Dosya tarayıcısında görülecek bir şeyler.
RUN mkdir -p /home/ayse/raporlar /home/ayse/gunlukler && \
    printf 'ceyrek kapanis raporu\n' > /home/ayse/raporlar/2026-Q3.txt && \
    printf 'musteri listesi\n' > /home/ayse/raporlar/musteriler.csv && \
    printf 'servis baslatildi\n' > /home/ayse/gunlukler/servis.log && \
    dd if=/dev/urandom of=/home/ayse/yedek.bin bs=1k count=64 2>/dev/null && \
    chown -R ayse:ayse /home/ayse

# ⚠️ YÖNETİM HESABI — Ansible rolünün postern_manage_host: true ile
# eklediğinin aynısı, panelden "Check management access" denenebilsin diye.
# Parola "*": kilitli değil (kilitliyse sertifika da kabul edilmiyor) ama
# parolayla da girilemiyor. authorized_keys YOK. Principal dosyası
# entrypoint.sh'te: orada yalnızca "postern-manage" yazıyor.
RUN addgroup -S postern && \
    adduser -S -D -G postern -h /var/lib/postern-managed -s /bin/sh postern && \
    sed -i 's/^postern:!/postern:*/' /etc/shadow && \
    echo 'postern ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/postern && \
    chmod 0440 /etc/sudoers.d/postern && \
    visudo -cf /etc/sudoers.d/postern

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

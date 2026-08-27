# S2.3 — sertifika kabul eden hedef.
#
# Bu Dockerfile aynı zamanda ÇALIŞTIRILABİLİR DOKÜMANTASYONDUR: gerçek bir
# hedefte yapılacaklar tam olarak bunlar (plan S2.3, deploy/ansible'a da
# aynısı girecek).
FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-keygen shadow

# Hedefteki OS kullanıcısı. Sertifikanın principal'ı buna karşılık gelir.
#
# ⚠️ adduser -D hesabı KİLİTLİ parolayla (/etc/shadow'da "!") açar ve OpenSSH
# kilitli hesaba sertifikayla bile giriş vermez ("account is locked").
# Parolayı "*" yapmak kilidi kaldırır ama parolayla girişe de izin vermez —
# istediğimiz tam olarak bu: giriş yalnızca sertifikayla.
RUN adduser -D -s /bin/sh postern \
 && sed -i 's/^postern:!/postern:*/' /etc/shadow

# Host anahtarları (postern bunları pinleyecek).
RUN ssh-keygen -A

# ⚠️ Hedef tarafının TAMAMI bu iki satır:
#
#   TrustedUserCAKeys        → "bu CA'nın imzaladığı sertifikalara güven"
#   AuthorizedPrincipalsFile → "hangi principal hangi hesaba girebilir"
#
# authorized_keys dosyalarında HİÇBİR statik anahtar yok. Erişimi veren şey
# artık bir anahtar değil, kısa ömürlü bir sertifika.
RUN printf '%s\n' \
    'TrustedUserCAKeys /etc/ssh/postern_ca.pub' \
    'AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u' \
    'PubkeyAuthentication yes' \
    'PasswordAuthentication no' \
    'PermitRootLogin no' \
    'LogLevel VERBOSE' \
    'AcceptEnv POSTERN_ALLOWED POSTERN_DENIED' \
    > /etc/ssh/sshd_config.d/postern.conf 2>/dev/null \
 || printf '%s\n' \
    'TrustedUserCAKeys /etc/ssh/postern_ca.pub' \
    'AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u' \
    'PubkeyAuthentication yes' \
    'PasswordAuthentication no' \
    'PermitRootLogin no' \
    'LogLevel VERBOSE' \
    'AcceptEnv POSTERN_ALLOWED POSTERN_DENIED' \
    >> /etc/ssh/sshd_config

# ⚠️ AcceptEnv yalnızca TEST için: postern'in env süzgecini HEDEFİN
# süzgecinden ayırt edebilmek gerekiyor. OpenSSH varsayılanı hiçbir env
# kabul etmez, dolayısıyla o hâlde "postern mi reddetti, hedef mi"
# ayrılamıyor. Gerçek bir hedefte bu satır olmamalı.

# "postern" OS kullanıcısına yalnızca "postern" principal'ı girebilir.
RUN mkdir -p /etc/ssh/auth_principals \
 && echo 'postern' > /etc/ssh/auth_principals/postern

# CA public anahtarı konteyner başlarken kopyalanacak (test üretiyor).
# Dosya yoksa sshd hiçbir sertifikaya güvenmez — varsayılan deny.
RUN touch /etc/ssh/postern_ca.pub && chmod 644 /etc/ssh/postern_ca.pub

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]

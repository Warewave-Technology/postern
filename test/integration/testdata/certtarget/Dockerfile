# S2.3 — sertifika kabul eden hedef.
#
# Bu Dockerfile aynı zamanda ÇALIŞTIRILABİLİR DOKÜMANTASYONDUR: gerçek bir
# hedefte yapılacaklar tam olarak bunlar (plan S2.3, deploy/ansible'a da
# aynısı girecek).
FROM alpine:3.20

# sudo: yönetim hesabı için (visudo da bu pakette). shadow: useradd,
# groupadd, usermod — postern busybox adduser'ı yönetmiyor.
RUN apk add --no-cache openssh-server openssh-keygen shadow sudo

# Hedefteki OS kullanıcısı. Sertifikanın principal'ı buna karşılık gelir.
#
# ⚠️ adduser -D hesabı KİLİTLİ parolayla (/etc/shadow'da "!") açar ve OpenSSH
# kilitli hesaba sertifikayla bile giriş vermez ("account is locked").
# Parolayı "*" yapmak kilidi kaldırır ama parolayla girişe de izin vermez —
# istediğimiz tam olarak bu: giriş yalnızca sertifikayla.
#
# ⚠️ HESAP ADI "postern" DEĞİL. Bu dosya çalıştırılabilir doküman ve
# eskiden insanın hesabını "postern" diye açıyordu; o ad artık postern'in
# KENDİ yönetim hesabı (hedefte parolasız root sudo) ve ikili onu bir kişi
# için hiç açmıyor. Dokümanın tam o karışıklığı öğretmesi yanlıştı.
RUN adduser -D -s /bin/sh deploy \
 && sed -i 's/^deploy:!/deploy:*/' /etc/shadow

# ⚠️ KİLİTSİZ AMA PRINCIPAL DOSYASI OLMAYAN HESAP — principal politikasının
# testi için. O test önceden "nobody" kullanıyordu ve yanlış sebepten
# geçiyordu: nobody KİLİTLİ, sshd onu sertifikaya bakmadan reddediyordu.
# AuthorizedPrincipalsFile satırı kaldırılsa bile test yeşil kalırdı.
RUN adduser -D -s /bin/sh noprincipals \
 && sed -i 's/^noprincipals:!/noprincipals:*/' /etc/shadow

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

# "deploy" OS kullanıcısına yalnızca "deploy" principal'ı girebilir.
# "noprincipals" için bilerek dosya YOK.
RUN mkdir -p /etc/ssh/auth_principals \
 && echo 'deploy' > /etc/ssh/auth_principals/deploy

# ⚠️ YÖNETİM HESABI — Ansible rolünün postern_manage_host: true ile
# eklediğinin aynısı (deploy/ansible/roles/postern_target/tasks/main.yml).
#
#   - hesap "postern", parolası "*" (kilitli değil; kilitliyse sertifika da
#     kabul edilmiyor)
#   - principal dosyasında YALNIZCA "postern-manage": os_user'ı "postern"
#     olan bir kişinin sertifikası (principal'ı "postern") bu hesabı açamaz
#   - authorized_keys YOK
#   - parolasız sudo, visudo'dan geçerek
RUN addgroup -S postern \
 && adduser -S -D -G postern -h /var/lib/postern-managed -s /bin/sh postern \
 && sed -i 's/^postern:!/postern:*/' /etc/shadow \
 && echo 'postern-manage' > /etc/ssh/auth_principals/postern \
 && echo 'postern ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/postern \
 && chmod 0440 /etc/sudoers.d/postern \
 && visudo -cf /etc/sudoers.d/postern

# CA public anahtarı konteyner başlarken kopyalanacak (test üretiyor).
# Dosya yoksa sshd hiçbir sertifikaya güvenmez — varsayılan deny.
RUN touch /etc/ssh/postern_ca.pub && chmod 644 /etc/ssh/postern_ca.pub

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]

#!/bin/sh
# Hedefin sshd'sini postern'in CA'sına güvenecek biçimde başlatır.
set -e

# ⚠️ CA AÇIK ANAHTARI BEKLENİYOR, ÜRETİLMİYOR. Hedef, postern'in CA'sını
# yalnızca TANIR; anahtarı burada üretseydik her hedefin kendi CA'sı
# olurdu ve "tek yerden imzalanan sertifika" iddiası kalmazdı.
if [ ! -s /etc/ssh/postern_ca.pub ]; then
	echo "hedef: /etc/ssh/postern_ca.pub yok — önce quickstart.sh CA'yı üretmeli" >&2
	exit 1
fi

# ⚠️ HOST ANAHTARLARI KALICI — YOKSA HEDEF İMAJINA DOKUNMAK DEMOYU KIRIYOR.
#
# postern hedefin host anahtarını kurulumda SABİTLİYOR. Anahtar her
# başlangıçta yeniden üretilseydi, hedef konteynerini yeniden oluşturan
# her değişiklik (bu dosyaya bir satır eklemek bile) sabitlenmiş anahtarla
# uyuşmazlık verir ve her oturum "host key mismatch" ile düşerdi. Anahtarlar
# .state altında duruyor; ilk başlangıçta üretilip oraya yazılıyor.
KEYS=/var/lib/demo-hostkeys
if ls "$KEYS"/ssh_host_*_key >/dev/null 2>&1; then
	cp "$KEYS"/ssh_host_* /etc/ssh/
else
	ssh-keygen -A
	mkdir -p "$KEYS"
	cp /etc/ssh/ssh_host_* "$KEYS"/
fi
chmod 600 /etc/ssh/ssh_host_*_key

# ⚠️ PRINCIPAL DOSYASI ŞART — YÖNETİM HESABI YÜZÜNDEN, VE ÖLÇÜLDÜ.
#
# Bu hedef önceden yalnızca TrustedUserCAKeys yazıyordu. O hâlde sshd giriş
# adını sertifikanın principal listesinde arıyor: "ayse" için basılan
# sertifika "ayse" hesabını açıyor ve bu yeterliydi. Yönetim hesabı bu
# kuralın dışında: postern "postern" hesabına "postern-manage" principal'ıyla
# giriyor, ve principal dosyası yoksa bu giriş reddedilirken principal'ı
# "postern" olan bir sertifika parolasız root tutan hesabı AÇIYOR
# (test/integration/manage_test.go). Ansible rolünün kurduğu şeyin aynısı.
mkdir -p /etc/ssh/auth_principals
echo ayse >/etc/ssh/auth_principals/ayse
echo veli >/etc/ssh/auth_principals/veli
echo postern-manage >/etc/ssh/auth_principals/postern

cat >> /etc/ssh/sshd_config <<'CONF'

# postern hızlı başlangıcı
TrustedUserCAKeys /etc/ssh/postern_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
CONF

exec /usr/sbin/sshd -D -e

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

ssh-keygen -A

cat >> /etc/ssh/sshd_config <<'CONF'

# postern hızlı başlangıcı
TrustedUserCAKeys /etc/ssh/postern_ca.pub
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
CONF

exec /usr/sbin/sshd -D -e

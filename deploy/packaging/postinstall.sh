#!/bin/sh
# postern paket kurulumu: hesap, dizinler, izinler.
#
# ⚠️ SERVİS BAŞLATILMIYOR VE ETKİNLEŞTİRİLMİYOR. postern bir
# yapılandırma, bir CA anahtarı, bir sır anahtarı ve bir veritabanı
# olmadan açılmıyor; paketin kurulumunda başlatmak, her kurulumun
# ardından "failed" bir birim bırakırdı. Operatör hazır olduğunda
# kendisi `systemctl enable --now postern` diyor.
set -e

# ⚠️ HESAP VARSA DOKUNULMUYOR. Yükseltmede yeniden yaratmaya çalışmak,
# kayıtların ve anahtarların sahipliğini değiştirebilirdi.
if ! getent passwd postern >/dev/null 2>&1; then
	useradd --system --home-dir /var/lib/postern \
		--shell /usr/sbin/nologin --comment "postern bastion" postern \
		2>/dev/null ||
		adduser --system --home /var/lib/postern \
			--shell /usr/sbin/nologin postern 2>/dev/null || true
fi

# Kayıtlar: yalnızca postern okur ve yazar.
install -d -o postern -g postern -m 0700 /var/lib/postern
install -d -o postern -g postern -m 0700 /var/lib/postern/recordings

# ⚠️ /etc/postern KÖKE AİT, GRUBA OKUNUR. İçinde CA ve sır anahtarının
# YOLLARI var; postern'in okuması yeterli, yazması gerekmiyor.
install -d -o root -g postern -m 0750 /etc/postern

if [ -f /etc/postern/postern.env ]; then
	chown root:postern /etc/postern/postern.env
	chmod 0640 /etc/postern/postern.env
fi

systemctl daemon-reload >/dev/null 2>&1 || true

cat <<'NEXT'

postern is installed but not started — it needs a configuration first.

  1. write /etc/postern/postern.yaml      (see /usr/share/doc/postern)
  2. postern ca init --key /etc/postern/ca_ed25519
  3. postern secret init --config /etc/postern/postern.yaml
  4. postern db migrate --config /etc/postern/postern.yaml
  5. postern admin bootstrap --config /etc/postern/postern.yaml
  6. systemctl enable --now postern

NEXT

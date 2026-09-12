#!/bin/sh
# ⚠️ YALNIZCA DURDURUYOR. Kayıtlar, anahtarlar, yapılandırma ve
# veritabanı DURUYOR: paket kaldırmak denetim kanıtını silmek değildir.
# Silmek isteyen operatör bunu bilerek ve elle yapar.
set -e

if [ -d /run/systemd/system ]; then
	systemctl stop postern >/dev/null 2>&1 || true
fi

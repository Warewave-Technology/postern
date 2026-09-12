#!/usr/bin/env bash
#
# postern in ten minutes: a bastion, a database, two target machines.
#
# Builds the binary, generates its own keys and secrets, migrates the
# schema, registers the two demo machines by their real host keys, seeds
# a user and a role, and prints a link that signs you in.
#
# Nothing here is production shape — deploy/quickstart/README.md says
# what changes when it is.
set -euo pipefail

cd "$(dirname "$0")/../deploy/quickstart"

STATE=".state"
ENV_FILE=".env"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# ⚠️ ÇIKTIYI YUTMUYORUZ, ERTELİYORUZ. Adımların çıktısı sessiz kalırsa
# ilk on dakika temiz görünüyor; ama bir adım düştüğünde geriye hiçbir
# şey kalmıyordu. Burada çıktı tutuluyor ve YALNIZCA arızada basılıyor.
run() {
	local out
	if ! out="$("$@" 2>&1)"; then
		red "failed: $*"
		printf '%s\n' "$out" >&2
		exit 1
	fi
}

usage() {
	cat <<'USAGE'
postern quickstart

  ./scripts/quickstart.sh          bring everything up and print a sign-in link
  ./scripts/quickstart.sh --down   stop and remove everything it created

USAGE
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
--down)
	say "stopping"
	# -v: the database volume too. Everything this script makes is
	# disposable by design; a volume left behind would make the next
	# run start from a half-seeded schema.
	docker compose down -v --remove-orphans 2>/dev/null || true
	rm -rf "$STATE" "$ENV_FILE"
	say "gone"
	exit 0
	;;
"") ;;
*)
	red "unknown argument: $1"
	usage
	exit 2
	;;
esac

command -v docker >/dev/null || {
	red "docker is required"
	exit 1
}
docker compose version >/dev/null 2>&1 || {
	red "docker compose v2 is required"
	exit 1
}

# ⚠️ ÇALIŞAN BİR KURULUMUN ÜZERİNE YAZMIYORUZ. İkinci kez çalıştıran
# biri ilk kurulumun anahtarlarını ezerse, hedefler artık tanımadıkları
# bir CA'ya bakıyor olur ve arıza "bağlanamıyorum" diye görünür.
if [ -d "$STATE" ]; then
	red "$PWD/$STATE already exists — run './scripts/quickstart.sh --down' first"
	exit 1
fi

mkdir -p "$STATE/keys" "$STATE/recordings"

HTTP_PORT="${POSTERN_HTTP_PORT:-8088}"
SSH_PORT="${POSTERN_SSH_PORT:-2222}"

# ⚠️ HER KURULUM KENDİ PAROLASINI ÜRETİYOR. Depoda duran sabit bir
# parola, onu değiştirmeyi unutan herkesin kurulumunda aynı olurdu.
{
	echo "POSTERN_DB_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"
	echo "POSTERN_HTTP_PORT=$HTTP_PORT"
	echo "POSTERN_SSH_PORT=$SSH_PORT"
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"

say "building images (the first run takes a few minutes)"
docker compose build --quiet

# Hedefler CA'nın AÇIK anahtarını bağlıyor, dolayısıyla anahtarlar
# konteynerler ayağa kalkmadan önce üretilmeli.
say "generating CA, host key and master key"
run docker compose run --rm --no-deps --entrypoint postern postern \
	ca init --key /var/lib/postern/keys/ca_ed25519
# ⚠️ CA AÇIK ANAHTARI, HEDEF KONTEYNERİNDEN ÖNCE YAZILMALI. compose bu
# dosyayı hedeflere bind-mount ediyor ve Docker, olmayan bir kaynak yolu
# DİZİN olarak yaratıyor: sırayı ters çevirince `ca show` bir dizine
# yazmaya çalışıp düşüyor (ölçüldü).
docker compose run --rm --no-deps --entrypoint postern postern \
	ca show --key /var/lib/postern/keys/ca_ed25519 2>/dev/null >"$STATE/keys/ca_ed25519.pub"
test -s "$STATE/keys/ca_ed25519.pub" || {
	red "the CA public key did not land in $STATE/keys/ca_ed25519.pub"
	exit 1
}

# ⚠️ Durum dizini demo-a'ya AYRICA bağlanıyor: hedef imajında ssh-keygen
# var, postern imajında yok, ama .state yalnızca postern'e bağlı.
run docker compose run --rm --no-deps --entrypoint ssh-keygen \
	-v "$PWD/$STATE:/state" demo-a -t ed25519 -N '' -q -f /state/keys/host_ed25519

# ⚠️ EN SONA: `secret init` config'in TAMAMINI doğruluyor ve host
# anahtarının dosyada durmasını istiyor (ölçüldü). Sırayı bozmak,
# "config geçersiz" diye görünen ama aslında sıra hatası olan bir
# arıza veriyor.
run docker compose run --rm --no-deps --entrypoint postern postern \
	secret init --config /etc/postern/postern.yaml

say "starting the database"
docker compose up -d db
docker compose run --rm --entrypoint postern postern \
	db migrate --config /etc/postern/postern.yaml >/dev/null

say "starting the bastion and two demo machines"
docker compose up -d postern demo-a demo-b

say "waiting for the panel"
for _ in $(seq 1 60); do
	curl -fsS -o /dev/null "http://127.0.0.1:$HTTP_PORT/healthz" 2>/dev/null && break
	sleep 1
done
curl -fsS -o /dev/null "http://127.0.0.1:$HTTP_PORT/healthz" || {
	red "the panel did not come up — docker compose -f deploy/quickstart/compose.yaml logs postern"
	exit 1
}

# ⚠️ HEDEFLER GERÇEK HOST ANAHTARIYLA KAYDEDİLİYOR. postern hedefin
# anahtarını sabitliyor; "ilk bağlantıda ne gelirse onu kabul et", araya
# girenin ilk bağlantıda kazanması demekti.
say "registering the demo machines by their host keys"
for m in demo-a demo-b; do
	for _ in $(seq 1 30); do
		docker compose exec -T "$m" test -s /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null && break
		sleep 1
	done
	docker compose exec -T "$m" cat /etc/ssh/ssh_host_ed25519_key.pub >"$STATE/$m.pub"
done

pg() {
	docker compose run --rm --entrypoint postern postern "$@" --config /etc/postern/postern.yaml
}

pg target add --name demo-a --host demo-a --port 22 \
	--host-key-file /var/lib/postern/demo-a.pub >/dev/null
pg target add --name demo-b --host demo-b --port 22 \
	--host-key-file /var/lib/postern/demo-b.pub >/dev/null
pg role add --name developer --target demo-a --target demo-b >/dev/null

# ⚠️ DEMO BİR RET ÜRETMELİ. Kural yazmayan bir rol her yola erişiyor ve
# ilk on dakikada postern'in ayırt edici tarafı — reddettiğini sayıp
# listede göstermesi — hiç görünmüyor. Ev dizini açık, gerisi kapalı:
# `get /etc/shadow` artık HEDEFİN izin hatası değil, POSTERN'İN reddi
# olarak deftere giriyor.
pg role path set --role developer --prefix /home/ayse --write >/dev/null
pg role path set --role developer --prefix / --deny >/dev/null

say "creating a demo user"
ssh-keygen -t ed25519 -N '' -q -f "$STATE/demo_key"
pg user add --name ayse --os-user ayse --role developer \
	--key /var/lib/postern/demo_key.pub >/dev/null

say "creating the administrator"
ADMIN_OUT="$(pg admin bootstrap --name admin --os-user veli 2>&1 || true)"
ADMIN_PASSWORD="$(printf '%s\n' "$ADMIN_OUT" | grep -Eo '[A-Z0-9]{2,}(-[A-Z0-9]{2,}){3,}' | head -1)"

cat <<INFO

  postern is up.

  Panel      http://127.0.0.1:$HTTP_PORT
  Sign in    admin / ${ADMIN_PASSWORD:-"(see the output above)"}

  Open a recorded SSH session as the demo user:

    ssh -i deploy/quickstart/$STATE/demo_key -o User=ayse:demo-a -p $SSH_PORT 127.0.0.1

  Move a file over SFTP — it lands in the session's file journal:

    sftp -i deploy/quickstart/$STATE/demo_key -o User=ayse:demo-a -P $SSH_PORT 127.0.0.1

  Then open the panel: Sessions has the recording, and the Evidence column
  flags anything postern refused or could not write down.

  Stop and remove everything:  ./scripts/quickstart.sh --down

INFO

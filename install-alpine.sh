#!/bin/sh
# Installe (ou met à jour) infos.broker comme service OpenRC sur Alpine Linux.
# Usage : sudo sh install-alpine.sh            (depuis le dossier du projet)
#         sudo sh install-alpine.sh /chemin/vers/infos-broker
#
# Relancer le script = recompiler, mettre à jour et redémarrer le service.
# Le fichier /opt/infos-broker/.env existant est toujours conservé.
set -eu

SERVICE="infos-broker"
BIN_NAME="infos-broker-mailer"
APP_USER="infosbroker"
APP_DIR="/opt/infos-broker"
LOG_DIR="/var/log/infos-broker"
SRC_DIR="${1:-$(pwd)}"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Lancez ce script en root (sudo ou doas)."
[ -f /etc/alpine-release ] || die "Ce script est prévu pour Alpine Linux."
[ -f "$SRC_DIR/Cargo.toml" ] || die "Cargo.toml introuvable dans $SRC_DIR"

# 1. Dépendances de compilation
say "Installation des dépendances (rust, cargo, openssl)…"
apk add --no-cache rust cargo build-base pkgconf openssl-dev ca-certificates >/dev/null

# 2. Compilation
say "Compilation en mode release (peut prendre quelques minutes)…"
cd "$SRC_DIR"
cargo build --release
[ -x "target/release/$BIN_NAME" ] || die "Binaire introuvable après compilation."

# 3. Utilisateur système dédié
if ! id "$APP_USER" >/dev/null 2>&1; then
  say "Création de l'utilisateur système $APP_USER…"
  addgroup -S "$APP_USER"
  adduser -S -D -H -h "$APP_DIR" -s /sbin/nologin -G "$APP_USER" "$APP_USER"
fi

# 4. Arrêt du service s'il tourne (mise à jour)
if rc-service "$SERVICE" status >/dev/null 2>&1; then
  say "Arrêt du service en cours…"
  rc-service "$SERVICE" stop || true
fi

# 5. Installation des fichiers
say "Installation dans $APP_DIR…"
install -m 0755 "target/release/$BIN_NAME" "/usr/local/bin/$BIN_NAME"
mkdir -p "$APP_DIR/static" "$LOG_DIR"
cp -r static/. "$APP_DIR/static/"

if [ -f "$APP_DIR/.env" ]; then
  say "Fichier .env existant conservé."
elif [ -f "$SRC_DIR/.env" ]; then
  cp "$SRC_DIR/.env" "$APP_DIR/.env"
  say "Fichier .env copié depuis $SRC_DIR."
else
  cp "$SRC_DIR/.env.example" "$APP_DIR/.env"
  warn "Aucun .env trouvé : .env.example copié. Éditez $APP_DIR/.env avant de démarrer."
fi

# Le .env contient le mot de passe SMTP : lisible uniquement par le service
sed -i 's|^STATIC_DIR=.*|STATIC_DIR=/opt/infos-broker/static|' "$APP_DIR/.env"
chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR"
chmod 0750 "$APP_DIR"
chmod 0600 "$APP_DIR/.env"

# 6. Script OpenRC
say "Création du service OpenRC /etc/init.d/$SERVICE…"
cat > "/etc/init.d/$SERVICE" <<EOF
#!/sbin/openrc-run

name="$SERVICE"
description="infos.broker — formulaire et envoi d'e-mails"

command="/usr/local/bin/$BIN_NAME"
command_user="$APP_USER:$APP_USER"
directory="$APP_DIR"

supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0

output_log="$LOG_DIR/$SERVICE.log"
error_log="$LOG_DIR/$SERVICE.log"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --owner $APP_USER:$APP_USER --mode 0750 "$LOG_DIR"
    checkpath --file --owner $APP_USER:$APP_USER --mode 0640 "$LOG_DIR/$SERVICE.log"
    if [ ! -f "$APP_DIR/.env" ]; then
        eerror "Fichier $APP_DIR/.env manquant"
        return 1
    fi
}
EOF
chmod 0755 "/etc/init.d/$SERVICE"

# 7. Rotation des logs (si logrotate est installé)
if [ -d /etc/logrotate.d ]; then
  cat > "/etc/logrotate.d/$SERVICE" <<EOF
$LOG_DIR/*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
EOF
fi

# 8. Activation au démarrage + lancement
rc-update add "$SERVICE" default >/dev/null 2>&1 || true

if grep -q '^SMTP_USER=votre-identifiant-smtp' "$APP_DIR/.env"; then
  warn "Le .env contient encore les valeurs d'exemple : service activé mais NON démarré."
  warn "1) nano $APP_DIR/.env   2) rc-service $SERVICE start"
  exit 0
fi

say "Démarrage du service…"
rc-service "$SERVICE" start
sleep 2

if rc-service "$SERVICE" status >/dev/null 2>&1; then
  say "Service actif. Dernières lignes du log :"
  tail -n 5 "$LOG_DIR/$SERVICE.log" 2>/dev/null || true
  PORT=$(grep '^BIND_ADDR=' "$APP_DIR/.env" | sed 's/.*://' || echo 8080)
  printf '\nTest : curl http://127.0.0.1:%s/health\n' "${PORT:-8080}"
else
  die "Le service ne démarre pas. Consultez : tail -n 50 $LOG_DIR/$SERVICE.log"
fi

cat <<EOF

Commandes utiles :
  rc-service $SERVICE status | start | stop | restart
  tail -f $LOG_DIR/$SERVICE.log
  nano $APP_DIR/.env   (puis rc-service $SERVICE restart)
EOF

#!/usr/bin/env sh
set -eu

BIN_SOURCE="./homepki"
CONFIG_SOURCE="./appliance.example.yaml"
AVAHI_SOURCE="./avahi-homepki.service"
MIGRATIONS_SOURCE="./migrations"
PLATFORM_SOURCE="./platform"
BIN_TARGET="/usr/local/bin/homepki"
CONFIG_DIR="/etc/homepki"
CONFIG_TARGET="/etc/homepki/config.yaml"
STATE_DIR="/var/lib/homepki"
SYSTEMD_UNIT="/etc/systemd/system/homepki.service"
STEP_SYSTEMD_UNIT="/etc/systemd/system/homepki-step-ca.service"
SUDOERS_FILE="/etc/sudoers.d/homepki"

if [ ! -f "$BIN_SOURCE" ]; then
  echo "missing binary: $BIN_SOURCE" >&2
  exit 1
fi

if [ ! -f "$CONFIG_SOURCE" ]; then
  echo "missing example config: $CONFIG_SOURCE" >&2
  exit 1
fi

if [ ! -d "$MIGRATIONS_SOURCE" ]; then
  echo "missing migrations directory: $MIGRATIONS_SOURCE" >&2
  exit 1
fi
if [ ! -f "$AVAHI_SOURCE" ]; then
  echo "missing Avahi service file: $AVAHI_SOURCE" >&2
  exit 1
fi

if [ ! -f "$PLATFORM_SOURCE" ]; then
  echo "missing platform metadata: $PLATFORM_SOURCE" >&2
  exit 1
fi

PLATFORM_OS=$(cut -d/ -f1 "$PLATFORM_SOURCE")
PLATFORM_ARCH=$(cut -d/ -f2 "$PLATFORM_SOURCE")
if [ "$PLATFORM_OS" != "$(uname -s | tr '[:upper:]' '[:lower:]')" ]; then
  echo "this installer package targets $PLATFORM_OS, not $(uname -s)" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64 | amd64) HOST_ARCH=amd64 ;;
  aarch64 | arm64) HOST_ARCH=arm64 ;;
  *) HOST_ARCH=$(uname -m) ;;
esac
if [ "$PLATFORM_ARCH" != "$HOST_ARCH" ]; then
  echo "this installer package targets $PLATFORM_ARCH, not $HOST_ARCH" >&2
  exit 1
fi

for required_command in step step-ca ykman pkcs11-tool sudo systemctl; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "missing required command: $required_command" >&2
    exit 1
  fi
done

STEP_BINARY=$(command -v step)
STEP_CA_BINARY=$(command -v step-ca)
YKMAN_BINARY=$(command -v ykman)
PKCS11_TOOL_BINARY=$(command -v pkcs11-tool)
SUDO_BINARY=$(command -v sudo)
SYSTEMCTL_BINARY=$(command -v systemctl)

if ! "$STEP_BINARY" kms --help >/dev/null 2>&1; then
  echo "missing Step KMS plugin: install step-kms-plugin before installing HomePKI" >&2
  exit 1
fi

PKCS11_LIBRARY=${HOMEPKI_PKCS11_LIBRARY:-}
if [ -z "$PKCS11_LIBRARY" ] && command -v ldconfig >/dev/null 2>&1; then
  PKCS11_LIBRARY=$(ldconfig -p 2>/dev/null | awk '/libykcs11\.so/ { print $NF; exit }')
fi
if [ -z "$PKCS11_LIBRARY" ]; then
  PKCS11_LIBRARY=$(find /usr/lib /lib -type f -name 'libykcs11.so*' 2>/dev/null | head -n 1)
fi
if [ -z "$PKCS11_LIBRARY" ] || [ ! -e "$PKCS11_LIBRARY" ]; then
  echo "missing YubiKey PKCS#11 library; install libykcs11 or set HOMEPKI_PKCS11_LIBRARY" >&2
  exit 1
fi

if ! id -u homepki >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin homepki
fi
if getent group plugdev >/dev/null 2>&1; then
  usermod -aG plugdev homepki
fi

install -d -m 0750 -o root -g homepki "$CONFIG_DIR"
install -d -m 0700 -o homepki -g homepki "$STATE_DIR" "$STATE_DIR/migrations"
install -m 0755 "$BIN_SOURCE" "$BIN_TARGET"
if [ ! -f "$CONFIG_TARGET" ]; then
  sed \
    -e "s|__STEP_BINARY__|$STEP_BINARY|g" \
    -e "s|__STEP_CA_BINARY__|$STEP_CA_BINARY|g" \
    -e "s|__SUDO_BINARY__|$SUDO_BINARY|g" \
    -e "s|__SYSTEMCTL_BINARY__|$SYSTEMCTL_BINARY|g" \
    -e "s|__YKMAN_BINARY__|$YKMAN_BINARY|g" \
    -e "s|__PKCS11_TOOL_BINARY__|$PKCS11_TOOL_BINARY|g" \
    -e "s|__PKCS11_LIBRARY__|$PKCS11_LIBRARY|g" \
    "$CONFIG_SOURCE" > "$CONFIG_TARGET"
else
  echo "Keeping existing config: $CONFIG_TARGET"
fi
chown root:homepki "$CONFIG_TARGET"
chmod 0640 "$CONFIG_TARGET"
install -m 0600 "$MIGRATIONS_SOURCE"/*.sql "$STATE_DIR/migrations/"
chown -R homepki:homepki "$STATE_DIR/migrations"
if [ -d "/etc/avahi/services" ]; then
  install -m 0644 "$AVAHI_SOURCE" "/etc/avahi/services/homepki.service"
fi

cat > "$SYSTEMD_UNIT" <<'UNIT'
[Unit]
Description=HomePKI Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=homepki
Group=homepki
WorkingDirectory=/var/lib/homepki
ExecStart=/usr/local/bin/homepki -config /etc/homepki/config.yaml
Restart=on-failure
UMask=0077
ProtectSystem=full
ReadWritePaths=/var/lib/homepki

[Install]
WantedBy=multi-user.target
UNIT

cat > "$STEP_SYSTEMD_UNIT" <<'UNIT'
[Unit]
Description=HomePKI Step CA
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=homepki
Group=homepki
WorkingDirectory=/var/lib/homepki
ExecStart=$STEP_CA_BINARY /var/lib/homepki/.step/config/ca.json --password-file /etc/homepki/provisioner-password
Restart=on-failure
UMask=0077
ProtectSystem=full
ReadWritePaths=/var/lib/homepki

[Install]
WantedBy=multi-user.target
UNIT

cat > "$SUDOERS_FILE" <<SUDOERS
homepki ALL=(root) NOPASSWD: $SYSTEMCTL_BINARY start homepki-step-ca.service, $SYSTEMCTL_BINARY stop homepki-step-ca.service, $SYSTEMCTL_BINARY restart homepki.service
SUDOERS
chmod 0440 "$SUDOERS_FILE"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable homepki.service
fi

echo "HomePKI installer completed."
echo "Create /etc/homepki/provisioner-password, review $CONFIG_TARGET, then run: systemctl start homepki.service"

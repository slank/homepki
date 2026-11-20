#!/usr/bin/env sh
set -eu

TARGET_BIN="/usr/local/bin/homepki"
BACKUP_BIN="/usr/local/bin/homepki.previous"

if [ ! -f "$BACKUP_BIN" ]; then
  echo "rollback binary not found: $BACKUP_BIN" >&2
  exit 1
fi

install -m 0755 "$BACKUP_BIN" "$TARGET_BIN"

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart homepki.service
fi

echo "HomePKI rolled back using $BACKUP_BIN"

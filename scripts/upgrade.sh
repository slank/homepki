#!/usr/bin/env sh
set -eu

if [ $# -ne 1 ]; then
  echo "usage: $0 <new-binary-path>" >&2
  exit 1
fi

NEW_BIN="$1"
TARGET_BIN="/usr/local/bin/homepki"
BACKUP_BIN="/usr/local/bin/homepki.previous"

if [ ! -f "$NEW_BIN" ]; then
  echo "new binary not found: $NEW_BIN" >&2
  exit 1
fi

if [ -f "$TARGET_BIN" ]; then
  cp "$TARGET_BIN" "$BACKUP_BIN"
fi

install -m 0755 "$NEW_BIN" "$TARGET_BIN"

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart homepki.service
fi

echo "HomePKI upgraded. Rollback binary saved to $BACKUP_BIN"

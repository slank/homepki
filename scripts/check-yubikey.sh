#!/usr/bin/env sh
set -eu

YKMAN_BIN=${YKMAN_BIN:-$(command -v ykman 2>/dev/null || true)}
REQUESTED_SERIAL=${1:-}

if [ -z "$YKMAN_BIN" ] || [ ! -x "$YKMAN_BIN" ]; then
  echo "FAIL: ykman is not installed or is not executable." >&2
  echo "Install YubiKey Manager, then run this script again." >&2
  exit 2
fi

device_count=$("$YKMAN_BIN" list 2>/dev/null | awk 'NF { count++ } END { print count+0 }')
if [ "$device_count" -eq 0 ]; then
  echo "FAIL: no YubiKey was detected." >&2
  echo "Insert one YubiKey and run this script again." >&2
  exit 1
fi
if [ "$device_count" -gt 1 ] && [ -z "$REQUESTED_SERIAL" ]; then
  echo "FAIL: $device_count YubiKeys were detected." >&2
  echo "Keep one inserted, or pass its serial as the first argument." >&2
  exit 2
fi

if [ -n "$REQUESTED_SERIAL" ]; then
  serial=$REQUESTED_SERIAL
  if ! "$YKMAN_BIN" list | awk -v expected="$serial" 'index($0, "Serial: " expected) { found=1 } END { exit !found }'; then
    echo "FAIL: requested serial $serial was not detected." >&2
    exit 1
  fi
else
  serial=$("$YKMAN_BIN" list --serials | awk 'NF { print; exit }')
fi

info=$("$YKMAN_BIN" --device "$serial" info 2>/dev/null) || {
  echo "FAIL: could not read YubiKey information for serial $serial." >&2
  exit 1
}

model=$(printf '%s\n' "$info" | sed -n 's/^Device type:[[:space:]]*//p' | head -n 1)
firmware=$(printf '%s\n' "$info" | sed -n 's/^Firmware version:[[:space:]]*//p' | head -n 1)
interfaces=$(printf '%s\n' "$info" | sed -n 's/^Enabled USB interfaces:[[:space:]]*//p' | head -n 1)
piv_line=$(printf '%s\n' "$info" | sed -n 's/^[[:space:]]*PIV[[:space:]]*//p' | head -n 1)

echo "YubiKey serial: $serial"
echo "Model: ${model:-unknown}"
echo "Firmware: ${firmware:-unknown}"
echo "Enabled USB interfaces: ${interfaces:-unknown}"
echo "PIV capability: ${piv_line:-not reported}"

if [ "$piv_line" != "Enabled" ]; then
  echo "FAIL: this YubiKey does not expose PIV/CCID for HomePKI." >&2
  echo "No settings were changed." >&2
  exit 1
fi

if ! piv_info=$("$YKMAN_BIN" --device "$serial" piv info 2>&1); then
  echo "FAIL: ykman reports PIV as enabled, but PIV could not be read." >&2
  printf '%s\n' "$piv_info" >&2
  exit 1
fi

echo "PIV read check: PASS"
echo "$piv_info" | sed 's/^/  /'
echo "PASS: this YubiKey has the PIV/CCID capability required by HomePKI."
echo "No settings, PINs, keys, or certificates were changed."

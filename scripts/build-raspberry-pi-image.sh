#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
RPI_IMAGE_GEN_DIR=${RPI_IMAGE_GEN_DIR:-"$ROOT_DIR/.build/rpi-image-gen"}
VERSION=${VERSION:-dev}
INSTALLER_ARCHIVE="$ROOT_DIR/dist/homepki-installer-linux-arm64.tar.gz"
OUTPUT_IMAGE="$ROOT_DIR/dist/homepki-$VERSION-raspberry-pi-zero2w-arm64.img"
OUTPUT_ARCHIVE="$OUTPUT_IMAGE.xz"

if [ ! -x "$RPI_IMAGE_GEN_DIR/rpi-image-gen" ]; then
  echo "rpi-image-gen is required at $RPI_IMAGE_GEN_DIR" >&2
  exit 1
fi
if [ ! -f "$INSTALLER_ARCHIVE" ]; then
  echo "missing ARM64 installer archive: $INSTALLER_ARCHIVE" >&2
  exit 1
fi
if ! command -v xz >/dev/null 2>&1; then
  echo "xz is required to compress the Raspberry Pi image" >&2
  exit 1
fi

(
  cd "$RPI_IMAGE_GEN_DIR"
  ./rpi-image-gen build \
    -S "$ROOT_DIR/image" \
    -c "$ROOT_DIR/image/homepki.yaml" \
    -- "IGconf_homepki_installer=$INSTALLER_ARCHIVE"
)

IMAGE_PATH="$RPI_IMAGE_GEN_DIR/work/image-homepki-raspberry-pi/homepki-raspberry-pi.img"
if [ ! -f "$IMAGE_PATH" ]; then
  echo "rpi-image-gen did not produce the expected image: $IMAGE_PATH" >&2
  exit 1
fi

mkdir -p "$ROOT_DIR/dist"
cp "$IMAGE_PATH" "$OUTPUT_IMAGE"
xz -9 -T0 -f "$OUTPUT_IMAGE"
printf '%s\n' "$OUTPUT_ARCHIVE"

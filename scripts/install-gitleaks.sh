#!/bin/bash
# Rock House — Gitleaks Installer (Linux/Mac)
# Downloads latest gitleaks binary with SHA256 verification
# Usage: bash install-gitleaks.sh

set -e

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

LATEST=$(curl -sL "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
  echo "Failed to fetch latest version. Check your internet connection."
  exit 1
fi
VERSION="${LATEST#v}"

FILENAME="gitleaks_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/gitleaks/gitleaks/releases/download/${LATEST}/${FILENAME}"
CHECKSUM_URL="https://github.com/gitleaks/gitleaks/releases/download/${LATEST}/gitleaks_${VERSION}_checksums.txt"

echo "Downloading gitleaks ${VERSION} for ${OS}/${ARCH}..."
curl -sL "$URL" -o "/tmp/$FILENAME"
curl -sL "$CHECKSUM_URL" -o "/tmp/checksums.txt"

EXPECTED=$(grep "$FILENAME" /tmp/checksums.txt | awk '{print $1}')
ACTUAL=$(sha256sum "/tmp/$FILENAME" | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA256 mismatch! Expected: $EXPECTED Got: $ACTUAL"
  echo "Download may be corrupted or tampered with. Aborting."
  rm -f "/tmp/$FILENAME" "/tmp/checksums.txt"
  exit 1
fi

echo "SHA256 verified."
tar -xzf "/tmp/$FILENAME" -C "$INSTALL_DIR" gitleaks
chmod +x "$INSTALL_DIR/gitleaks"
rm -f "/tmp/$FILENAME" "/tmp/checksums.txt"

if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  echo "Add to your PATH: export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo "gitleaks ${VERSION} installed to $INSTALL_DIR/gitleaks"
"$INSTALL_DIR/gitleaks" version

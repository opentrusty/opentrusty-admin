#!/bin/bash
set -e

# install.sh - OpenTrusty Admin Plane Installer
# Purpose: Installs opentrusty-admin binary and systemd unit.

COMPONENT="admin"
BINARY_NAME="opentrusty-admin"
SERVICE_NAME="opentrusty-admin"

# 1. Root check
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root."
  exit 1
fi

echo "Installing OpenTrusty ${COMPONENT}..."

# 2. Copy binary
if [ -f "./${BINARY_NAME}" ]; then
  cp "./${BINARY_NAME}" /usr/local/bin/
  chmod +x /usr/local/bin/${BINARY_NAME}
  echo "✓ Installed ${BINARY_NAME} to /usr/local/bin/"
else
  echo "Error: Binary ${BINARY_NAME} not found in current directory."
  exit 1
fi

# 3. Create config directory
mkdir -p /etc/opentrusty
echo "✓ Config directory /etc/opentrusty/ exists."

# 4. Install systemd unit
if [ -d "./systemd" ] && [ -f "./systemd/${SERVICE_NAME}.service" ]; then
  cp "./systemd/${SERVICE_NAME}.service" /etc/systemd/system/
  echo "✓ Installed systemd unit to /etc/systemd/system/${SERVICE_NAME}.service"
  
  # 5. Reload systemd
  systemctl daemon-reload
  echo "✓ systemd daemon reloaded."
else
  echo "Warning: systemd unit not found. Skipping service installation."
fi

echo ""
echo "Installation complete!"
echo "Next steps:"
echo "1. Create /etc/opentrusty/shared.env and /etc/opentrusty/${COMPONENT}.env (see .env.example)"
echo "2. Ensure the 'opentrusty' user exists: useradd -r -s /bin/false opentrusty"
echo "3. Ensure /var/lib/opentrusty exists and is owned by opentrusty"
echo "4. Start the service: systemctl enable --now ${SERVICE_NAME}"
echo ""

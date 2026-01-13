#!/bin/bash
set -e

# uninstall.sh - OpenTrusty Admin Plane Uninstaller
# Purpose: Removes opentrusty-admin binary, systemd unit, and optionally configurations.

COMPONENT="admin"
BINARY_NAME="opentrusty-admind"
SERVICE_NAME="opentrusty-admind"
CONFIG_DIR="/etc/opentrusty"
DATA_DIR="/var/lib/opentrusty"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# 1. Root check
if [ "$EUID" -ne 0 ]; then
  log_error "This script must be run as root."
  exit 1
fi

# Detect interactive mode
INTERACTIVE=false
if [ -t 0 ]; then INTERACTIVE=true; fi

# Support force flag
FORCE_REMOVE=${FORCE_REMOVE:-false}

echo "Uninstalling OpenTrusty ${COMPONENT}..."
echo ""

# 2. Stop and disable service
if systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
  log_info "Stopping and disabling ${SERVICE_NAME}..."
  systemctl stop "${SERVICE_NAME}" || true
  systemctl disable "${SERVICE_NAME}" || true
  rm -f /etc/systemd/system/${SERVICE_NAME}.service
  systemctl daemon-reload
  log_info "Removed systemd unit."
else
  log_info "No systemd unit found for ${SERVICE_NAME}."
fi

# 3. Remove binary
if [ -f "/usr/local/bin/${BINARY_NAME}" ]; then
  rm -f "/usr/local/bin/${BINARY_NAME}"
  log_info "Removed binary /usr/local/bin/${BINARY_NAME}"
fi

# 4. Optional: Remove config and data
REMOVE_ALL="n"
if [ "$INTERACTIVE" = true ] && [ "$FORCE_REMOVE" = false ]; then
  read -p "Do you want to remove configuration and data in ${CONFIG_DIR} and ${DATA_DIR}? (y/N): " REMOVE_ALL
elif [ "$FORCE_REMOVE" = true ]; then
  REMOVE_ALL="y"
fi

if [[ "$REMOVE_ALL" =~ ^[Yy]$ ]]; then
  # We only remove the component-specific env file to avoid breaking other planes
  # unless they also want to remove everything.
  rm -f "${CONFIG_DIR}/${COMPONENT}.env"
  log_info "Removed ${CONFIG_DIR}/${COMPONENT}.env"
  
  # Remove data directory
  rm -rf "${DATA_DIR}"
  log_info "Removed data directory ${DATA_DIR}"
  
  # Check if config directory is empty, if so remove it
  if [ -d "${CONFIG_DIR}" ] && [ -z "$(ls -A ${CONFIG_DIR})" ]; then
    rm -rf "${CONFIG_DIR}"
    log_info "Removed empty config directory ${CONFIG_DIR}"
  fi
else
  log_info "Preserved configuration and data."
fi

echo ""
log_info "OpenTrusty ${COMPONENT} uninstallation complete."

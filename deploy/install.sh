#!/bin/bash
set -e

# install.sh - OpenTrusty Admin Plane Installer
# Purpose: Installs opentrusty-admin binary and systemd unit with production-ready checks.

COMPONENT="admin"
BINARY_NAME="opentrusty-admind"
SERVICE_NAME="opentrusty-admind"
CONFIG_DIR="/etc/opentrusty"
DATA_DIR="/var/lib/opentrusty"
SERVICE_USER="opentrusty"
VERSION="dev"

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

echo "Installing OpenTrusty ${COMPONENT}..."
echo ""

# 2. Pre-flight checks
echo "Running pre-flight checks..."

# Check if systemd is available
if ! command -v systemctl &> /dev/null; then
  log_warn "systemctl not found. Systemd service installation will be skipped."
  SKIP_SYSTEMD=true
fi

# Check/create service user
if id "${SERVICE_USER}" &>/dev/null; then
  log_info "Service user '${SERVICE_USER}' already exists."
else
  useradd -r -s /bin/false "${SERVICE_USER}"
  log_info "Created service user '${SERVICE_USER}'."
fi

# 3. Copy binary
if [ -f "./${BINARY_NAME}" ]; then
  cp "./${BINARY_NAME}" /usr/local/bin/
  chmod +x /usr/local/bin/${BINARY_NAME}
  log_info "Installed ${BINARY_NAME} to /usr/local/bin/"
else
  log_error "Binary ${BINARY_NAME} not found in current directory."
  exit 1
fi

# 4. Create config directory and data directory
mkdir -p "${CONFIG_DIR}"
log_info "Config directory ${CONFIG_DIR}/ exists."

mkdir -p "${DATA_DIR}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
log_info "Data directory ${DATA_DIR}/ exists and owned by ${SERVICE_USER}."

# 4. Create version file
echo "$VERSION" > "${CONFIG_DIR}/${COMPONENT}.version"
log_info "Recorded version $VERSION in ${CONFIG_DIR}/${COMPONENT}.version"

# 5. Install environment config
if [ -f "./.env.example" ]; then
  ENV_FILE="${CONFIG_DIR}/${COMPONENT}.env"
  if [ ! -f "$ENV_FILE" ]; then
    cp "./.env.example" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    chown "${SERVICE_USER}:${SERVICE_USER}" "$ENV_FILE"
    log_info "Installed new config to $ENV_FILE"
    log_warn "IMPORTANT: Edit $ENV_FILE with production values!"
  else
    log_info "Config file $ENV_FILE already exists. Migrating new variables..."
    # Migration logic: append variables from .env.example that are missing in .env
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Skip comments and empty lines
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ "$line" =~ ^[[:space:]]*$ ]] && continue
      
      VAR_NAME=$(echo "$line" | cut -d'=' -f1)
      if ! grep -q "^${VAR_NAME}=" "$ENV_FILE"; then
        echo "$line" >> "$ENV_FILE"
        log_info "Migrated missing variable: $VAR_NAME"
      fi
    done < "./.env.example"
  fi
fi

# 6. Legacy shared.env cleanup (no longer used in autonomous plane model)
if [ -f "${CONFIG_DIR}/shared.env" ]; then
  log_warn "Found legacy shared.env. OpenTrusty now uses autonomous plane configuration."
  log_warn "Please ensure all required variables are in ${ENV_FILE}."
fi

# 7. Install systemd unit
if [ "$SKIP_SYSTEMD" != "true" ]; then
  if [ -d "./systemd" ] && [ -f "./systemd/${SERVICE_NAME}.service" ]; then
    cp "./systemd/${SERVICE_NAME}.service" /etc/systemd/system/
    log_info "Installed systemd unit to /etc/systemd/system/${SERVICE_NAME}.service"
    
    systemctl daemon-reload
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
      systemctl restart "${SERVICE_NAME}"
      log_info "Service ${SERVICE_NAME} restarted."
    fi
  else
    log_warn "systemd unit not found. Skipping service installation."
  fi
fi

echo ""
echo "============================================"
echo "Installation complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "1. Edit ${CONFIG_DIR}/${COMPONENT}.env with production values"
echo "   - Set OPENTRUSTY_DATABASE_URL"
echo "   - Set OPENTRUSTY_SESSION_SECRET (64-byte hex)"
echo "   - Set OPENTRUSTY_IDENTITY_SECRET (32-byte hex)"
echo ""
if [ "$SKIP_SYSTEMD" != "true" ]; then
  echo "2. Start the service:"
  echo "   sudo systemctl enable --now ${SERVICE_NAME}"
  echo ""
  echo "3. Check status:"
  echo "   sudo systemctl status ${SERVICE_NAME}"
  echo "   curl http://localhost:8081/health"
fi
echo ""


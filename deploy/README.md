# OpenTrusty Admin Plane Deployment

This package contains the OpenTrusty Administration Plane (admind), which provides the management API for tenants, users, and clients.

## Package Contents

- `opentrusty-admind`: The Go binary.
- `install.sh`: Automated installer script.
- `systemd/`: systemd unit files.
- `.env.example`: Example environment variables.
- `LICENSE`: Apache 2.0 license.

## Installation

1. Extract the tarball:
   ```bash
   tar -xzf opentrusty-admin-<version>-linux-amd64.tar.gz
   cd opentrusty-admin/
   ```

2. Run the installer as root:
   ```bash
   sudo ./install.sh
   ```

3. Configure environment variables in `/etc/opentrusty/admin.env` and `/etc/opentrusty/shared.env`.

4. Start the service:
   ```bash
   sudo systemctl enable --now opentrusty-admin
   ```

## Configuration

The Admin Plane requires connection to the OpenTrusty PostgreSQL database. Refer to `.env.example` for detailed variable descriptions.

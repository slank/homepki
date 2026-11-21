# Hardware Acceptance Checklist (Raspberry Pi Zero 2 W)

Raspberry Pi Zero 2 W is the reference appliance target. Repeat the same checklist on any supported `linux/arm64` or `linux/amd64` Debian-based system.

## Build and image

- [ ] `make cross-build` completes for `linux/arm64`
- [ ] `make cross-build-amd64` completes for `linux/amd64`
- [ ] `homepki -check-yubikey` reports `piv=enabled`
- [ ] `make source-package` produces a versioned source archive
- [ ] `make appliance-package` produces release tarball
- [ ] `make appliance-installer-package` produces installer tarball
- [ ] `scripts/build-raspberry-pi-image.sh` produces a compressed Zero 2 W image
- [ ] Release checksums cover every published artifact

## Boot and service

- [ ] Appliance boots on Pi Zero 2 W
- [ ] `homepki.service` starts automatically
- [ ] `/healthz` returns healthy status

## Setup and auth

- [ ] Setup wizard endpoint reports initial state
- [ ] Admin setup succeeds and creates authenticated session
- [ ] Login succeeds with valid credentials and fails with invalid credentials

## PKI and certificate flows

- [ ] Certificate issue flow stores inventory entry
- [ ] Certificate revoke requires destructive confirmation
- [ ] Certificate delete requires destructive confirmation

## Network behavior

- [ ] `homepki.local` resolves on local network when mDNS available
- [ ] fallback IP guidance is shown when mDNS is unavailable

## Recovery

- [ ] Backup archive is created and restorable
- [ ] Upgrade script preserves rollback binary
- [ ] Rollback script restores prior binary and service health

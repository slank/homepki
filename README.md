# HomePKI

HomePKI gives everyone a secure, reliable, and easy-to-use PKI system.

## Install and Configure a Device

- Start with `DEVICE_SETUP.md` for Raspberry Pi installation, network setup, HTTPS exposure, admin bootstrap, and client configuration.
- Use `configs/appliance.example.yaml` as the appliance configuration template.
- New to running a CA? Read `RUNNING_YOUR_OWN_CA.md` for an introduction to key handling, certificate types, validation, distribution, and backups.

## Project Goals

HomePKI is an application build on Step CA and Linux. Some goals of HomePKI are:
- Issue certificates for services on private domains such as `.local`.
- Issue client certificates for browsers, allowing VPN-like access to private resources.
- Issue private certificates for web servers via an ACME service.
- Integrate with Yubikey for cryptographic services.
- Provide web-based tools for managing and configuring certs and clients.
- Run on small, cheap computers like the Raspberry Pi Zero

## Development Commands

- `make generate` runs code generation.
- `make test` runs Go tests.
- `make lint` runs `go vet`.
- `make build` builds a local binary in `dist/`.
- `make cross-build` builds the `linux/arm64` release binary in `dist/`.
- `make cross-build-amd64` builds the `linux/amd64` release binary in `dist/`.
- `make source-package` creates a versioned source archive in `dist/`.
- `make appliance-package` creates an ARM64 release tarball in `dist/`.
- `make appliance-package-amd64` creates an AMD64 release tarball in `dist/`.
- `make appliance-installer-package` creates an installer tarball in `dist/`.
- `make appliance-installer-package-amd64` creates an amd64 installer tarball in `dist/`.
- `RPI_IMAGE_GEN_DIR=/path/to/rpi-image-gen make raspberry-pi-image` creates a compressed Raspberry Pi Zero 2 W image in `dist/`.
- `./dist/homepki -check-yubikey` checks connected-key PIV/CCID readiness without changing the device.

Set `TARGET_OS` and `TARGET_ARCH` with the `*-platform` targets for another supported Linux architecture.

## Releases

Releases are published from semantic version tags in the form `vMAJOR.MINOR.PATCH`. A tag triggers the release workflow, which runs validation and publishes:

- a versioned source archive
- Linux `arm64` and `amd64` binaries and installer archives
- a Raspberry Pi Zero 2 W 64-bit disk image
- SHA-256 checksums and an SBOM

The Raspberry Pi image bundles the matching installer but does not contain administrator credentials, CA keys, YubiKey PINs, or network secrets. Use Raspberry Pi Imager's customization options for SSH and network setup before first boot.

The first release is `v0.0.1`. To publish a release after its changes are merged and CI is green:

```sh
git tag v0.0.1
git push origin v0.0.1
```

Annotated or signed tags can carry a release message and signature. The version embedded in release binaries comes from the tag that triggered the workflow.

## Database Migrations

- `go run ./cmd/homepki -migrate -config configs/dev.yaml` applies pending migrations.
- `go run ./cmd/homepki -rollback 1 -config configs/dev.yaml` rolls back the latest migration step.

## Copilot Execution Helpers

- `COPILOT_WORK_QUEUE.md` is the plain-language task queue and status board.
- `COPILOT_TASK_PROMPT_TEMPLATE.md` is the reusable prompt format for each small task.

## Local Development (No YubiKey)

Use `configs/dev.yaml` for local development where a hardware YubiKey is not available yet.
This profile sets `require_yubikey: false` and uses a local SQLite path for early implementation work.

## Upgrade and Recovery

- `scripts/upgrade.sh /path/to/new/homepki` upgrades binary and restarts service.
- `scripts/rollback.sh` restores the previous binary.
- See `UPGRADE_AND_RECOVERY.md` for backup/restore and factory reset steps.

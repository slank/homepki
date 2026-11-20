# HomePKI Architecture

For installation and network configuration, see `DEVICE_SETUP.md`.

## Runtime Shape

A Go appliance application runs on a 64-bit Debian-based Linux system with systemd. Raspberry Pi OS Lite 64-bit on Raspberry Pi Zero 2 W is the reference release target, while the binary, installer, and configuration support both `arm64` and `amd64`.

Step CA supplies the private CA. OpenSSL or a PKCS#11 integration handles cryptographic operations, while SQLite stores appliance state, certificate inventory, and audit events.

## Components

- **Web application:** HTMX/Templ setup wizard, login, certificate forms, trust guidance, status, and recovery flows.
- **Appliance API:** Local session authentication, setup state, certificate inventory, configuration validation, and YubiKey action orchestration.
- **PKI service:** A Go boundary for provisioning the CA and issuing or revoking certificates. Manual issuance is the v1 implementation.
- **YubiKey adapter:** PIV/PKCS#11 discovery and signing operations, with explicit confirmation for sensitive actions.
- **Step CA:** Local CA provisioning and certificate issuance. Operational state remains local and is not exposed directly to the browser.
- **Step CA KMS:** With the appliance profile, root and intermediate signing keys are created in YubiKey PIV slots through the `step kms` plugin. The generated CA config references `yubikey:` key URIs and a root-only PIN file.
- **Setup UI:** Server-rendered pages guide administrator creation, YubiKey checks, CA provisioning, login, issuance, inventory, revocation, and trust setup.
- **SQLite:** Administrator credentials, configuration, setup progress, certificate metadata, and audit records.
- **Network services:** mDNS for `homepki.local`, local address fallback behavior, and systemd-managed startup and recovery.

## Security Boundaries

The browser communicates only with the Go application. The application requires a local administrator session, validates certificate names and lifetimes, and requires YubiKey presence and confirmation for sensitive signing actions. Private keys and CA material remain outside browser-accessible storage.

Sensitive operations and configuration changes are recorded in SQLite. Authentication, authorization, and input validation remain server-side; UI state is not trusted as a security boundary.

## Deployment

The Go binary can be compiled for `linux/arm64` or `linux/amd64` and runs under systemd. Static UI assets are embedded in the binary where practical. Step CA and supporting system dependencies are installed with an explicit installer; package and PKCS#11 paths are detected during installation. The appliance does not require a public internet service.

Backups include protected CA material, the SQLite database, and appliance configuration. Recovery flows should make key availability and backup requirements clear before destructive operations.

## Operation Flow

The setup wizard records progress and validates network and YubiKey prerequisites. CA provisioning creates the local CA and stores only operational metadata in SQLite.

Manual certificate issuance validates requested names and lifetimes, obtains the required YubiKey-protected signing action, and records the result and download metadata. Trust guidance provides Linux and macOS browser-specific instructions rather than attempting to modify host trust stores.

## v1 Boundaries

V1 supports guided setup, manual certificate issuance and download, local administrator authentication, YubiKey signing confirmation, and CA trust guidance. ACME, automated renewal, multi-user roles, public exposure, and broad hardware support remain future work.

The PKI service boundary should avoid hard-coding assumptions that certificates can only be issued manually, but no ACME implementation or scheduling decisions are required now.

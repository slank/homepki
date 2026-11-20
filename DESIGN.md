# HomePKI

HomePKI is an offline-first private PKI appliance for home and DIY self-hosted environments.

The first release targets a Raspberry Pi Zero 2 W with a required YubiKey for sensitive signing operations. The goal is to make private HTTPS certificate management accessible to novice users without requiring deep PKI knowledge.

## Vision

HomePKI should let a user:

1. Flash an image to storage
2. Boot the device on a local network
3. Open a browser to `homepki.local` (or fallback IP)
4. Complete a guided setup flow
5. Provision a local certificate authority (CA)
6. Install CA trust in supported browsers
7. Issue certificates for internal HTTPS services

## First Release Scope (v1)

### Platform and deployment

- Hardware target: **Raspberry Pi Zero 2 W**
- OS baseline: **Raspberry Pi OS Lite 64-bit**
- Network model: **local LAN appliance**
- Internet exposure: **not required and not intended**

### Security and authentication

- Single administrator account in v1
- Admin login: local username/password
- YubiKey is required for sensitive signing actions
- Multi-user and role-based permissions are planned for later versions

### Certificate workflows

- Provision a CA through guided setup
- Support user-owned local domains (for example: `*.home.example`)
- Install CA trust guidance for:
  - Linux browsers
  - macOS browsers
- Issue internal service certificates from the web interface
- Certificate issuance method in v1: **manual UI flow** (download cert/key bundles)
- ACME automation: **out of scope for v1** (planned later)

### Target use cases

HomePKI is designed for popular DIY/self-hosted services, including:

- smart home controllers and dashboards
- media and file services
- personal/internal web apps on a home network

## User Experience Principles

- Appliance-style setup with minimal manual steps
- Clear, novice-friendly language and guided decisions
- Safe defaults for cryptographic operations
- Predictable recovery paths for common setup failures
- Low operational overhead on low-power hardware

## Out of Scope for v1

- Internet-facing/public CA operation
- Multi-user role management in the first usable release
- Mandatory ACME support in the first usable release
- Broad multi-platform deployment beyond Pi Zero 2 W

## Roadmap (Post-v1 Direction)

- ACME-based automated issuance and renewal
- Multi-user management and role separation (e.g., issuer, signer)
- Expanded browser/device trust onboarding
- Additional supported hardware and Linux targets
- Operational tooling for backups, upgrades, and lifecycle management

## Project Status

Early planning stage. Requirements are being finalized before implementation begins.

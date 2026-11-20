# HomePKI v001 Implementation Roadmap

## Baseline Decisions

- Create a Go module targeting `linux/arm64`; keep the Raspberry Pi Zero 2 W as the hardware acceptance target.
- Use server-rendered Templ components and HTMX, with static assets embedded into the binary.
- Separate HTTP handlers, appliance services, PKI operations, YubiKey/PIV operations, network setup, and persistence behind interfaces.
- Keep ACME and multi-user concepts as future-facing interfaces, not v1 implementations.

## Milestone 1: Build and Repository Foundation

### Deliverables

- Add Go module structure: `cmd/homepki`, `internal/{web,pki,yubikey,network,storage,config}`, and `migrations/`.
- Establish pinned build and formatting tools: Go, Templ generation, migration tooling, linters, and vulnerability scanning.
- Add a `Makefile` or equivalent for:
  - generate
  - test
  - lint
  - build
  - cross-build
  - appliance image/installer package
- Add GitHub Actions workflows for pull requests and tagged releases.
- Introduce a local development configuration that does not require YubiKey hardware.

### Build Infrastructure

- Build natively for development and cross-compile release binaries for `linux/arm64`.
- Produce a reproducible binary with embedded assets and explicit version metadata.
- Resolve CGO requirements early by evaluating SQLite and PKCS#11 drivers; document the cross-compiler toolchain and Raspberry Pi OS compatibility.
- Release builds should generate SBOM, checksums, and reproducible metadata.

### Exit Criteria

- A PR validates formatting, generation, tests, linting, and an arm64 build.
- A tagged build produces an identifiable binary and release metadata.

## Milestone 2: Persistence and Appliance Foundation

### Deliverables

- SQLite connection management and versioned migrations.
- Storage for administrator credentials, setup state, configuration, certificate metadata, audit events, and download records.
- Argon2id or another deliberate password-hashing implementation with documented parameters.
- Server-side session authentication with secure cookies and CSRF protection.
- Central configuration validation and secrets handling.
- Audit every authentication and sensitive configuration/PKI operation.

### Exit Criteria

- A clean database initializes successfully.
- Migrations upgrade and roll back in isolated tests.
- Unauthorized API requests and invalid configuration changes are rejected.

## Milestone 3: Hardware and Setup Prerequisites

### Deliverables

- Implement YubiKey discovery and PKCS#11 capability detection behind a replaceable interface.
- Implement network prerequisite checks and safe fallback IP behavior.
- Implement a setup-state machine covering not initialized, prerequisites, CA provisioning, complete, and recoverable failure states.
- Add systemd unit generation and startup/recovery behavior.
- Configure mDNS for `homepki.local` while making fallback behavior explicit.

### Testing

- Mock PIV/PKCS#11 operations for normal and hardware-failure paths.
- Test setup-state transitions independently from browser handlers.
- Run Raspberry Pi smoke tests for service startup, network availability, PIV discovery, and systemd restart behavior.

### Exit Criteria

- Setup can resume after a restart or a recoverable prerequisite failure.

## Milestone 4: PKI Core

### Deliverables

- Implement a PKI service boundary for:
  - CA provisioning
  - certificate issuance
  - certificate metadata
  - revocation
  - future ACME/renewal adapters
- Integrate Step CA provisioning and persistent operational state.
- Make cryptographic operations explicit: YubiKey presence, touch/sign confirmation, and failure reporting.
- Validate DNS names, lifetime limits, request fields, and destructive-operation confirmation server-side.
- Store CA material only in protected appliance storage, never in SQLite or browser-visible locations.

### Testing

- Unit-test name and lifetime validation.
- Use an integration test PKI with temporary CA material and no real YubiKey.
- Contract-test the PKI interface so future ACME implementations cannot break existing issuance behavior.
- Exercise signing cancellation, absent keys, PIN failures, touch timeouts, and partial provisioning.

### Exit Criteria

- A service certificate can be issued and downloaded through an end-to-end integration test.
- No private key or CA material can be returned by an API or HTML response.

## Milestone 5: User Workflows

### Deliverables

- Guided setup wizard.
- Single-administrator login.
- CA status and setup recovery screens.
- Manual certificate issuance and download.
- Certificate inventory and revoke/delete workflows.
- Linux and macOS trust instructions.
- Explicit warnings for backup requirements and destructive setup operations.

### Testing

- Handler and HTMX fragment tests.
- Browser tests for setup, login, issuance, and recovery flows.
- Accessibility checks for the setup and signing-confirmation dialogs.
- Small-device browser testing and network-failure/error-state testing.

### Exit Criteria

- A novice user can complete setup and issue a certificate without shell access.
- Every destructive or sensitive action has server-side authorization and clear confirmation.

## Milestone 6: Appliance Packaging and Recovery

### Deliverables

- Raspberry Pi OS Lite appliance image or a documented installer, selecting one primary distribution mechanism for v1.
- Systemd-managed application startup and dependency ordering.
- A backup format containing protected CA material, SQLite data, and appliance configuration.
- Restore and factory-reset flows with confirmation and key-availability warnings.
- Documented upgrade and rollback procedure.

### Release Logistics

- Release candidate artifacts should include release notes, upgrade notes, checksums, SBOM, and hardware compatibility information.
- Sign or otherwise attest the appliance image and binary.
- Define a versioning and migration policy before the first public release.
- Ship one hardware-accepted release candidate with explicit acceptance evidence.

### Exit Criteria

- A clean image boots, initializes, and becomes reachable at `homepki.local` or its fallback address.
- Restore succeeds on replacement storage.
- Upgrade preserves certificates and recovers cleanly from migration failure.

## Recommended Delivery Sequence

1. Repository and build infrastructure.
2. SQLite, authentication, and audit foundations.
3. YubiKey and PKI service interfaces with mocks.
4. Setup state machine and systemd integration.
5. Real Step CA and YubiKey integration.
6. HTMX workflows and trust guidance.
7. Backup/restore and appliance image.
8. Hardware acceptance and release candidate.

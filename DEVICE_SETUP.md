# Device Setup and Network Configuration

HomePKI provides a server-rendered setup and administration interface, SQLite storage, authentication, audit logging, Step CA command integration, YubiKey/PKCS#11 checks, certificate inventory, backup, and packaging.

The Raspberry Pi Zero 2 W is the primary release target, but the software is not Pi-specific. This installer supports Debian-based `linux/arm64` and `linux/amd64` systems that use systemd. Other Linux service managers need a separate service file; macOS and Windows are supported for client/development use, not this appliance installer.

Do not expose the service directly to the internet.

## What you need

- A 64-bit Debian-based Linux system; Raspberry Pi Zero 2 W with Raspberry Pi OS Lite 64-bit is the reference target
- Network access to the trusted LAN
- SSH administration access
- An installer package matching the host:
  - `homepki-installer-linux-arm64.tar.gz`
  - `homepki-installer-linux-amd64.tar.gz`
- An HTTPS reverse proxy if users will access HomePKI from other devices
- `step-cli` and `step-ca`
- YubiKey Manager (`ykman`), `pkcs11-tool`, and the Yubico PKCS#11 library

Keep the HomePKI device on a trusted LAN. A private certificate service should not be reachable from the public internet.

## 1. Prepare the Linux host

1. Install a 64-bit Debian-based distribution. Raspberry Pi users can install Raspberry Pi OS Lite 64-bit.
2. Enable SSH and connect the host to the local network.
3. Set a hostname such as `homepki`.
4. Update the OS:

```sh
sudo apt update
sudo apt upgrade
```

5. Give the device a DHCP reservation in your router. Keep the reserved address stable so the fallback address does not change.

6. Install the runtime dependencies from supported distribution packages or release repositories:

- `step-cli`
- a CGO-enabled `step-ca` build with YubiKey PIV support
- the Smallstep `step-kms-plugin`
- `ykman` / YubiKey Manager
- PC/SC, `pcscd`, OpenSC, and `pkcs11-tool`
- Avahi for mDNS
- `sudo`

The standard release build of `step-ca` does not include PKCS#11/YubiKey PIV support. A CGO/HSM build is required for the hardware-backed CA configuration used by the appliance profile.

Before installation, verify the device with:

```sh
./homepki -check-yubikey
```

HomePKI requires a YubiKey model with **PIV/CCID enabled**. A key that only exposes OTP, FIDO, or FIDO2 will be rejected without modifying it.

When testing several physical keys, use the repeatable read-only script:

```sh
./scripts/check-yubikey.sh
```

Insert one key at a time and run the script for each. It exits with a clear pass/fail result and never changes interfaces, PINs, certificates, or keys.

## 2. Install HomePKI

Copy the installer package to the Pi, then run:

```sh
tar -xzf homepki-installer-linux-arm64.tar.gz
sudo ./install.sh
```

The installer rejects a package for the wrong OS or CPU architecture, discovers installed Step/YubiKey/tool paths, and locates `libykcs11.so`. It:

- installs the binary at `/usr/local/bin/homepki`
- installs the example config at `/etc/homepki/config.yaml` when no config exists
- creates `/var/lib/homepki`
- installs database migrations under `/var/lib/homepki/migrations`
- enables the `homepki.service` systemd unit
- installs `homepki-step-ca.service`; HomePKI starts this service after CA provisioning

The installer does not start the service until you review the config.

## 3. Configure the appliance

Edit `/etc/homepki/config.yaml`. The installer replaces platform placeholders in the packaged template with discovered absolute paths:

```yaml
environment: appliance

server:
  host: 127.0.0.1
  port: 8080

security:
  require_yubikey: true
  allow_insecure_local_session_cookie: false

storage:
  sqlite_path: /var/lib/homepki/homepki.db

pki:
  provider: step
  step_binary: /detected/path/step
  ca_url: https://homepki.local:8443
  root_certificate_path: /var/lib/homepki/.step/certs/root_ca.crt
  provisioner: homepki
  provisioner_password_file: /etc/homepki/provisioner-password
  step_path: /var/lib/homepki/.step
  ca_name: HomePKI Root CA
  ca_dns_name: homepki.local
  ca_address: :8443
  step_ca_binary: /detected/path/step-ca
  systemctl_binary: /detected/path/sudo
  systemctl_args:
    - /detected/path/systemctl
  yubikey_pin_file: /var/lib/homepki/yubikey-pin
  yubikey_root_slot: "82"
  yubikey_intermediate_slot: "83"

yubikey:
  ykman_binary: /detected/path/ykman
  pkcs11_tool_binary: /detected/path/pkcs11-tool
  pkcs11_library_path: /detected/path/to/libykcs11.so
  signing_slot: 9c
```

### Listen address

- `127.0.0.1` is the safe default. HomePKI only accepts local connections.
- Use `0.0.0.0` only when an HTTPS reverse proxy is configured and your firewall blocks direct access to port `8080`.
- Do not bind HomePKI directly to a public address.

### Port

Use port `8080` for the internal application listener. Expose HTTPS from the reverse proxy on port `443`.

### Security

Keep `allow_insecure_local_session_cookie: false` on an appliance. This setting prevents the browser from sending the session cookie over an insecure HTTP connection.

When `require_yubikey` is enabled, HomePKI verifies the inserted YubiKey and PKCS#11 capabilities during setup. It also requires a YubiKey PIN and a hardware signing confirmation before CA provisioning and every certificate issuance.

### Storage

Keep SQLite under `/var/lib/homepki`. Back up this directory with the appliance config under `/etc/homepki`.

### PKI provider

The appliance profile uses `step`. HomePKI invokes `step ca init` during setup, starts the installed Step CA systemd service, and uses `step ca certificate` and `step ca revoke` for live certificate operations.

The command can receive Step CA KMS arguments through `pki.additional_provision_args` so the CA signing key itself uses the configured YubiKey PKCS#11 key. Keep these arguments aligned with the same signing slot configured in the `yubikey` section.

Create the password file before setup:

```sh
sudo install -m 0600 /dev/null /etc/homepki/provisioner-password
sudo chown root:homepki /etc/homepki/provisioner-password
sudo chmod 0640 /etc/homepki/provisioner-password
sudo sh -c 'openssl rand -base64 48 > /etc/homepki/provisioner-password'
```

## 4. Provide a local HTTPS name

The recommended local name is `homepki.local`, with a stable fallback address such as `192.168.1.50`.

1. Enable mDNS on the Pi.
2. Reserve the Pi's address in your router.
3. Configure an HTTPS reverse proxy on the Pi or another trusted appliance.
4. Give the proxy a certificate for the chosen local name.
5. Proxy HTTPS traffic to `127.0.0.1:8080`.

The installer publishes `_https._tcp` through Avahi when `/etc/avahi/services` is present. Set the host name to `homepki` so `homepki.local` resolves on compatible clients.

If mDNS is not available on a client, open the reserved IP address instead. Firewall direct access to port `8080`; clients should use HTTPS on the proxy.

## 5. Start HomePKI

```sh
sudo systemctl daemon-reload
sudo systemctl start homepki.service
sudo systemctl status homepki.service
sudo journalctl -u homepki.service -f
```

Check the local health endpoint:

```sh
curl http://127.0.0.1:8080/healthz
```

Expected response:

```json
{"status":"ok"}
```

## 6. Complete setup in the browser

Open the HomePKI HTTPS name or the local SSH-tunnel URL.

1. Create the administrator account.
2. Confirm the root and intermediate CA names.
3. Leave the YubiKey connected for prerequisite detection and touch.
4. Enter the YubiKey PIN and select **Check prerequisites and provision CA**.

On success, HomePKI saves the Step CA provision state and starts `homepki-step-ca.service`. Setup can be resumed after a failed prerequisite or Step CA startup failure.

The CA state and setup screens are server-rendered. Secure session and CSRF cookies protect state-changing actions.

## 7. Configure each client device

Devices do not install HomePKI itself. They use certificates issued by HomePKI.

For a service on your network:

1. Add a DNS or hosts entry for its private name to point at that service.
2. Request or issue a certificate for that name.
3. Install the generated certificate and private key on the service.
4. Export the HomePKI CA certificate.
5. Install that CA certificate in the client or operating-system trust store.
6. Restart the browser or service if it caches trust settings.

For a service certificate, use the **Issue a certificate** form. A successful browser request downloads a ZIP containing:

- `certificate.pem`
- `private-key.pem`

Handle the private key as a secret. HomePKI does not store the service private key in SQLite or return it in JSON API responses. The certificate inventory keeps only metadata.

## Firewall guidance

Allow:

- SSH from your administration device only
- HTTPS on `443` from the trusted LAN

Block:

- direct LAN access to `8080`
- all internet-facing access
- port forwarding to the HomePKI Pi

## Common checks

```sh
sudo systemctl status homepki.service
sudo journalctl -u homepki.service --since "10 minutes ago"
curl http://127.0.0.1:8080/healthz
ss -ltnp
```

If the service cannot start:

1. Check that `/etc/homepki/config.yaml` exists and is valid YAML.
2. Check that `/var/lib/homepki` is writable by the service.
3. Check that the configured port is free.
4. Read the systemd journal for the exact error.

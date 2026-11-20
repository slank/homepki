# Running Your Own Certificate Authority

This guide is a plain-language introduction to running a private certificate authority (CA) for a home or small network. Most of it applies to any private CA. Where a concrete example helps, it uses HomePKI.

For installation steps, see `DEVICE_SETUP.md`. For backup and upgrade mechanics, see `UPGRADE_AND_RECOVERY.md`.

## What a CA actually does

A certificate is a signed statement: "this public key belongs to `nas.home.example`, and that's true until this date." The CA is whoever signs that statement. A device that trusts your CA accepts every certificate your CA signs.

So running a CA comes down to one responsibility: **you decide who gets to say they are who.** Anyone who can use your CA's signing key can impersonate any service on your network to any device that trusts it. Everything below follows from protecting that key and being careful about what you sign.

### The chain of trust

Most CAs, including HomePKI, use two levels:

- **Root CA**: the top of the chain. Its certificate is what you install on phones, laptops, and browsers. It signs very rarely, usually only the intermediate.
- **Intermediate CA**: signs everyday certificates. If it is compromised or needs replacing, you can issue a new intermediate from the root without re-installing trust on every device.
- **Leaf certificates**: the certificates your services and clients actually use.

```
HomePKI Root CA            (installed in client trust stores)
  └─ HomePKI Intermediate  (signs day-to-day certificates)
       ├─ nas.home.example
       ├─ hass.home.example
       └─ printer.home.example
```

In HomePKI, the setup wizard asks you to confirm the root and intermediate names, then creates both.

## Physical security

A private CA is only as trustworthy as the box it runs on. You don't need a vault, but think about who can touch it.

**Keep the CA on a trusted, private network.** It should never be reachable from the internet. HomePKI is designed as a LAN appliance: the application listens on `127.0.0.1:8080` by default, users connect through an HTTPS reverse proxy, and you should block port forwarding to the device entirely. See the firewall guidance in `DEVICE_SETUP.md`.

**Use hardware to hold the keys.** If the CA's private keys live in ordinary files, anyone who copies the disk (or the SD card) can copy your CA. A hardware token such as a YubiKey stores the key in a chip designed so that it can't be read out. Signing happens *inside* the token.

HomePKI requires a YubiKey for this reason. During setup it generates the root key in PIV slot `82` and the intermediate key in slot `83`, on the YubiKey itself, with:

- `--pin-policy ALWAYS`: every signature needs the PIN.
- `--touch-policy ALWAYS`: every signature needs someone to physically touch the key.

The touch requirement is the important physical control. Malware on the device can't issue a certificate by itself, because someone has to be standing there.

**Think about where the token lives.** Practical options, from most convenient to most protected:

1. Left plugged into the CA device. Fine for a home network, as long as the device is somewhere guests and visitors can't get to it.
2. Plugged in only when you issue certificates, and stored in a drawer the rest of the time.
3. Stored somewhere locked when not in use, such as a small safe.

**Lock down administrative access.** Limit SSH to your own administration device, use key-based SSH login, and keep the OS updated. HomePKI keeps a single local administrator account in v1, so choose a strong password and don't share it.

## Handling key material safely

There are three kinds of secrets in a typical private PKI. Treat each differently.

### CA signing keys

These are the crown jewels. Rules of thumb:

- Generate them on the device that will hold them (ideally inside hardware), so they never exist anywhere else.
- Never email, paste, sync to cloud storage, or commit them to a repository.
- If a CA key ever exists as a plain file, delete that file once it's moved into hardware.

HomePKI follows this pattern. `step ca init` first creates software keys, then HomePKI rebuilds the CA around the YubiKey keys and removes the superseded files (`secrets/root_ca_key` and `secrets/intermediate_ca_key`). The resulting Step CA config refers to the keys by URI, such as `yubikey:slot-id=83`, not by file path.

### PINs, passwords, and other secrets that unlock things

- **YubiKey PIN**: protects the CA keys. Change it from the factory default and set a separate PUK (the unblock code). Write both down and store them apart from the YubiKey. HomePKI keeps the PIN in a root-only file (`/var/lib/homepki/yubikey-pin`, mode `0600`) so Step CA can sign. The touch policy is what stops an attacker who reads that file from signing remotely.
- **Provisioner password**: lets HomePKI ask Step CA for certificates. Generate it randomly and restrict the file:

  ```sh
  sudo sh -c 'openssl rand -base64 48 > /etc/homepki/provisioner-password'
  sudo chown root:homepki /etc/homepki/provisioner-password
  sudo chmod 0640 /etc/homepki/provisioner-password
  ```

### Service (leaf) private keys

Each server or client certificate comes with its own private key. Leaking one of these only compromises that one service, but it's still a secret:

- Move it straight to the service that needs it, over a secure channel such as `scp`.
- Make it readable only by the service account (`chmod 600`).
- Delete leftover copies from your Downloads folder.

When you issue a certificate in HomePKI, the browser downloads a ZIP containing `certificate.pem` and `private-key.pem`. HomePKI doesn't store the service private key: the inventory keeps only metadata (serial number, names, validity dates). That means **the downloaded ZIP is the only copy of the key.** If you lose it, issue a new certificate rather than trying to recover the old one.

A better general practice is for the service to generate its own key and send the CA only a certificate signing request (CSR), so the private key never leaves the service. HomePKI v1 doesn't offer a CSR workflow yet, so the key is created during issuance and handed to you. ACME automation, planned for later releases, follows the CSR model.

## Certificate types and uses

All certificates share the same format (X.509). What makes them different is the fields set inside them, especially the names they cover and the *extended key usage* (EKU), which says what the certificate is allowed to be used for.

| Type | Used for | Typical names | EKU |
|---|---|---|---|
| Root CA | Top of the trust chain, installed on clients | `HomePKI Root CA` | CA only (signs other certificates) |
| Intermediate CA | Signs everyday certificates | `HomePKI Intermediate CA` | CA only |
| TLS server | HTTPS for a web UI, API, or reverse proxy | `nas.home.example`, `*.home.example` | Server authentication |
| TLS client | Proving a user or device's identity to a server (mutual TLS, VPN-like access) | A user or device name | Client authentication |
| Other | Code signing, email (S/MIME), SSH certificates | Varies | Purpose-specific |

The most common home use is TLS server certificates: putting real HTTPS (no browser warnings) on Home Assistant, a NAS, a media server, or a router admin page. HomePKI v1 focuses on this. Its **Issue a certificate** form produces a server certificate for the names you enter. Client certificates for browsers are a project goal for later versions.

### Names matter

Browsers ignore the "Common Name" field and check only the **Subject Alternative Names (SANs)**. A certificate must list every name clients will use to reach the service:

- `hass.home.example` and `hass` (if you also use the short name)
- An IP address such as `192.168.1.20`, if you connect by IP (this requires an IP SAN, not a DNS SAN)

**Wildcards** like `*.home.example` cover any single label (`nas.home.example`, but not `a.b.home.example`). They're convenient, but one leaked key exposes every name the wildcard covers. Prefer one certificate per service when you can.

**Pick a domain you control.** Use a subdomain of a domain you own (for example, `home.example.com`) or `home.arpa`, which is reserved for home networks. Avoid made-up top-level domains, which can collide with real ones later. `.local` belongs to mDNS: it works for discovering the CA itself (`homepki.local`), but it's a poor choice for service names, because some systems treat it specially.

### Lifetimes

Shorter lifetimes limit the damage from a lost key, but you have to renew more often. Reasonable defaults:

- Root CA: 10 to 20 years. Replacing it means re-installing trust on every device.
- Intermediate CA: a few years.
- Leaf certificates: 90 days to one year. Many browsers and Apple platforms reject server certificates valid for more than 398 days.

HomePKI rejects leaf certificates with a lifetime longer than 397 days for this reason.

## Validating certificates and requests

### Before you sign: validate the request

The CA is a gatekeeper. Before signing, check:

1. **Is the requester allowed to have this name?** This is the real security check. On a home network it usually means "did *I* ask for this?" On larger setups it means proving control of the name (that's what ACME challenges do).
2. **Are the names well formed?** No typos, no stray spaces, valid hostname characters.
3. **Is the lifetime reasonable?**
4. **Is the key strong enough?** For example, RSA 2048+ or ECDSA P-256+.

HomePKI performs the mechanical checks on the server before anything reaches Step CA:

- A common name is required.
- The lifetime must be greater than zero and at most 397 days.
- The common name and every SAN must be a valid DNS name: labels of 1–63 letters, digits, or hyphens, no leading or trailing hyphen, and 253 characters total.

The "should this exist?" check is still your job. That's why every issuance needs your PIN and a physical touch: it gives you a moment to read what you're about to sign.

### After you sign: inspect the certificate

Get into the habit of looking at what you issued:

```sh
# Show names, validity, issuer, and key usage
openssl x509 -in certificate.pem -noout -text

# Shorter, friendlier output
step certificate inspect certificate.pem

# Confirm it chains to your root
step certificate verify certificate.pem --roots root_ca.crt

# Confirm the certificate and private key belong together (hashes should match)
openssl x509 -in certificate.pem -noout -pubkey | openssl sha256
openssl pkey -in private-key.pem -pubout | openssl sha256
```

### On the wire: check what the service presents

After installing a certificate, confirm the service is actually serving it, along with the intermediate:

```sh
openssl s_client -connect nas.home.example:443 -servername nas.home.example \
  -CAfile root_ca.crt </dev/null
```

Look for `Verify return code: 0 (ok)`. A common mistake is configuring only the leaf certificate without the intermediate, which works in some clients and fails in others.

## Managing and distributing certificates

### Distributing trust (the root certificate)

Clients need your root certificate (and *only* the root, never a private key) in their trust store. Public certificates aren't secret, so share them however is convenient, but make sure you're installing the *right* one. Compare its fingerprint against the one shown on the CA:

```sh
step certificate fingerprint root_ca.crt
```

Where trust lives varies by platform:

- **macOS**: Keychain Access → System keychain, set to "Always Trust". Safari and Chrome use this.
- **Linux**: the system store (`/usr/local/share/ca-certificates/` and then `update-ca-certificates` on Debian-based systems). Firefox keeps its own store unless it's set to use the system store.
- **iOS/Android**: install a profile or certificate, then enable full trust in settings.
- **Containers and apps**: many programs (Python, Node.js, Java, Docker images) bundle their own CA list and need the root added separately.

HomePKI provides trust guidance for Linux and macOS browsers rather than editing trust stores for you. On the appliance, the root lives at `/var/lib/homepki/.step/certs/root_ca.crt`.

### Distributing leaf certificates

- Install the certificate *and* the intermediate (the "full chain") on the service.
- Install the private key with tight permissions.
- Restart or reload the service. Many services read certificates only at startup.

### Keeping an inventory

You'll forget what you issued. An inventory answers "what expires next month?" and "which certificates covered the old NAS?" At minimum, track serial number, names, issue and expiry dates, and where each certificate is installed.

HomePKI keeps a certificate inventory in SQLite with the serial number, names, validity window, and revocation status of every certificate it issues. It records sensitive actions in an audit log.

### Renewal

Certificates expire, and an expired certificate breaks things in an abrupt, confusing way. Plan for it:

- Set a calendar reminder a few weeks before each expiry, or check the inventory regularly.
- Renew by issuing a fresh certificate for the same names, installing it, and confirming it works before the old one expires.
- Automation (ACME clients like Caddy, Traefik, or certbot) removes this chore entirely. HomePKI v1 issues certificates manually; ACME is on the roadmap.

### Revocation

Revoke a certificate when its private key may have leaked, the device was retired or sold, or it was issued by mistake. Revocation tells the CA "this certificate should no longer be trusted."

In HomePKI, you revoke from the inventory. Behind the scenes it requests a revocation token from Step CA and runs `step ca revoke` with the certificate's serial number and a reason.

Be aware of a practical limit: many clients never check revocation for private CAs. Revocation is a record, not a kill switch. For a leaked key, also remove the certificate from the service, replace it, and rely on short lifetimes as your real safety net.

## Backups and lifecycle

### What to back up

| Item | Why | Secret? |
|---|---|---|
| Root and intermediate certificates | Clients and services need them; reinstalling trust requires them | No |
| CA configuration | Rebuilds the CA's settings | Partly |
| Certificate inventory and audit log | Knowing what you issued and when | No, but sensitive |
| CA private keys | Lets you keep signing after a hardware failure | **Yes, extremely** |
| PINs, PUKs, passwords | Unlocks the above | **Yes** |

On HomePKI, back up `/var/lib/homepki` (the SQLite database and Step CA files) together with `/etc/homepki` (configuration and the provisioner password). `UPGRADE_AND_RECOVERY.md` describes creating and restoring a backup archive. Encrypt backups that include `/etc/homepki` or the PIN file, and keep a copy off the device.

### The key backup trade-off

Hardware-held keys can't be copied, and that's the point. It also means **they can't be backed up.** You have two choices:

1. **Accept that the key can be lost.** If the token dies or disappears, you build a new CA and re-install trust on every device. For a home network with a handful of devices, this is often a reasonable trade.
2. **Generate the key outside hardware once, back it up offline, then import it into the token.** This allows recovery, but the backup copy now needs the same protection as the token itself (for example, an encrypted USB drive in a safe, with the passphrase stored separately).

HomePKI currently takes the first approach: the root and intermediate keys are generated on the YubiKey and can't be exported. Your backups let you restore the inventory, configuration, and certificates, but **if the YubiKey is lost or reset, the CA must be provisioned again** and the new root distributed to every client. Know this before you depend on it. Keep your list of trusting devices current so re-provisioning is a chore, not a crisis.

### Test your restores

A backup you've never restored is a hope, not a backup. After setup, and after major changes:

1. Restore the backup archive into a scratch directory.
2. Confirm the database opens and the inventory is intact.
3. Confirm the root certificate fingerprint matches the one your clients trust.

### Lifecycle milestones

| When | What to do |
|---|---|
| Setup | Set YubiKey PIN/PUK, record the root fingerprint, take a first backup, install root trust on clients |
| Every issuance | Read the names and lifetime before touching the key; move the private key to the service and delete the download |
| Monthly | Check upcoming expirations; take a backup |
| Device retired | Revoke its certificates and remove it from your device list |
| Key suspected leaked | Revoke, replace, and investigate how it happened |
| Intermediate nearing expiry | Issue a new intermediate from the root, then reissue leaves as they renew |
| Root nearing expiry | Create a new root well ahead of time, distribute it alongside the old one, then retire the old one |
| Retiring the CA | Remove its root from every trust store, then reset the YubiKey PIV application and factory-reset the appliance |

## Quick checklist

- [ ] CA is on a private network, not reachable from the internet
- [ ] CA keys are in hardware, and no software copies remain
- [ ] YubiKey PIN and PUK changed from defaults and stored separately from the key
- [ ] Root fingerprint recorded somewhere you can check it
- [ ] Service names use a domain you control, and certificates list every name in their SANs
- [ ] Leaf lifetimes are one year or less
- [ ] Private keys go straight to their service with tight permissions; downloads are deleted
- [ ] Inventory reviewed regularly for upcoming expirations
- [ ] Backups are encrypted, stored off-device, and have been test-restored
- [ ] You know what happens, and what you'll do, if the YubiKey is lost

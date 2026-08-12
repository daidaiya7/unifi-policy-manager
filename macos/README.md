# UniFi Policy Manager Dual Authentication for macOS

Native macOS dual-authentication port. API Key mode provides full management through the official Ubiquiti Integration API; on compatible Network versions, UniFi OS local-account Cookie mode supports DNS reads and writes while ACL and firewall remain read-only.

> **Important:** Local-account DNS writes depend on the installed Network version. The app uses the v2 `static-dns` endpoint for DNS CRUD and batch operations. A 403, 404 or 405 response automatically disables further Cookie DNS writes and keeps reads available. ACL, firewall, ordering and policy-change execution still require API Key mode.

## Requirements

- macOS 14 or later
- UniFi Cloud Gateway / Network application exposing the Integration API
- API Key created in the local Console under `Integrations` or in `unifi.ui.com -> Settings -> API Keys`, or a UniFi OS local administrator account

## Included

- Native connection and multi-site selection
- API Key mode: DNS records (forward domain, A, AAAA, CNAME, MX, TXT and SRV) CRUD
- API Key mode: DNS batch import from TXT, CSV and XLSX with preview, validation and de-duplication
- API Key mode: bundled 212-domain forwarder preset, built-in CSV template and forward-domain batch deletion
- API Key mode: ACL and firewall policy list, JSON create/edit, enable/disable, delete and user-policy ordering
- API Key mode: full policy change center with cross-platform baseline import, safe diff execution, strict synchronization, snapshot recovery and ordering restoration
- Local-account Cookie mode: DNS CRUD and batch operations on compatible Network versions; ACL and firewall views remain read-only
- System and derived policies remain read-only
- API Key or local-account password storage in macOS Keychain
- Automatic live DNS, ACL and firewall baseline snapshots before write operations
- Manual baseline export
- Offline demo mode

Backups and operation logs are stored in:

```text
~/Library/Application Support/UniFiPolicyManager
```

## Authentication

The connection screen supports two modes:

- API Key: sends the key to the official Integration API and enables all write controls.
- Local account: signs in through `/api/auth/login`, keeps the UniFi OS Cookie session, reads section-by-section and enables DNS writes when the v2 `static-dns` endpoint accepts them.

DNS create, update, enable/disable, delete, batch add and forward-domain batch delete are available when the controller accepts Cookie writes. The app saves a fresh DNS snapshot first. Every ACL/firewall write, ordering change and policy-change execution remains API-Key-only.

Local-account mode requires a UniFi OS local administrator. Ubiquiti cloud SSO,
2FA and Passkey accounts are not supported. Local session endpoint availability
varies by Network version. A missing DNS, ACL or firewall endpoint is reported
individually, while the other readable sections remain available; API Key mode
continues to provide the complete supported feature set.

## Build

The source is a Swift Package. Install Xcode or Apple Command Line Tools, then run:

```bash
swift test --package-path macos
./macos/build-app.sh
```

The application is written to `macos/dist/UniFi-Policy-Manager.app`, enables
Hardened Runtime, and receives an ad-hoc local signature when no Developer ID
identity is configured. GitHub Actions packages the bundle with `ditto` so
executable permissions and macOS metadata are preserved. The release workflow
automatically performs Developer ID signing and Apple notarization when the
secrets documented in the repository root `SIGNING.md` are available.

Run the Swift package directly in offline demo mode with:

```bash
swift run --package-path macos UniFiPolicyManagerMac --demo
```

## Feature scope

The macOS and Windows editions cover the same official Integration API policy
scope: DNS, ACL and firewall CRUD, DNS batch workflows, policy ordering and the
complete policy change center. Features without a public Network API endpoint,
such as NAT, policy-based routing, port forwarding, QoS and static routes, are
intentionally not implemented on either platform.

## License

MIT. See the repository root `LICENSE`.

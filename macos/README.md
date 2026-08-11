# UniFi Policy Manager for macOS

Native macOS port built with SwiftUI and the official Ubiquiti Integration API.

## Requirements

- macOS 14 or later
- UniFi Cloud Gateway / Network application exposing the Integration API
- API Key created in the local Console under `Integrations`, or in `unifi.ui.com -> Settings -> API Keys`

## Included

- Native connection and multi-site selection
- DNS records: forward domain, A, AAAA, CNAME, MX, TXT and SRV CRUD
- ACL and firewall policy list, JSON create/edit, enable/disable and delete
- System and derived policies remain read-only
- API Key storage in macOS Keychain
- Automatic live DNS, ACL and firewall baseline snapshots before write operations
- Manual baseline export
- Offline demo mode

Backups and operation logs are stored in:

```text
~/Library/Application Support/UniFiPolicyManager
```

## Build

The source is a Swift Package. Install Xcode or Apple Command Line Tools, then run:

```bash
./macos/build-app.sh
```

The application is written to `macos/dist/UniFi-Policy-Manager.app` and receives
an ad-hoc local signature. GitHub Actions packages the bundle with `ditto` before
artifact upload so executable permissions and macOS metadata are preserved.
Release builds still require Developer ID signing and Apple notarization before
public distribution.

Run the Swift package directly in offline demo mode with:

```bash
swift run --package-path macos UniFiPolicyManagerMac --demo
```

## Current scope

The macOS port covers connection, policy browsing and individual CRUD workflows.
The Windows-only policy change center, bundled 212-domain import, XLSX import and
policy ordering workflows are not yet ported.

## License

MIT. See the repository root `LICENSE`.

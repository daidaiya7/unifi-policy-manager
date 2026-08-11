# UniFi Policy Manager Dual Authentication for macOS

Native macOS port supporting both API Key and UniFi OS local-account authentication, built with SwiftUI and the official Ubiquiti Integration API.

## Requirements

- macOS 14 or later
- UniFi Cloud Gateway / Network application exposing the Integration API
- API Key created in `unifi.ui.com -> Settings -> API Keys`, or a UniFi OS local administrator account

## Included

- Native connection and multi-site selection
- DNS records: forward domain, A, AAAA, CNAME, MX, TXT and SRV CRUD
- ACL and firewall policy list, JSON create/edit, enable/disable and delete
- System and derived policies remain read-only
- API Key or local-account password storage in macOS Keychain
- Automatic full baseline snapshots before write operations
- Manual baseline export
- Offline demo mode

Backups and operation logs are stored in:

```text
~/Library/Application Support/UniFiPolicyManager
```

## Authentication

The connection screen supports two modes:

- API Key: sends the key to the official Integration API.
- Local account: signs in through `/api/auth/login`, keeps the UniFi OS Cookie session and CSRF token, then accesses the same Integration API endpoints.

Local-account mode requires a UniFi OS local administrator. Ubiquiti cloud SSO,
2FA and Passkey accounts are not supported. If the installed Integration API
rejects Cookie authentication, the app reports that incompatibility instead of
falling back to private Network application endpoints.

## Build

The source is a Swift Package. Install Xcode or Apple Command Line Tools, then run:

```bash
./macos/build-app.sh
```

The application is written to `macos/dist/UniFi-Policy-Manager.app` and receives
an ad-hoc local signature. Release builds still require Developer ID signing and
Apple notarization before public distribution.

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

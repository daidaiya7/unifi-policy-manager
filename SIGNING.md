# Release signing

The project can build and publish without paid signing certificates. In that
mode, GitHub Actions produces:

- an unsigned Windows executable;
- a macOS application with an ad-hoc signature and Hardened Runtime;
- SHA-256 checksums and GitHub build-provenance attestations for the release
  packages.

Checksums and attestations prove which files GitHub Actions built, but they do
not replace operating-system trust. Windows SmartScreen and macOS Gatekeeper may
still warn users.

## Windows Authenticode

A publicly trusted Authenticode signature requires a code-signing certificate.
The release workflow supports a password-protected PFX certificate through two
GitHub repository or environment secrets:

| Secret | Value |
| --- | --- |
| `WINDOWS_CERTIFICATE_PFX_BASE64` | Base64 representation of the `.pfx` file |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password protecting the `.pfx` file |

On PowerShell, create the Base64 value without printing it to the terminal:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('codesigning.pfx')) | Set-Clipboard
```

Possible certificate sources include a commercial OV/EV code-signing
certificate, Microsoft Trusted Signing where available, or SignPath Foundation
for qualifying open-source projects. A self-signed certificate is useful for
private testing only and will not remove SmartScreen warnings on other users'
computers.

## macOS Developer ID and notarization

Apple notarization requires an active Apple Developer Program membership and a
`Developer ID Application` certificate. Export that certificate and its private
key as a password-protected `.p12`, then configure these secrets:

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE_P12_BASE64` | Base64 representation of the exported `.p12` |
| `APPLE_CERTIFICATE_PASSWORD` | Password protecting the `.p12` |
| `APPLE_SIGNING_IDENTITY` | Full identity, for example `Developer ID Application: Name (TEAMID)` |
| `APPLE_ID` | Apple ID used for notarization |
| `APPLE_TEAM_ID` | Apple Developer Team ID |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password created at `appleid.apple.com` |

Create the Base64 value on macOS with:

```bash
base64 -i developer-id-application.p12 | pbcopy
```

When all notarization credentials are present, the workflow signs with Hardened
Runtime, submits the application using `notarytool`, staples the ticket, checks
it with Gatekeeper, and only then creates the public ZIP. If only the certificate
is configured, the application is Developer ID signed but the workflow emits a
warning that it was not notarized.

## Secret safety

- Add signing values under GitHub repository `Settings -> Secrets and variables
  -> Actions`, or use a protected GitHub Environment.
- Never commit PFX/P12 files, passwords, private keys, or Base64 certificate
  values to the repository.
- Restrict release workflow access and require review for a protected release
  environment when multiple maintainers have write access.

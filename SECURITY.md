# Security

## Credentials

Never include a real UniFi API Key in an issue, screenshot, log, baseline, test fixture, pull request, or commit.

The application stores a remembered API Key with Windows DPAPI for the current Windows user. Local settings, backups, operation logs, build outputs, and environment files are excluded from Git by default.

## Reporting a vulnerability

If the GitHub repository has private vulnerability reporting enabled, use the repository's **Security → Report a vulnerability** page. Otherwise, open an issue that contains only a non-sensitive description and do not attach credentials or private network data.

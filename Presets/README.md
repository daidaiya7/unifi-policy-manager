# Bundled forward-domain preset

`unifi-forward-domains-by-service.csv` contains 212 categorized forward-domain rules.

The `DNS 服务器` column is intentionally empty. UniFi Policy Manager fills it with the value entered in **转发域默认 DNS 服务器** when the file is imported. This keeps the preset usable on networks that do not use `192.168.1.10`.

Review the domains before applying them. Service providers can add or retire domains over time, so this list is a starting point rather than a guarantee of completeness.

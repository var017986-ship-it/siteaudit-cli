# Security policy

## Intended use

SiteAudit is for websites you own or have explicit permission to assess. The scanner restricts HTTP requests to the target host and port, blocks redirects outside that scope, rejects non-public DNS results unless `--allow-private` is explicitly set, and pins each connection to the IP address it validated.

Active checks are bounded GET, HEAD, and OPTIONS requests. GET handlers can still have application-specific side effects, so scan only authorized targets where those side effects are acceptable. The scanner does not submit POST forms, authenticate, brute force, upload files, or attempt command execution.

## Reporting a bug

Please report vulnerabilities in SiteAudit through a private GitHub Security Advisory or by contacting the repository maintainer privately. Include the affected version, reproduction steps, and impact. Do not include real credentials or third-party target data in a public issue.

# Security policy

## Intended use

SiteAudit is for websites you own or have explicit permission to assess. The scanner restricts HTTP requests to the target host and port, blocks redirects outside that scope, rejects non-public DNS results unless `--allow-private` is explicitly set, and pins each connection to the IP address it validated.

Default active checks use bounded GET, HEAD, and OPTIONS requests. The SSTI check sends only nonce-wrapped integer multiplication expressions to at most two non-sensitive GET parameters; it does not attempt command execution, file access, callbacks, or delays. The CORS plugin sends a GET with a reserved test `Origin` value to at most five discovered pages and sends no cookies or authorization credentials. Optional `--post-probes` sends one inert marker-only form request to at most five discovered forms; this may create application data. Optional `--graphql-probe` sends a single fixed read-only introspection query to at most three same-host GraphQL paths, without cookies or authorization; it reports whether the query type name is exposed and never stores the schema. GET handlers can also have application-specific side effects, so scan only authorized targets where those side effects are acceptable. The scanner does not authenticate, brute force, upload files, or attempt command execution. Response bodies used by passive plugins are kept in a bounded in-memory cache and are not copied into the report.

## Reporting a bug

Please report vulnerabilities in SiteAudit through a private GitHub Security Advisory or by contacting the repository maintainer privately. Include the affected version, reproduction steps, and impact. Do not include real credentials or third-party target data in a public issue.

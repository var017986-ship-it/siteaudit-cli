# Tool coverage map

SiteAudit combines independent checks behind one CLI. The names below describe inspiration and coverage areas; this project does not embed upstream code, databases, or claim compatibility with the named scanners.

| Reference tool | Included now | Not included yet |
| --- | --- | --- |
| OWASP ZAP | Same-host crawl; passive HTTPS/header/cookie, mixed-content, weak-CSP, stack-trace and CORS observations; JSON findings | Intercepting proxy, authenticated sessions, browser/AJAX spider, full active rule set, API imports |
| Nuclei | Five bundled signatures, including public API specification discovery, plus up to 27 user-supplied JSON rules; fixed-path literal matchers and source references | Community CVE template library, YAML compatibility, workflows, code or network callbacks in templates |
| Nikto | Bounded HEAD probes for common exposed paths; compares metadata with a random missing-path response to filter common catch-all pages; checks OPTIONS method observations | Nikto's full test database, plugin collection, mutation/wordlist modes and version database |
| Wapiti | Bounded crawler; GET marker reflection, database error indicators, un-followed open-redirect probes, and opt-in one-field POST marker checks | Authenticated crawling, upload, SSRF, XXE, time-based and broader fuzzing modules |
| W3AF | Static plugin registry; credentialed CORS reflection check and low-confidence POST-form CSRF token-name heuristic | W3AF's broad plugin set, exploit verification, authentication profiles and audit framework |
| GraphQL APIs | Optional fixed read-only introspection query to up to three same-host endpoints; reports only whether the query type name is exposed | Full schema enumeration, authentication profiles, mutation fuzzing and exploit testing |

## Shared execution model

- `siteaudit <target>` runs the core crawl, passive response checks, and bounded active plugins.
- `--passive` runs the core crawl and passive response checks, with all active plugins disabled.
- Scanner modules share the same request budget, delay, host-and-port scope, DNS pinning, response cap, and finding schema.
- Reports show which plugins ran, checks or requests attempted where available, findings added, severity, confidence, evidence, remediation, and references.
- Results are indicators from a black-box scan. They cannot prove that the whole application is secure or that every suspected issue is exploitable.

This map is intentionally explicit so future feature work can close the remaining coverage gaps without presenting partial coverage as full parity.

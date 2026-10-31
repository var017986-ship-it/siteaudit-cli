# Tool coverage map

SiteAudit combines independent checks behind one CLI. The names below describe inspiration and coverage areas; this project does not embed upstream code, databases, or claim compatibility with the named scanners.

| Reference tool | Included now | Not included yet |
| --- | --- | --- |
| OWASP ZAP | Same-host crawl; document-aware security-header checks and value validation, origin-root HSTS max-age validation, cookie flag/SameSite/prefix checks, mixed-content, weak-CSP, stack-trace and CORS observations; JSON findings | Intercepting proxy, authenticated sessions, browser/AJAX spider, full active rule set, API imports |
| Nuclei | Nine bundled signatures for diagnostic, source-control, runtime-metrics, and API-documentation exposure, plus up to 23 local JSON rules or a restricted optional YAML subset; fixed-path GET/HEAD and positive status/body-word matchers | Community CVE template library, full YAML compatibility, workflows, code or network callbacks in templates |
| Nikto | Bounded HEAD probes for common exposed paths; compares metadata with a random missing-path response to filter common catch-all pages; checks OPTIONS method observations | Nikto's full test database, plugin collection, mutation/wordlist modes and version database |
| Wapiti | Bounded crawler; parsed inert HTML-marker reflection, database error indicators, un-followed open-redirect probes, opt-in repeated boolean SQL checks for up to two numeric GET parameters, one-field POST marker checks, and a bounded arithmetic-only SSTI check | Authenticated crawling, upload, SSRF, XXE, time-based and broader fuzzing modules |
| W3AF | Static plugin registry; credentialed CORS reflection check and low-confidence POST-form CSRF token-name heuristic | W3AF's broad plugin set, exploit verification, authentication profiles and audit framework |
| GraphQL APIs | Optional fixed read-only introspection query to up to three same-host endpoints; reports only whether the query type name is exposed | Full schema enumeration, authentication profiles, mutation fuzzing and exploit testing |
| Windows CLI | `setup.bat` installs SiteAudit; `setup-engines.bat` verifies and installs the Nuclei v3.11.1 binary/template pack and Wapiti into user-local locations, and pulls Nikto/ZAP images if Docker is already running; `start.bat` offers quick passive, standard, deep, full combined, and upstream-only modes with a progress bar and approximate ETA | Installing Docker Desktop or W3AF; exact completion-time prediction |

## Optional upstream engines

The CLI can invoke Nuclei, Nikto (native or the official Docker image), Wapiti, OWASP ZAP (Docker), and W3AF processes with repeated `--engine` flags or `--engine all`. Their findings are normalized into the SiteAudit report. Their source code and signature databases are not bundled. `siteaudit --doctor` reports which prerequisites are ready. ZAP uses baseline/passive mode by default; `--zap-active` opts into its active scan.

Upstream processes do not share SiteAudit's request counter or global delay. A temporary scope proxy filters plaintext HTTP requests and HTTPS `CONNECT` tunnels to the selected hostname and port, connects to the pinned target IP, and checks HTTPS SNI. It blocks redirects to a different host or port when the scanner uses the proxy. HTTPS request contents, methods, bodies, and `Host` headers inside a tunnel remain encrypted, so the proxy counts and paces tunnels rather than individual requests; a client can send another encrypted `Host` or method to the pinned IP. Native engine limits still apply, and reports flag blocked attempts, proxy overload, or exhausted tunnel/request limits as partial. This is not OS-level egress isolation for scanner processes. Wapiti has no global requests-per-second setting or hard total-page cap. W3AF also has no hard page cap, and its crawler may submit smart-filled forms. Its SSL-certificate audit plugin is disabled because it makes direct socket connections outside the configured proxy. The Nuclei adapter screens selected template files and excludes templates calling network DSL helpers `resolve()`, `public_ip()`, or `jarm()` because these may send direct traffic outside the configured proxy in Nuclei v3.11.1. Nikto matches are reported at informational severity because its export does not provide a normalized severity. W3AF is unsupported on native Windows. Wapiti 3.3.2 was exercised on Windows with Python 3.13; its upstream FAQ still recommends WSL and other Wapiti releases may differ.

## Shared execution model

- `siteaudit <target>` runs the core crawl, passive response checks, and bounded active plugins.
- `siteaudit <target> --external-only --engine all` runs only the requested upstream engines and reports their proxy counters separately from SiteAudit's own request count.
- `--passive` runs the core crawl and passive response checks, with all active plugins disabled.
- Built-in Python modules share SiteAudit's request budget, delay, host-and-port scope, DNS pinning, response cap, and finding schema. Optional upstream subprocess engines apply their own controls; their requests do not count against the built-in budget, their scope behavior differs by engine, and their findings are normalized into the shared schema.
- Reports show which plugins ran, checks or requests attempted where available, findings added, severity, confidence, evidence, remediation, and references.
- Results are indicators from a black-box scan. They cannot prove that the whole application is secure or that every suspected issue is exploitable.

This map is intentionally explicit so future feature work can close the remaining coverage gaps without presenting partial coverage as full parity.

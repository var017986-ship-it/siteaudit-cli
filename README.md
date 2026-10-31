# SiteAudit

SiteAudit is a self-contained command-line web security checker written in Python. One CLI runs a bounded same-host crawl, HTTPS/header/cookie checks, Nikto-style server exposure checks, Wapiti-style input indicators, ZAP-inspired passive response rules, W3AF-inspired modular checks, and a local literal-match template runner inspired by Nuclei.

It is an educational starter project, not a replacement for a professional penetration test or for mature scanners such as OWASP ZAP, Nuclei, Nikto, or Wapiti. It does not claim to find every vulnerability. Findings include the URL, observed evidence, severity, confidence, and a suggested fix.

## Use only with permission

Only scan websites you own or have explicit permission to assess. The default scan stays on the supplied host, uses bounded request and crawl limits, and avoids authentication attempts, brute force, uploads, destructive payloads, and command execution. Active checks use inert markers and error-indicator probes. POST form probes are disabled by default; `--post-probes` sends at most one marker-only request to each of five forms and may create application data. Since some applications attach state changes to GET routes too, scan only targets where you can accept those application-specific side effects. Findings are indicators for manual verification, not a guarantee that a vulnerability can be exploited.

## Requirements

- Python 3.11 or newer
- No third-party Python packages

## Install

```powershell
python -m pip install -e .
```

On Windows, run `setup.bat` to install the CLI; choose option 1 for the core only or option 2 to prepare available upstream engines. Then use `start.bat` to choose quick passive, standard, deep, full combined, or upstream-only mode, or check engine readiness. Full combined mode runs the built-in checks and every installed upstream engine; upstream-only skips the built-in crawl. Both include ZAP active scanning when ZAP is available. Missing programs appear as `unavailable` in the JSON report. The terminal shows progress and an approximate remaining time; estimates for external engines use their runtime limits, so scans often finish sooner.

Run `siteaudit --doctor` before a full scan to check which upstream engines, template files, WSL installations, and Docker images are ready. The check is read-only and does not contact the target. `start.bat` runs this check before full and upstream-only modes and asks before continuing with only the engines that are available. On Windows, `setup-engines.bat` can install the checksum-verified Nuclei v3.11.1 binary and official template pack into the current user's SiteAudit folder, install Wapiti 3.3.2 in a separate Python 3.12-3.14 environment, install pinned Nikto 2.6.1 and ZAP 2.17.0 in Debian WSL when present, and pull official Nikto/ZAP Docker images as a fallback when Docker Desktop is already running. Nikto's source stays in WSL outside the repository. It does not install Docker Desktop or W3AF.

## Run

```powershell
siteaudit https://example.com --output report.json
```

To also send one inert marker in up to five discovered POST forms (may create target data):

```powershell
siteaudit https://example.com --post-probes --output report.json
```

To run a repeated boolean-based SQL injection check against at most two numeric GET parameters (this changes the query value and can affect application behavior):

```powershell
siteaudit https://example.com --sqli-probes --output report.json
```

The check compares an unchanged response with two true and two false numeric predicates. It uses no delays, data extraction, callbacks, or write statements.

To optionally check whether a GraphQL endpoint exposes its query type through introspection (up to three same-host POSTs; no cookies/authentication; informational result):

```powershell
siteaudit https://example.com --graphql-probe --output report.json
```

Add reviewed local JSON signatures or a restricted Nuclei YAML subset with `--templates-file`; see [docs/custom-templates.md](docs/custom-templates.md) for supported fields. YAML imports require `python -m pip install -e ".[yaml]"`.

Or without installing the console command:

```powershell
python -m siteaudit https://example.com --output report.json
```

Use `siteaudit --help` to see available scope, rate, crawl, and passive-mode options. The default run performs bounded GET/HEAD/OPTIONS checks; `--passive` skips template, server-path, and input probes. Private and loopback IPs require `--allow-private`. Review the target and options before each scan. Query values are redacted in saved URLs, but reports can still contain hostnames and server metadata.

## Optional upstream engines

SiteAudit can invoke Nuclei, Nikto, Wapiti, OWASP ZAP, and W3AF engines and merge their findings into its JSON report. Nuclei and Wapiti can be stored in the current user's managed engine directory; Nikto can run from pinned Debian WSL, native Perl, or Docker; ZAP uses pinned Debian WSL or Docker. Their upstream source code and signature databases are not copied into this repository. Run one or more with repeated `--engine` flags, or use `--engine all`:

```powershell
siteaudit https://example.com --engine all --engine-timeout 300 --output report.json
```

Use `--external-only` to run only the selected upstream engines without repeating SiteAudit's own crawl and checks. The report then shows zero built-in pages/requests and keeps each external engine's proxy counters in its engine result:

```powershell
siteaudit https://example.com --external-only --engine nuclei --engine-timeout 300 --output nuclei-report.json
```

For Nuclei, optionally provide a local template file or directory with `--nuclei-templates`; otherwise the adapter looks in the managed engine directory, then `~/nuclei-templates`. Before scanning, it copies HTTP template files to a temporary directory and excludes files that call the direct-network DSL helpers `resolve()`, `public_ip()`, or `jarm()`; the report gives the number excluded. This protects against the Nuclei v3.11.1 helpers that can make DNS/TLS/HTTPS calls outside its configured proxy. Redirects and Interactsh are disabled. Review templates before running: the proxy cannot inspect an encrypted HTTPS `Host` header inside a CONNECT tunnel. On Windows, `setup-engines.bat` installs pinned ZAP 2.17.0 in Debian WSL and verifies the archive SHA-256 before extraction; `ghcr.io/zaproxy/zaproxy:stable` remains the Docker fallback. Its default baseline mode spiders and passively analyzes the site. `--engine zap --zap-active` selects ZAP's full active scan, which sends attack probes. ZAP baseline needs `--engine-timeout` of at least 120 seconds; ZAP active needs at least 180 seconds. Other engines use `--engine-timeout` as their scan budget; WSL Nikto may use up to 25 additional seconds to finish and write its report. `--delay` is applied where supported. External tools use a separate proxy transaction limit and do not share SiteAudit's internal request budget; for HTTPS, the limit counts CONNECT tunnels rather than requests inside them. Wapiti has no global requests-per-second option or hard total-page cap. Nikto matches are reported at informational severity because its export provides test matches but no normalized severity field. W3AF has no hard page limit and its crawler may submit smart-filled forms. On Windows W3AF is reported as unavailable. Wapiti 3.3.2 was exercised here on Windows with Python 3.13; its upstream FAQ still recommends WSL and other releases may differ. The JSON report records each requested engine as `completed`, `partial`, `unavailable`, or `error`.

Each external adapter starts a temporary scope proxy. WSL engines connect through the WSL gateway with an exact scanner-IP allow-list; Docker clients are restricted to the inspected bridge subnet and must use a random per-scan proxy credential. The proxy closes active sockets when a scan ends. It filters plaintext HTTP requests and HTTPS `CONNECT` tunnels to the selected hostname and port, connects to the IP pinned by SiteAudit, and checks TLS SNI. This blocks redirects to a different host or port when the scanner follows them through its proxy. The report includes allowed HTTP requests, HTTPS tunnels, blocked attempts, and limit status; blocked attempts and exhausted limits mark a scan partial. HTTPS request contents remain encrypted: individual requests, methods, bodies, and `Host` headers are not visible inside a tunnel, so the proxy counts and paces tunnels rather than every HTTPS request. A scanner or template can send a different encrypted `Host` header or method to the pinned IP; the proxy does not provide an HTTP-authority allow-list inside TLS. Review Nuclei templates and run external engines only against targets you are authorized to assess.

`setup-engines.bat` installs Wapiti 3.3.2 in an isolated Python environment; this version was exercised on Windows with Python 3.13. Other Wapiti releases may have different platform requirements. Nikto can run from Debian WSL, native Perl, or the Docker fallback. W3AF requires a legacy Linux/macOS environment and is reported unavailable on native Windows. Managed Nuclei/Wapiti executables are preferred, then SiteAudit checks `PATH` for other engines. Only run them on targets you are authorized to assess.

The Nuclei template filter addresses an [upstream v3.11.1 issue](https://github.com/projectdiscovery/nuclei/issues/7769) where `resolve()`, `public_ip()`, and `jarm()` could make direct network calls outside the configured proxy.

## Checks

- HTTPS availability, redirect behavior, document security headers (including effective frame-protection values), origin-root HSTS max-age, exact `nosniff` validation, and cookie checks for session-like names, `SameSite=None` without `Secure`, invalid SameSite values, and `__Secure-`/`__Host-` prefix requirements.
- Same-host page discovery with configurable depth and page/request limits.
- Bounded in-memory response cache (up to 100 responses and 2 MB) for passive checks of mixed content, weak CSP, stack-trace leakage, and CORS headers.
- A small curated set of common web-server exposure checks. Sensitive paths use bodyless HEAD requests and are compared with a random missing-path response to filter common soft-404 or single-page-app catch-all responses.
- Low-impact GET-only checks on discovered query parameters for parsed inert HTML-marker reflection, common database error indicators, and open redirects on redirect-like parameters; redirect probes are never followed, and reflection does not confirm XSS. Optional `--sqli-probes` compares stable responses from repeated true/false predicates on at most two numeric GET parameters to look for blind SQL injection.
- A bounded server-side template injection check sends only nonce-wrapped multiplication expressions to at most two non-sensitive GET parameters; it reports evaluation only when both computed outputs match.
- A small modular W3AF-inspired plugin set for credentialed arbitrary-origin CORS reflection and POST forms with no recognizable CSRF token field; this CSRF heuristic never submits forms.
- Optional GraphQL introspection check using one fixed read-only query on up to three same-host endpoints; the schema is not saved and the result is informational.
- Local JSON-template checks with strict GET/HEAD methods and literal response matchers; templates cannot execute code or define arbitrary payloads.
- Up to 23 additional reviewed local rules through `--templates-file`; JSON is always available, and an optional restricted Nuclei YAML importer accepts fixed GET/HEAD paths and positive body-word/status matchers (32 combined with the nine bundled rules).
- JSON report with severity, confidence, evidence, URL, remediation guidance, and references for template findings.

The nine bundled templates check the Go pprof index and expvar metrics, Spring Boot Actuator mappings, Django's debug 404, public OpenAPI specifications at two common paths, Git repository configuration, PHP configuration information, and Apache server status. API documentation is informational because it is often intentionally public. Response bodies are inspected for fixed signatures but are not copied into findings; these rules detect selected exposure surfaces and are not a general CVE database.

See [FEATURES.md](FEATURES.md) for the coverage map against the tools that inspired this project.

The scanner does not authenticate, brute force, exploit remote code execution, attempt SSRF callbacks, upload files, or intentionally test state-changing actions. Optional POST probes are limited to one inert marker field per form or one fixed read-only GraphQL introspection query per endpoint. It cannot guarantee that application-specific GET or POST routes are side-effect free. Its small local rule pack and restricted YAML importer are not compatible with or equivalent to Nuclei's large community CVE template library; it also does not include ZAP's intercepting proxy or full active/passive rule set, nor W3AF's broad plugin ecosystem. The W3AF-inspired registry currently contains two focused checks, not hundreds. TLS and application behavior vary; verify important findings manually.

## Development

The default installation uses Python's standard library. The optional `yaml` extra adds PyYAML only when importing restricted Nuclei YAML templates. Scanner modules share a request context and a finding schema so additional checks can be added without changing the report format.

## License

This project is distributed under the MIT License. It is an independent implementation and does not bundle code or vulnerability databases from the tools that inspired its feature categories.

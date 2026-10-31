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

# SiteAudit

SiteAudit is a self-contained command-line web security checker written in Python. One CLI runs a bounded same-host crawl, HTTPS/header/cookie checks, Nikto-style server exposure checks, Wapiti-style input indicators, ZAP-inspired passive response rules, W3AF-inspired modular checks, and a local literal-match template runner inspired by Nuclei.

It is an educational starter project, not a replacement for a professional penetration test or for mature scanners such as OWASP ZAP, Nuclei, Nikto, or Wapiti. It does not claim to find every vulnerability. Findings include the URL, observed evidence, severity, confidence, and a suggested fix.

## Use only with permission

Only scan websites you own or have explicit permission to assess. The default scan stays on the supplied host, uses bounded request and crawl limits, and avoids authentication attempts, brute force, uploads, destructive payloads, and command execution. Active parameter checks use inert marker and error-indicator probes over GET. Since some applications attach state changes to GET routes, scan only targets where you can accept those application-specific side effects. A result is an indicator for manual verification, not a guarantee that a vulnerability can be exploited.

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

Or without installing the console command:

```powershell
python -m siteaudit https://example.com --output report.json
```

Use `siteaudit --help` to see available scope, rate, crawl, and passive-mode options. The default run performs bounded GET/HEAD/OPTIONS checks; `--passive` skips template, server-path, and input probes. Private and loopback IPs require `--allow-private`. Review the target and options before each scan. Query values are redacted in saved URLs, but reports can still contain hostnames and server metadata.

## Checks

- HTTPS availability, redirect behavior, security headers, and cookie flags.
- Same-host page discovery with configurable depth and page/request limits.
- Bounded in-memory response cache (up to 100 responses and 2 MB) for passive checks of mixed content, weak CSP, stack-trace leakage, and CORS headers.
- A small curated set of common web-server exposure and configuration checks.
- Low-impact GET-only checks on discovered query parameters for reflected input and common database error indicators.
- A small modular W3AF-inspired plugin set for credentialed arbitrary-origin CORS reflection and POST forms with no recognizable CSRF token field; forms are inspected but never submitted.
- Local JSON-template checks with strict GET/HEAD methods and literal response matchers; templates cannot execute code or define arbitrary payloads.
- JSON report with severity, confidence, evidence, URL, remediation guidance, and references for template findings.

The bundled templates look for the Go pprof profile index, Spring Boot Actuator mappings, and Django's technical 404 page with debug mode enabled. These detect exposed diagnostic surfaces; they are not a general CVE database.

See [FEATURES.md](FEATURES.md) for the coverage map against the tools that inspired this project.

The scanner does not authenticate, submit POST forms, brute force, exploit remote code execution, attempt SSRF callbacks, upload files, or intentionally test state-changing actions. It cannot guarantee that an application-specific GET route is side-effect free. Its small local rule pack is not compatible with or equivalent to Nuclei's large community CVE template library; it also does not include ZAP's intercepting proxy or full active/passive rule set, nor W3AF's broad plugin ecosystem. The W3AF-inspired registry currently contains two focused checks, not hundreds. TLS and application behavior vary; verify important findings manually.

## Development

The implementation uses Python's standard library to keep installation simple. Scanner modules share a request context and a finding schema so additional checks can be added without changing the report format.

## License

This project is distributed under the MIT License. It is an independent implementation and does not bundle code or vulnerability databases from the tools that inspired its feature categories.

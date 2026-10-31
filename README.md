# SiteAudit

SiteAudit is a small, self-contained command-line web security checker written in Python. It combines bounded same-host crawling, HTTPS and security-header checks, selected web-server exposure checks, and low-impact tests for reflected input and database error indicators.

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

Use `siteaudit --help` to see available scope, rate, crawl, and passive-mode options. The default run performs bounded GET/HEAD/OPTIONS checks; `--passive` skips targeted server-path and input probes. Private and loopback IPs require `--allow-private`. Review the target and options before each scan. Query values are redacted in saved URLs, but reports can still contain hostnames and server metadata.

## Checks

- HTTPS availability, redirect behavior, security headers, and cookie flags.
- Same-host page discovery with configurable depth and page/request limits.
- A small curated set of common web-server exposure and configuration checks.
- Low-impact GET-only checks on discovered query parameters for reflected input and common database error indicators.
- JSON report with severity, confidence, evidence, URL, and remediation guidance.

The scanner does not authenticate, submit POST forms, brute force, exploit remote code execution, attempt SSRF callbacks, upload files, or intentionally test state-changing actions. It cannot guarantee that an application-specific GET route is side-effect free. It does not include the large community CVE template library from Nuclei, ZAP's proxy/active rules, or W3AF's plugin ecosystem. TLS and application behavior vary; verify important findings manually.

## Development

The implementation uses Python's standard library to keep installation simple. Scanner modules share a request context and a finding schema so additional checks can be added without changing the report format.

## License

This project is distributed under the MIT License. It is an independent implementation and does not bundle code or vulnerability databases from the tools that inspired its feature categories.

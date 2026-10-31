# Add local templates

Pass a local JSON file with `--templates-file`. SiteAudit merges it with the bundled rules. The combined set is limited to 32 rules; each file must be at most 256 KB and use schema version 1.

```powershell
siteaudit https://example.com --templates-file .\my-templates.json --output report.json
```

Example rule:

```json
{
  "schema_version": 1,
  "templates": [
    {
      "id": "example.header-marker",
      "name": "Example diagnostic header is present",
      "severity": "info",
      "confidence": "medium",
      "category": "example",
      "method": "HEAD",
      "path": "/",
      "max_bytes": 1024,
      "match": {
        "status": [200],
        "headers": [
          {"name": "x-example-diagnostic", "contains": "enabled"}
        ],
        "condition": "all"
      },
      "evidence": "A custom response header matched the example signature.",
      "remediation": "Review whether this diagnostic header should be exposed publicly.",
      "references": ["https://example.com/security-guide"]
    }
  ]
}
```

Each rule needs a unique `id`, severity, confidence, category, method, fixed root-relative path, literal matchers, evidence, remediation, and HTTPS references. Only `GET` and `HEAD` are accepted. Paths cannot contain a hostname, port, query, fragment, traversal segment, or nested percent-encoding; known state-changing routes are rejected. Templates are fully validated before the crawl sends requests. Matchers support exact status codes and case-insensitive literal substrings in response headers/body, with `all` or `any` for positive matchers.

Templates cannot run code, regexes, scripts, external callbacks, or arbitrary payloads. Review a local template before use: a `GET` endpoint can still have application-specific side effects. Custom rules are indicators and do not turn the bundled pack into a general CVE feed.

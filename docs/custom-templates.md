# Add local templates

Pass a local JSON file or a restricted Nuclei YAML file with `--templates-file`. SiteAudit merges imported rules with the bundled rules. The combined set is limited to 32 rules; each file must be at most 256 KB. JSON files use schema version 1. YAML support is optional:

```powershell
python -m pip install -e ".[yaml]"
```

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

## Restricted Nuclei YAML subset

YAML imports are deliberately narrower than Nuclei. Each document must define `id`, `info`, and exactly one `http` request. A request may use `GET` or `HEAD`, one to three fixed paths beginning with `{{BaseURL}}`, and positive `status` and/or `word` matchers. Status lists match any listed code and do not accept `condition: and`. `word` matchers are limited to the response body; Nuclei's case-sensitive default, exact word text, and optional `case-insensitive: true` behavior are preserved. Word-level and top-level `and`/`or` conditions are evaluated as separate groups.

Example:

```yaml
id: example-diagnostic-surface
info:
  name: Example diagnostic page exposed
  severity: low
  reference:
    - https://example.com/security-guide
http:
  - method: GET
    path:
      - "{{BaseURL}}/diagnostics"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["diagnostics enabled", "build-info"]
        condition: or
```

The importer rejects aliases, duplicate keys, merge keys, additional requests, non-`{{BaseURL}}` path variables, absolute URLs, query strings, request bodies, custom headers, redirects, cookies, payloads, flows, extractors, negative/internal matchers, regex/DSL/binary/XPath matchers, and non-body word matching. Multiple fixed paths expand into separate rules. YAML metadata such as author, tags, and classification is parsed with bounds but is not used by the scanner. Unsupported features fail before any scan request is sent. This is a small compatible subset, not full Nuclei compatibility or its CVE template database.

Templates cannot run code, regexes, scripts, external callbacks, or arbitrary payloads. Review a local template before use: a `GET` endpoint can still have application-specific side effects. Custom rules are indicators and do not turn the bundled pack into a general CVE feed.
